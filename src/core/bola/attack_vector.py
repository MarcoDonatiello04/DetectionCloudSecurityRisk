"""
Vettori di Attacco BOLA per il framework D-AST.
Esteso per eseguire test Role-Aware stimolando gli endpoint tramite tre scenari:
1. Test Orizzontale (Bob - utente ordinario, su risorsa di Alice - utente ordinario)
2. Test Verticale (Alice - utente ordinario, su risorsa di Charlie - amministratore)
3. Test di Falso Positivo / Privilegio Legittimo (Charlie - amministratore, su risorsa di Alice - utente ordinario)

Tutte le richieste transitano dal proxy di OWASP ZAP per registrare i flussi.
"""

import logging
import requests
import urllib.parse
import re
from typing import Dict, Any, List

logger = logging.getLogger("SecurityPlatform.BOLA.AttackVector")


def update_url_query_param(url: str, param_name: str, new_value: str) -> str:
    """Aggiorna o aggiunge un parametro di query a un URL."""
    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query)
    query_params[param_name] = [str(new_value)]
    new_query = urllib.parse.urlencode(query_params, doseq=True)
    return urllib.parse.ParseResult(
        parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment
    ).geturl()


def set_nested_value(data: Any, path_str: str, value: Any) -> None:
    """Imposta ricorsivamente un valore all'interno di una struttura nidificata (dizionari/liste)."""
    parts = re.split(r'\.|(?=\[)', path_str)
    parts = [p.strip('[]') for p in parts if p]
    
    current = data
    for i, part in enumerate(parts[:-1]):
        next_part = parts[i+1]
        is_next_index = next_part.isdigit()
        
        if part.isdigit():
            idx = int(part)
            while len(current) <= idx:
                current.append({})
            current = current[idx]
        else:
            if is_next_index:
                if part not in current or not isinstance(current[part], list):
                    current[part] = []
            else:
                if part not in current or not isinstance(current[part], dict):
                    current[part] = {}
            current = current[part]
            
    last_part = parts[-1]
    if last_part.isdigit():
        idx = int(last_part)
        while len(current) <= idx:
            current.append(None)
        current[idx] = value
    else:
        current[last_part] = value


class BOLAAttackVector:
    """
    Gestisce la stimolazione differenziale multi-ruolo degli endpoint dinamici.
    """

    def __init__(self, zap_proxy_url: str):
        self.zap_proxy_url = zap_proxy_url
        self.proxies = {
            "http": zap_proxy_url,
            "https": zap_proxy_url
        }

    def execute_tampering(
        self,
        method: str,
        target_base_url: str,
        path: str,
        headers_matrix: Dict[str, Dict[str, str]],
        uuid_alice: str,
        uuid_bob: str,
        uuid_charlie: str,
        role_alice: str = "user",
        role_bob: str = "user",
        role_charlie: str = "admin",
        discovered_refs: List[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Esegue i test BOLA incrociati simulando 3 scenari per ciascun metodo HTTP:
        - Scenario Orizzontale (Bob accede ad Alice)
        - Scenario Verticale (Alice accede a Charlie/Admin)
        - Scenario Privilegiato Legittimo (Charlie accede ad Alice)
        """
        method = method.upper()
        results = []

        # Scenari di testing da stimolare
        scenarios = [
            {
                "name": "BOLA Orizzontale",
                "resource_id": uuid_alice,
                "owner_key": "userA",
                "owner_role": role_alice,
                "attacker_key": "userB",
                "attacker_role": role_bob,
                "description": "Bob (User) tenta di accedere ad Alice (User)"
            },
            {
                "name": "BOLA Verticale",
                "resource_id": uuid_charlie,
                "owner_key": "userC",
                "owner_role": role_charlie,
                "attacker_key": "userA",
                "attacker_role": role_alice,
                "description": "Alice (User) tenta di accedere a Charlie (Admin)"
            },
            {
                "name": "Privilegio Legittimo",
                "resource_id": uuid_alice,
                "owner_key": "userA",
                "owner_role": role_alice,
                "attacker_key": "userC",
                "attacker_role": role_charlie,
                "description": "Charlie (Admin) tenta di accedere ad Alice (User) - Legit per design"
            }
        ]

        for sc in scenarios:
            logger.info(f"🎭 [Scenario: {sc['name']}] - {sc['description']} - Metodo {method}")
            
            # Costruzione del path della risorsa
            test_path = path
            if "{id}" in test_path:
                test_path = test_path.replace("{id}", sc["resource_id"])
            elif discovered_refs:
                # Se abbiamo riferimenti nel path scoperti dal Discovery Engine, li sostituiamo all'indice corretto
                path_segments = [s for s in test_path.split("/") if s]
                for ref in discovered_refs:
                    if ref.get("location") == "path" and "index" in ref:
                        idx = ref["index"]
                        if idx < len(path_segments):
                            path_segments[idx] = sc["resource_id"]
                test_path = "/" + "/".join(path_segments)

            target_url = f"{target_base_url.rstrip('/')}{test_path}"

            # Sostituzione dei parametri di query se presenti tra i riferimenti scoperti
            if discovered_refs:
                for ref in discovered_refs:
                    if ref.get("location") == "query":
                        target_url = update_url_query_param(target_url, ref["name"], sc["resource_id"])

            # URL per ZAP passante dal container Docker
            zap_target_url = target_url.replace("localhost", "api-server").replace("127.0.0.1", "api-server")

            # Configurazione payload di tampering per metodi di scrittura (PUT/POST/PATCH)
            payload = None
            if method in ("PUT", "POST", "PATCH"):
                payload = {
                    "details": f"Risorsa alterata tramite exploit {sc['name']} con ruolo {sc['attacker_role']}",
                    "owner": "user_a" if sc["owner_key"] == "userA" else "admin_user"
                }
                # Se sono stati scoperti parametri ID nel corpo JSON, inseriscili/sovrascrivili con il target
                if discovered_refs:
                    for ref in discovered_refs:
                        if ref.get("location") == "body":
                            set_nested_value(payload, ref["name"], sc["resource_id"])

            # 1. Richiesta Legittima (Proprietario della risorsa)
            res_alice = None
            try:
                kwargs = {
                    "headers": headers_matrix[sc["owner_key"]],
                    "proxies": self.proxies,
                    "verify": False,
                    "timeout": 5
                }
                if payload is not None:
                    kwargs["json"] = payload
                res_alice = requests.request(method, zap_target_url, **kwargs)
            except Exception as e:
                logger.error(f"      ❌ Errore chiamata legittima proprietario ({sc['owner_key']}): {e}")

            # 2. Richiesta di Attacco (Attaccante del rispettivo scenario)
            res_bob = None
            try:
                kwargs = {
                    "headers": headers_matrix[sc["attacker_key"]],
                    "proxies": self.proxies,
                    "verify": False,
                    "timeout": 5
                }
                if payload is not None:
                    kwargs["json"] = payload
                res_bob = requests.request(method, zap_target_url, **kwargs)
            except Exception as e:
                logger.error(f"      ❌ Errore chiamata attaccante ({sc['attacker_key']}): {e}")

            # 3. Richiesta Anonymous (Broken Authentication check)
            res_anon = None
            try:
                kwargs = {
                    "headers": headers_matrix["anonymous"],
                    "proxies": self.proxies,
                    "verify": False,
                    "timeout": 5
                }
                if payload is not None:
                    kwargs["json"] = payload
                res_anon = requests.request(method, zap_target_url, **kwargs)
            except Exception as e:
                logger.error(f"      ❌ Errore chiamata Broken Auth Anonymous: {e}")

            results.append({
                "scenario_name": sc["name"],
                "method": method,
                "target_url": target_url,
                "zap_target_url": zap_target_url,
                "res_alice": res_alice,
                "res_bob": res_bob,
                "res_anon": res_anon,
                "attacker_role": sc["attacker_role"],
                "owner_role": sc["owner_role"],
                "path": path
            })

        return results
