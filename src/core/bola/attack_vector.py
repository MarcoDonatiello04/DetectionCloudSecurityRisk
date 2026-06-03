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
from typing import Dict, Any, List

logger = logging.getLogger("SecurityPlatform.BOLA.AttackVector")


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
        role_charlie: str = "admin"
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
            
            # Costruzione degli URL dinamici associati alla risorsa specifica
            test_path = path.replace("{id}", sc["resource_id"])
            target_url = f"{target_base_url.rstrip('/')}{test_path}"
            
            # URL per ZAP passante dal container Docker
            zap_target_url = target_url.replace("localhost", "api-server").replace("127.0.0.1", "api-server")

            # Configurazione payload di tampering per metodi di scrittura (PUT/POST)
            payload = None
            if method in ("PUT", "POST"):
                payload = {
                    "details": f"Risorsa alterata tramite exploit {sc['name']} con ruolo {sc['attacker_role']}",
                    "owner": "user_a" if sc["owner_key"] == "userA" else "admin_user"
                }

            # 1. Richiesta Legittima (Proprietario della risorsa)
            res_alice = None
            try:
                if method == "GET":
                    res_alice = requests.get(
                        zap_target_url, 
                        headers=headers_matrix[sc["owner_key"]], 
                        proxies=self.proxies, 
                        verify=False, 
                        timeout=5
                    )
                elif method in ("PUT", "POST"):
                    res_alice = requests.put(
                        zap_target_url, 
                        json=payload,
                        headers=headers_matrix[sc["owner_key"]], 
                        proxies=self.proxies, 
                        verify=False, 
                        timeout=5
                    )
                elif method == "DELETE":
                    res_alice = requests.delete(
                        zap_target_url, 
                        headers=headers_matrix[sc["owner_key"]], 
                        proxies=self.proxies, 
                        verify=False, 
                        timeout=5
                    )
            except Exception as e:
                logger.error(f"      ❌ Errore chiamata legittima proprietario ({sc['owner_key']}): {e}")

            # 2. Richiesta di Attacco (Attaccante del rispettivo scenario)
            res_bob = None
            try:
                if method == "GET":
                    res_bob = requests.get(
                        zap_target_url, 
                        headers=headers_matrix[sc["attacker_key"]], 
                        proxies=self.proxies, 
                        verify=False, 
                        timeout=5
                    )
                elif method in ("PUT", "POST"):
                    res_bob = requests.put(
                        zap_target_url, 
                        json=payload,
                        headers=headers_matrix[sc["attacker_key"]], 
                        proxies=self.proxies, 
                        verify=False, 
                        timeout=5
                    )
                elif method == "DELETE":
                    res_bob = requests.delete(
                        zap_target_url, 
                        headers=headers_matrix[sc["attacker_key"]], 
                        proxies=self.proxies, 
                        verify=False, 
                        timeout=5
                    )
            except Exception as e:
                logger.error(f"      ❌ Errore chiamata attaccante ({sc['attacker_key']}): {e}")

            # 3. Richiesta Anonymous (Broken Authentication check)
            res_anon = None
            try:
                if method == "GET":
                    res_anon = requests.get(
                        zap_target_url, 
                        headers=headers_matrix["anonymous"], 
                        proxies=self.proxies, 
                        verify=False, 
                        timeout=5
                    )
                elif method in ("PUT", "POST"):
                    res_anon = requests.put(
                        zap_target_url, 
                        json=payload,
                        headers=headers_matrix["anonymous"], 
                        proxies=self.proxies, 
                        verify=False, 
                        timeout=5
                    )
                elif method == "DELETE":
                    res_anon = requests.delete(
                        zap_target_url, 
                        headers=headers_matrix["anonymous"], 
                        proxies=self.proxies, 
                        verify=False, 
                        timeout=5
                    )
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
