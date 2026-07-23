"""
Requirements Analysis Document (RAD) & Object Design Document (ODD) Academic Alignment
Modulo: Attack Vector / Stimolatore Dinamico BOLA (ContextAwareAttackGenerator)
Percorso: src/core/api1_bola/attack_vector.py

Questo modulo implementa il generatore di attacchi sensibile al contesto per il
rilevamento di BOLA. Gestisce la decodifica dei token JWT reali per estrarre il claim 'sub'
(UUID di Keycloak) ed esegue la stimolazione incrociata multimetodo dei target.
"""

import base64
import json
import logging
import re
import urllib.parse
from typing import Any

import jwt
import requests

logger = logging.getLogger("SecurityPlatform.BOLA.AttackGenerator")


def update_url_query_param(url: str, param_name: str, new_value: str) -> str:
    """
    Utility per aggiornare o inserire parametri all'interno della query string di un URL.
    """
    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query)
    query_params[param_name] = [str(new_value)]
    new_query = urllib.parse.urlencode(query_params, doseq=True)
    return urllib.parse.ParseResult(
        parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment
    ).geturl()


def set_nested_value(data: Any, path_str: str, value: Any) -> None:
    """
    Utility per iniettare ricorsivamente valori in strutture dati complesse (dizionari/liste).
    """
    parts = re.split(r"\.|(?=\[)", path_str)
    parts = [p.strip("[]") for p in parts if p]

    current = data
    for i, part in enumerate(parts[:-1]):
        next_part = parts[i + 1]
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


class ContextAwareAttackGenerator:
    """
    Gestore della stimolazione dinamica e del tampering di token/risorse.

    Decodifica i token JWT per implementare il Context-Aware Seeding ed effettua
    chiamate di attacco multimetodo attraverso il proxy di OWASP ZAP.
    """

    def __init__(self, zap_proxy_url: str = "http://127.0.0.1:8080"):
        """
        Costruttore che configura l'instradamento verso OWASP ZAP.

        Args:
            zap_proxy_url (str): L'indirizzo del proxy locale di ZAP.
        """
        self.zap_proxy_url = zap_proxy_url
        self.proxies = {"http": zap_proxy_url, "https": zap_proxy_url}

    @staticmethod
    def extract_sub_from_jwt(auth_header: str | None) -> str | None:
        """
        Analizza l'header Authorization, decodifica il JWT senza verificare la firma
        ed estrae il claim standard 'sub' (UUID Keycloak).

        Args:
            auth_header (str): L'header Authorization completo.

        Returns:
            str: Il valore del claim 'sub' (UUID), oppure None in caso di errore o assenza.
        """
        if not auth_header or not auth_header.startswith("Bearer "):
            return None

        token = auth_header.split(" ")[1]

        # 1. Tentativo di decodifica tramite PyJWT
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            sub = decoded.get("sub")
            if sub:
                return str(sub)
        except Exception as e:
            logger.debug(f"Decodifica PyJWT fallita: {e}. Tento fallback manuale.")

        # 2. Fallback manuale tramite decodifica base64 del secondo segmento (Payload)
        try:
            segments = token.split(".")
            if len(segments) >= 2:
                payload_b64 = segments[1]
                payload_b64 += "=" * (-len(payload_b64) % 4)  # Aggiunta padding base64
                payload_json = base64.urlsafe_b64decode(payload_b64).decode("utf-8")
                payload = json.loads(payload_json)
                sub = payload.get("sub")
                if sub:
                    return str(sub)
        except Exception as e:
            logger.error(f"Errore critico durante la decodifica manuale del JWT: {e}")

        return None

    def execute_tampering(
        self,
        method: str,
        target_base_url: str,
        path: str,
        headers_matrix: dict[str, dict[str, str]],
        uuid_alice: str,
        uuid_bob: str,
        uuid_charlie: str,
        role_alice: str = "user",
        role_bob: str = "user",
        role_charlie: str = "admin",
        discovered_refs: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Esegue la simulazione degli scenari di tampering scambiando in modo incrociato i token.
        Decodifica i token JWT per estrarre gli UUID reali ed allineare gli scenari dinamici.

        Args:
            method (str): Il metodo HTTP (GET, POST, PUT, DELETE).
            target_base_url (str): L'URL dell'applicazione target.
            path (str): Il percorso dell'endpoint (può contenere {id}).
            headers_matrix (dict): La matrice contenente gli header Authorization per ciascun utente.
            uuid_alice (str): Fallback UUID per User A (Alice).
            uuid_bob (str): Fallback UUID per User B (Bob).
            uuid_charlie (str): Fallback UUID per User C (Admin).
            role_alice/bob/charlie (str): I ruoli associati per la Privilege Matrix.
            discovered_refs (list): Riferimenti aggiuntivi a oggetti rilevati dal Discovery.

        Returns:
            list: Lista dei risultati degli attacchi e delle risposte ricevute.
        """
        method = method.upper()
        results = []

        # Decodifica dei JWT in headers_matrix per estrarre dinamicamente i 'sub' (UUID reali di Keycloak)
        sub_alice = (
            self.extract_sub_from_jwt(headers_matrix.get("userA", {}).get("Authorization"))
            or uuid_alice
        )
        sub_bob = (
            self.extract_sub_from_jwt(headers_matrix.get("userB", {}).get("Authorization"))
            or uuid_bob
        )
        sub_charlie = (
            self.extract_sub_from_jwt(headers_matrix.get("userC", {}).get("Authorization"))
            or uuid_charlie
        )

        logger.info(
            f"🔑 [CONTEXT-AWARE SEEDING] Claim sub decodificati - Alice: {sub_alice}, Bob: {sub_bob}, Admin: {sub_charlie}"
        )

        # Definizione formale degli scenari di test
        scenarios = [
            {
                "name": "BOLA Orizzontale",
                "resource_id": sub_alice,  # Risorsa di Alice (Vittima)
                "owner_key": "userA",
                "owner_role": role_alice,
                "attacker_key": "userB",  # Attaccante (Bob - peer)
                "attacker_role": role_bob,
                "description": "Bob (User) tenta di accedere ad Alice (User) usando token Bob su ID Alice",
            },
            {
                "name": "BOLA Verticale",
                "resource_id": sub_charlie,  # Risorsa di Admin (Vittima)
                "owner_key": "userC",
                "owner_role": role_charlie,
                "attacker_key": "userA",  # Attaccante (Alice - privilegi inferiori)
                "attacker_role": role_alice,
                "description": "Alice (User) tenta di accedere a Charlie (Admin) usando token Alice su ID Admin",
            },
            {
                "name": "Privilegio Legittimo",
                "resource_id": sub_alice,  # Risorsa di Alice
                "owner_key": "userA",
                "owner_role": role_alice,
                "attacker_key": "userC",  # Attaccante (Charlie - Admin con diritti)
                "attacker_role": role_charlie,
                "description": "Charlie (Admin) accede ad Alice (User) - Legittimo per design gerarchico",
            },
        ]

        for sc in scenarios:
            logger.info(f"🎬 [STIMOLATORE ATTACK] Esecuzione scenario: {sc['name']} ({method})")

            # Sostituzione dinamica del parametro nel percorso (Path Parameter)
            test_path = path
            if "{id}" in test_path:
                test_path = test_path.replace("{id}", sc["resource_id"])
            elif discovered_refs:
                path_segments = [s for s in test_path.split("/") if s]
                for ref in discovered_refs:
                    if ref.get("location") == "path" and "index" in ref:
                        idx = ref["index"]
                        if idx < len(path_segments):
                            path_segments[idx] = sc["resource_id"]
                test_path = "/" + "/".join(path_segments)

            target_url = f"{target_base_url.rstrip('/')}{test_path}"

            # Sostituzione nei Query Parameters
            if discovered_refs:
                for ref in discovered_refs:
                    if ref.get("location") == "query":
                        target_url = update_url_query_param(
                            target_url, ref["name"], sc["resource_id"]
                        )

            # Indirizzamento specifico per l'ambiente containerizzato di ZAP
            zap_target_url = target_url.replace("localhost", "api-server").replace(
                "127.0.0.1", "api-server"
            )

            # Costruzione del payload di scrittura
            payload = None
            if method in ("PUT", "POST", "PATCH"):
                payload = {
                    "details": f"Risorsa alterata via attacco BOLA '{sc['name']}' da ruolo '{sc['attacker_role']}'",
                    "owner": "user_a" if sc["owner_key"] == "userA" else "admin_user",
                }
                if discovered_refs:
                    for ref in discovered_refs:
                        if ref.get("location") == "body":
                            set_nested_value(payload, ref["name"], sc["resource_id"])

            # 1. Chiamata Legittima (Alice accede a se stessa)
            res_alice = None
            try:
                kwargs = {
                    "headers": headers_matrix[sc["owner_key"]],
                    "proxies": self.proxies,
                    "verify": False,
                    "timeout": 5,
                }
                if payload is not None:
                    kwargs["json"] = payload
                res_alice = requests.request(method, zap_target_url, **kwargs)
            except Exception as e:
                logger.error(f"❌ Errore chiamata legittima {sc['owner_key']}: {e}")

            # 2. Chiamata di Attacco / Tampering (Attaccante con il proprio token su risorsa vittima)
            res_bob = None
            try:
                kwargs = {
                    "headers": headers_matrix[sc["attacker_key"]],
                    "proxies": self.proxies,
                    "verify": False,
                    "timeout": 5,
                }
                if payload is not None:
                    kwargs["json"] = payload
                res_bob = requests.request(method, zap_target_url, **kwargs)
            except Exception as e:
                logger.error(f"❌ Errore chiamata attaccante {sc['attacker_key']}: {e}")

            # 3. Chiamata Anonima (Broken Authentication Check)
            res_anon = None
            try:
                kwargs = {
                    "headers": headers_matrix.get("anonymous", {}),
                    "proxies": self.proxies,
                    "verify": False,
                    "timeout": 5,
                }
                if payload is not None:
                    kwargs["json"] = payload
                res_anon = requests.request(method, zap_target_url, **kwargs)
            except Exception as e:
                logger.error(f"❌ Errore chiamata anonima: {e}")

            results.append(
                {
                    "scenario_name": sc["name"],
                    "method": method,
                    "target_url": target_url,
                    "zap_target_url": zap_target_url,
                    "res_alice": res_alice,
                    "res_bob": res_bob,
                    "res_anon": res_anon,
                    "attacker_role": sc["attacker_role"],
                    "owner_role": sc["owner_role"],
                    "path": path,
                }
            )

        return results


# Classe Alias per retrocompatibilità immediata con altri moduli
class BOLAAttackVector(ContextAwareAttackGenerator):
    """
    Classe adattatrice per mantenere compatibilità con il codice legacy.
    Mappa il vecchio nome classe sui metodi del nuovo ContextAwareAttackGenerator.
    """

    pass
