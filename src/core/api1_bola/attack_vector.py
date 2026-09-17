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
from dataclasses import dataclass
from typing import Any

import jwt
import requests

from src.core.api1_bola.target_config import (
    DEFAULT_ZAP_INTERNAL_HOST,
    IDENTITY_PEER,
    IDENTITY_PRIVILEGED,
    IDENTITY_VICTIM,
    MATRIX_KEY_ANONYMOUS,
    MATRIX_KEY_BY_IDENTITY,
    rewrite_host_for_zap,
)

logger = logging.getLogger("SecurityPlatform.BOLA.AttackGenerator")

# Placeholder con cui l'inventario normalizza i parametri di path
ID_PLACEHOLDER = "{id}"


@dataclass(frozen=True)
class IdentityProfile:
    """
    Profilo di una delle tre identità di test, come lo vede il generatore di attacchi.

    Attributes:
        role (str): Ruolo nella privilege matrix (``user``, ``admin``, ...).
        username (str): Username presso il bersaglio (owner nel payload di scrittura).
        uuid (str): Claim ``sub`` del token; usato per i ``{id}`` genitori dei path annidati.
    """

    role: str = "user"
    username: str = ""
    uuid: str = ""


# Profili di ripiego quando l'orchestratore non ne fornisce
_DEFAULT_PROFILES = {
    IDENTITY_VICTIM: IdentityProfile(role="user"),
    IDENTITY_PEER: IdentityProfile(role="user"),
    IDENTITY_PRIVILEGED: IdentityProfile(role="admin"),
}


def substitute_path_ids(path: str, target_id: str, parent_id: str | None = None) -> str:
    """
    Sostituisce i placeholder ``{id}`` di un path: l'ULTIMO è l'oggetto bersaglio, i
    precedenti (path annidati, es. ``/api/users/{id}/projects/{id}``) sono i genitori.

    È la stessa convenzione di ``OwnershipInferenceEngine._parse_resource_from_path``,
    che legge la risorsa dalla fine del path.

    Args:
        path (str): Path normalizzato, con zero o più ``{id}``.
        target_id (str): ID della risorsa attaccata (ultimo placeholder).
        parent_id (str | None): Valore per i placeholder genitori; se None usa ``target_id``.

    Returns:
        str: Il path con i placeholder risolti.
    """
    if ID_PLACEHOLDER not in path:
        return path
    head, _, tail = path.rpartition(ID_PLACEHOLDER)
    head = head.replace(ID_PLACEHOLDER, parent_id if parent_id is not None else target_id)
    return f"{head}{target_id}{tail}"


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

    def __init__(
        self,
        zap_proxy_url: str = "http://127.0.0.1:8080",
        zap_internal_host: str = DEFAULT_ZAP_INTERNAL_HOST,
    ):
        """
        Costruttore che configura l'instradamento verso OWASP ZAP.

        Args:
            zap_proxy_url (str): L'indirizzo del proxy locale di ZAP.
            zap_internal_host (str): Host con cui il container di ZAP raggiunge il bersaglio
                (``target.zap_internal_host`` del contratto): gli URL locali vengono
                riscritti su di esso prima di passare dal proxy.
        """
        self.zap_proxy_url = zap_proxy_url
        self.zap_internal_host = zap_internal_host
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
        resource_ids: dict[str, str],
        profiles: dict[str, IdentityProfile] | None = None,
        discovered_refs: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Esegue la simulazione degli scenari di tampering scambiando in modo incrociato i token.

        Gli ID delle risorse non vengono più dedotti dal claim ``sub`` dei token: arrivano
        dall'orchestratore (ID creati dall'harness di seeding, oppure UUID/ID inferiti dal
        traffico come ripiego), così un bersaglio con DB reale che assegna gli ID da sé
        resta attaccabile.

        Args:
            method (str): Il metodo HTTP (GET, POST, PUT, PATCH, DELETE).
            target_base_url (str): L'URL dell'applicazione target.
            path (str): Il percorso dell'endpoint (può contenere uno o più ``{id}``).
            headers_matrix (dict): Header Authorization per ``userA``/``userB``/``userC``/``anonymous``.
            resource_ids (dict): Mappa ruolo logico (victim/peer/privileged) -> ID della
                risorsa posseduta da quell'identità per questo endpoint.
            profiles (dict | None): Mappa ruolo logico -> IdentityProfile (ruolo, username, uuid).
            discovered_refs (list): Riferimenti aggiuntivi a oggetti rilevati dal Discovery.

        Returns:
            list: Lista dei risultati degli attacchi e delle risposte ricevute.
        """
        method = method.upper()
        results = []
        profiles = {**_DEFAULT_PROFILES, **(profiles or {})}

        missing = [
            k
            for k in (IDENTITY_VICTIM, IDENTITY_PEER, IDENTITY_PRIVILEGED)
            if not resource_ids.get(k)
        ]
        if missing:
            logger.error(
                f"❌ Nessun ID risorsa per {missing} su {method} {path}: scenari non eseguibili."
            )
            return results

        logger.info(
            f"🔑 [CONTEXT-AWARE SEEDING] ID risorsa per {path} - "
            f"victim: {resource_ids[IDENTITY_VICTIM]}, peer: {resource_ids[IDENTITY_PEER]}, "
            f"privileged: {resource_ids[IDENTITY_PRIVILEGED]}"
        )

        # Definizione formale degli scenari di test (owner/attacker sono ruoli logici)
        scenarios = [
            {
                "name": "BOLA Orizzontale",
                "owner": IDENTITY_VICTIM,  # Risorsa della vittima
                "attacker": IDENTITY_PEER,  # Attaccante paritetico
                "description": "peer (user) tenta di accedere alla risorsa di victim (user) con il proprio token",
            },
            {
                "name": "BOLA Verticale",
                "owner": IDENTITY_PRIVILEGED,  # Risorsa dell'identità privilegiata
                "attacker": IDENTITY_VICTIM,  # Attaccante con privilegi inferiori
                "description": "victim (user) tenta di accedere alla risorsa di privileged (admin)",
            },
            {
                "name": "Privilegio Legittimo",
                "owner": IDENTITY_VICTIM,  # Risorsa della vittima
                "attacker": IDENTITY_PRIVILEGED,  # Identità privilegiata con diritti
                "description": "privileged (admin) accede alla risorsa di victim - legittimo per design gerarchico",
            },
        ]

        for sc in scenarios:
            logger.info(f"🎬 [STIMOLATORE ATTACK] Esecuzione scenario: {sc['name']} ({method})")

            owner_key, attacker_key = sc["owner"], sc["attacker"]
            owner, attacker = profiles[owner_key], profiles[attacker_key]
            resource_id = resource_ids[owner_key]
            owner_matrix_key = MATRIX_KEY_BY_IDENTITY[owner_key]
            attacker_matrix_key = MATRIX_KEY_BY_IDENTITY[attacker_key]

            # Sostituzione dinamica del parametro nel percorso: l'ultimo {id} è l'oggetto
            # bersaglio, gli eventuali {id} genitori ricevono l'UUID del proprietario.
            test_path = path
            if ID_PLACEHOLDER in test_path:
                test_path = substitute_path_ids(test_path, resource_id, owner.uuid or None)
            elif discovered_refs:
                path_segments = [s for s in test_path.split("/") if s]
                for ref in discovered_refs:
                    if ref.get("location") == "path" and "index" in ref:
                        idx = ref["index"]
                        if idx < len(path_segments):
                            path_segments[idx] = resource_id
                test_path = "/" + "/".join(path_segments)

            target_url = f"{target_base_url.rstrip('/')}{test_path}"

            # Sostituzione nei Query Parameters
            if discovered_refs:
                for ref in discovered_refs:
                    if ref.get("location") == "query":
                        target_url = update_url_query_param(target_url, ref["name"], resource_id)

            # Indirizzamento specifico per l'ambiente containerizzato di ZAP
            zap_target_url = rewrite_host_for_zap(target_url, self.zap_internal_host)

            # Costruzione del payload di scrittura
            payload = None
            if method in ("PUT", "POST", "PATCH"):
                payload = {
                    "details": f"Risorsa alterata via attacco BOLA '{sc['name']}' da ruolo '{attacker.role}'",
                    "owner": owner.username,
                }
                if discovered_refs:
                    for ref in discovered_refs:
                        if ref.get("location") == "body":
                            set_nested_value(payload, ref["name"], resource_id)

            # 1. Chiamata Legittima (il proprietario accede alla propria risorsa)
            res_alice = None
            try:
                kwargs = {
                    "headers": headers_matrix[owner_matrix_key],
                    "proxies": self.proxies,
                    "verify": False,
                    "timeout": 5,
                }
                if payload is not None:
                    kwargs["json"] = payload
                res_alice = requests.request(method, zap_target_url, **kwargs)
            except Exception as e:
                logger.error(f"❌ Errore chiamata legittima {owner_key}: {e}")

            # 2. Chiamata di Attacco / Tampering (Attaccante con il proprio token su risorsa vittima)
            res_bob = None
            try:
                kwargs = {
                    "headers": headers_matrix[attacker_matrix_key],
                    "proxies": self.proxies,
                    "verify": False,
                    "timeout": 5,
                }
                if payload is not None:
                    kwargs["json"] = payload
                res_bob = requests.request(method, zap_target_url, **kwargs)
            except Exception as e:
                logger.error(f"❌ Errore chiamata attaccante {attacker_key}: {e}")

            # 3. Chiamata Anonima (Broken Authentication Check)
            res_anon = None
            try:
                kwargs = {
                    "headers": headers_matrix.get(MATRIX_KEY_ANONYMOUS, {}),
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
                    "attacker_role": attacker.role,
                    "owner_role": owner.role,
                    "attacker": attacker_key,
                    "owner": owner_key,
                    "resource_id": resource_id,
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
