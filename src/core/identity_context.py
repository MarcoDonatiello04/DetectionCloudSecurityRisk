"""
Modulo Identity Context e Seeding per il framework ASPM D-AST.
Fornisce la gestione delle identità (IdentityManager) con estrazione dinamica degli UUID dei token JWT
(tramite tecnica di "Context-Aware Seeding" con decodifica del claim 'sub')
e il popolamento deterministico del database target (DatabaseSeeder) con tali UUID.
Esteso per gestire 3 identità incrociate (User A, User B e l'amministratore User C).
"""

import base64
import json
import logging
from typing import Any

import jwt
import requests

# Configurazione logging
logger = logging.getLogger("SecurityPlatform.IdentityContext")

# Costanti di default ereditate dal framework
DEFAULT_USER_A_USERNAME = "user_a"
DEFAULT_USER_A_PASSWORD = "Password123!"
DEFAULT_USER_B_USERNAME = "user_b"
DEFAULT_USER_B_PASSWORD = "Password123!"
DEFAULT_USER_C_USERNAME = "admin_user"
DEFAULT_USER_C_PASSWORD = "Password123!"

DEFAULT_CLIENT_ID = "security-platform-client"
DEFAULT_KEYCLOAK_URL = "http://localhost:8080"
DEFAULT_KEYCLOAK_REALM = "myrealm"
DEFAULT_TARGET_BASE_URL = "http://localhost:5000"

HTTP_TIMEOUT_SHORT_SECONDS = 3
HTTP_TIMEOUT_MEDIUM_SECONDS = 5


def validate_url(url: str, param_name: str) -> None:
    """
    Valida la struttura formale di un URL passato come parametro.
    """
    if not url or not (url.startswith("http://") or url.startswith("https://")):
        raise ValueError(
            f"Parametro '{param_name}' non valido: deve iniziare con http:// o https://. Valore: {url}"
        )


class IdentityManager:
    """
    Gestisce l'acquisizione dei token JWT da Keycloak per tre utenti:
    - User A (Alice): Utente standard ('user')
    - User B (Bob): Utente standard paritetico ('user')
    - User C (Charlie/Admin): Utente privilegiato ('admin')
    Estrae l'UUID reale dal claim standard 'sub' e memorizza il ruolo associato.
    """

    def __init__(
        self, keycloak_url: str = DEFAULT_KEYCLOAK_URL, realm: str = DEFAULT_KEYCLOAK_REALM
    ):
        validate_url(keycloak_url, "keycloak_url")
        self.token_url = f"{keycloak_url.rstrip('/')}/realms/{realm}/protocol/openid-connect/token"
        self.client_id = DEFAULT_CLIENT_ID

        # Mappa globale dell'orchestratore per memorizzare gli UUID e i ruoli
        self.identity_map = {"UUID_ALICE": None, "UUID_BOB": None, "UUID_CHARLIE": None}
        self.role_map = {}  # Associa UUID -> Ruolo

    def get_headers_for_identities(self) -> dict[str, dict[str, str]]:
        """
        Ottiene i token JWT da Keycloak o genera token fittizi (fallback).
        Estrae l'UUID dal claim 'sub' e il ruolo decodificando il JWT.
        """
        identities = {
            "user_a": {"username": DEFAULT_USER_A_USERNAME, "password": DEFAULT_USER_A_PASSWORD},
            "user_b": {"username": DEFAULT_USER_B_USERNAME, "password": DEFAULT_USER_B_PASSWORD},
            "admin_user": {
                "username": DEFAULT_USER_C_USERNAME,
                "password": DEFAULT_USER_C_PASSWORD,
            },
        }

        headers_matrix = {
            "userA": {},
            "userB": {},
            "userC": {},  # Admin
            "anonymous": {},  # Header vuoti per Broken Auth
        }

        for identity_key, credentials in identities.items():
            if identity_key == "user_a":
                matrix_key = "userA"
            elif identity_key == "user_b":
                matrix_key = "userB"
            else:
                matrix_key = "userC"

            token = self._fetch_token(credentials["username"], credentials["password"])

            if token:
                logger.info(f"Ottenuto token JWT reale da Keycloak per {credentials['username']}")
                headers_matrix[matrix_key] = {"Authorization": f"Bearer {token}"}
            else:
                logger.warning(
                    f"Keycloak offline per {identity_key}. Utilizzo di un JWT di fallback con UUID realistico."
                )
                token = self._generate_mock_jwt(credentials["username"])
                headers_matrix[matrix_key] = {"Authorization": f"Bearer {token}"}

            # Estrazione dell'UUID e del ruolo decodificando il JWT (opzione verify_signature disabilitata)
            try:
                payload = jwt.decode(token, options={"verify_signature": False})
                sub_uuid = payload.get("sub")

                # Estrae il ruolo dal token
                roles = payload.get("roles", [])
                role = "user"
                if "admin" in roles:
                    role = "admin"
                elif "manager" in roles:
                    role = "manager"

                if sub_uuid:
                    if identity_key == "user_a":
                        self.identity_map["UUID_ALICE"] = sub_uuid
                        logger.info(
                            f"IdentityManager: Estratto UUID_ALICE -> {sub_uuid} (Ruolo: {role})"
                        )
                    elif identity_key == "user_b":
                        self.identity_map["UUID_BOB"] = sub_uuid
                        logger.info(
                            f"IdentityManager: Estratto UUID_BOB -> {sub_uuid} (Ruolo: {role})"
                        )
                    else:
                        self.identity_map["UUID_CHARLIE"] = sub_uuid
                        logger.info(
                            f"IdentityManager: Estratto UUID_CHARLIE -> {sub_uuid} (Ruolo: {role})"
                        )

                    # Memorizza l'UUID con il rispettivo ruolo per il controllo accessi
                    self.role_map[sub_uuid] = role
                else:
                    logger.warning(f"Claim 'sub' non presente nel JWT per {identity_key}")
            except Exception as e:
                logger.error(
                    f"Errore durante l'estrazione dei dati dal JWT per {identity_key}: {e}"
                )

        logger.info(f"Mappa delle identità globali completata: {self.identity_map}")
        logger.info(f"Mappa dei ruoli completata: {self.role_map}")
        return headers_matrix

    def _fetch_token(self, username: str, password: str) -> str:
        """
        Esegue la richiesta token standard a Keycloak via password grant.
        """
        payload = {
            "client_id": self.client_id,
            "grant_type": "password",
            "username": username,
            "password": password,
            "scope": "openid",
        }
        try:
            response = requests.post(
                self.token_url, data=payload, timeout=HTTP_TIMEOUT_SHORT_SECONDS
            )
            if response.status_code == 200:
                return response.json().get("access_token", "")
        except Exception as e:
            logger.debug(f"Chiamata a Keycloak fallita per {username}: {e}")
        return ""

    def _generate_mock_jwt(self, username: str) -> str:
        """
        Genera un token JWT fittizio/mock per fallback, impostando UUID realistici in 'sub'
        e ruoli specifici per ciascun utente.
        """
        mock_uuids = {
            "user_a": "f81d4fae-7dec-11d0-a765-00a0c91e6bfa",
            "user_b": "f81d4fae-7dec-11d0-a765-00a0c91e6bfb",
            "admin_user": "f81d4fae-7dec-11d0-a765-00a0c91e6bfc",
        }

        mock_roles = {"user_a": ["user"], "user_b": ["user"], "admin_user": ["admin"]}

        sub_uuid = mock_uuids.get(username, "00000000-0000-0000-0000-000000000000")
        roles = mock_roles.get(username, ["user"])

        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": sub_uuid,
            "name": username,
            "preferred_username": username,
            "roles": roles,
        }
        h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        signature = "mocksignature"
        return f"{h_b64}.{p_b64}.{signature}"


class DatabaseSeeder:
    """
    Gestisce l'iniezione dinamica di dati (Context-Aware Seeding) per tre utenti
    usando gli UUID estratti dai token.
    """

    def __init__(self, seed_url: str = f"{DEFAULT_TARGET_BASE_URL}/test/seed"):
        validate_url(seed_url, "seed_url")
        self.seed_url = seed_url

    def seed_target_application(
        self,
        dynamic_endpoints: list[dict[str, Any]],
        uuid_alice: str,
        uuid_bob: str,
        uuid_charlie: str,
    ) -> bool:
        """
        Popola il database Flask con le risorse di test ('orders', 'invoices', ecc.)
        associando le risorse a Alice (user_a), Bob (user_b) e Charlie (admin_user).
        """
        if not dynamic_endpoints:
            logger.info("Nessun endpoint dinamico rilevato per il seeding.")
            return True

        if not uuid_alice or not uuid_bob or not uuid_charlie:
            logger.error("Impossibile eseguire il seeding: UUID mancanti!")
            return False

        # Identifica le risorse dinamiche dall'inventario
        resources = {ep["resource_name"] for ep in dynamic_endpoints}

        # Costruisce il payload del seeding associando gli UUID agli utenti proprietari
        seed_payload = {}
        for res in resources:
            seed_payload[res] = {
                uuid_alice: "user_a",
                uuid_bob: "user_b",
                uuid_charlie: "admin_user",
            }

        logger.info(f"Esecuzione Context-Aware Seeding per risorse: {list(resources)}")

        try:
            response = requests.post(
                self.seed_url, json=seed_payload, timeout=HTTP_TIMEOUT_MEDIUM_SECONDS
            )
            if response.status_code == 200:
                logger.info("✅ Database Seeding completato con successo.")
                return True
            else:
                logger.warning(
                    f"⚠️ Endpoint di seeding ha risposto con codice {response.status_code}."
                )
        except Exception as e:
            logger.error(f"❌ Eccezione durante il seeding: {e}")

        return False
