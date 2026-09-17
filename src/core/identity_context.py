"""
Modulo Identity Context e Seeding per il framework ASPM D-AST.
Fornisce la gestione delle identità (IdentityManager) con estrazione dinamica degli UUID dei token JWT
(tramite tecnica di "Context-Aware Seeding" con decodifica del claim 'sub')
e il popolamento deterministico del database target (DatabaseSeeder) con tali UUID.

Le tre identità (vittima, pari grado, privilegiata), l'identity provider e gli endpoint
dell'harness non sono cablati qui: arrivano dal contratto del bersaglio
(``config/bola_target.yaml``, vedi ``src/core/api1_bola/target_config.py``).
"""

import base64
import json
import logging
from dataclasses import dataclass, field
from typing import Any

import jwt
import requests

from src.core.api1_bola.target_config import (
    IDENTITY_KEYS,
    MATRIX_KEY_ANONYMOUS,
    MATRIX_KEY_BY_IDENTITY,
    PROVIDER_STATIC_TOKENS,
    BolaTargetConfig,
    IdentitySpec,
    get_bola_target_config,
)
from src.core.config import (
    DEFAULT_USER_A_PASSWORD,
    DEFAULT_USER_B_PASSWORD,
    DEFAULT_USER_C_PASSWORD,
    HTTP_TIMEOUT_MEDIUM_SECONDS,
    HTTP_TIMEOUT_SHORT_SECONDS,
)

# Configurazione logging
logger = logging.getLogger("SecurityPlatform.IdentityContext")

# Password di ripiego del laboratorio quando la variabile `password_env` è assente
_DEFAULT_PASSWORDS = {
    "victim": DEFAULT_USER_A_PASSWORD,
    "peer": DEFAULT_USER_B_PASSWORD,
    "privileged": DEFAULT_USER_C_PASSWORD,
}

# UUID fittizi e stabili per il fallback offline (uno per identità logica)
_MOCK_UUIDS = {
    "victim": "f81d4fae-7dec-11d0-a765-00a0c91e6bfa",
    "peer": "f81d4fae-7dec-11d0-a765-00a0c91e6bfb",
    "privileged": "f81d4fae-7dec-11d0-a765-00a0c91e6bfc",
}


def validate_url(url: str, param_name: str) -> None:
    """
    Valida la struttura formale di un URL passato come parametro.
    """
    if not url or not (url.startswith("http://") or url.startswith("https://")):
        raise ValueError(
            f"Parametro '{param_name}' non valido: deve iniziare con http:// o https://. Valore: {url}"
        )


def role_from_jwt_payload(payload: dict[str, Any], fallback: str = "user") -> str:
    """Ruolo della privilege matrix dedotto dal claim ``roles`` (admin > manager > user)."""
    roles = {str(r).lower() for r in (payload.get("roles") or [])}
    if "admin" in roles:
        return "admin"
    if "manager" in roles:
        return "manager"
    return fallback


class IdentityManager:
    """
    Gestisce l'acquisizione dei token JWT per le tre identità del contratto:
    - victim:     proprietario della risorsa attaccata (utente standard)
    - peer:       attaccante paritetico (utente standard)
    - privileged: identità con ruolo superiore (admin)
    Estrae l'UUID reale dal claim standard 'sub' e memorizza il ruolo associato.

    Provider supportati (``identities.provider``):
    - ``keycloak``: password grant sul realm/client configurati;
    - ``static_tokens``: JWT già emessi letti dalle variabili ``token_env`` (repo con IdP proprio).
    In entrambi i casi, senza token si ricade su un JWT fittizio con UUID realistico.
    """

    def __init__(
        self,
        config: BolaTargetConfig | None = None,
        keycloak_url: str | None = None,
        realm: str | None = None,
    ):
        """
        Args:
            config (BolaTargetConfig | None): Contratto del bersaglio; se None usa quello condiviso.
            keycloak_url (str | None): Override dell'URL di Keycloak (es. da CLI).
            realm (str | None): Override del realm.
        """
        self.config = config or get_bola_target_config()
        self.provider = self.config.identity_provider
        base_url = keycloak_url or self.config.keycloak_url
        validate_url(base_url, "keycloak_url")
        self.realm = realm or self.config.realm
        self.token_url = f"{base_url.rstrip('/')}/realms/{self.realm}/protocol/openid-connect/token"
        self.client_id = self.config.client_id

        # Mappa ruolo logico -> UUID (claim 'sub') e UUID -> ruolo della privilege matrix
        self.identity_map: dict[str, str | None] = dict.fromkeys(IDENTITY_KEYS)
        self.role_map: dict[str, str] = {}

    @property
    def uuids(self) -> dict[str, str]:
        """Mappa ruolo logico -> UUID per le sole identità risolte."""
        return {key: uid for key, uid in self.identity_map.items() if uid}

    def get_headers_for_identities(self) -> dict[str, dict[str, str]]:
        """
        Ottiene i token JWT (Keycloak o statici) o genera token fittizi (fallback).
        Estrae l'UUID dal claim 'sub' e il ruolo decodificando il JWT.

        Returns:
            dict: La headers_matrix ``{"userA": {...}, "userB": {...}, "userC": {...}, "anonymous": {}}``.
        """
        headers_matrix: dict[str, dict[str, str]] = {
            **{MATRIX_KEY_BY_IDENTITY[key]: {} for key in IDENTITY_KEYS},
            MATRIX_KEY_ANONYMOUS: {},  # Header vuoti per Broken Auth
        }

        for identity_key in IDENTITY_KEYS:
            spec = self.config.identity(identity_key)
            token = self._acquire_token(identity_key, spec)
            headers_matrix[MATRIX_KEY_BY_IDENTITY[identity_key]] = {
                "Authorization": f"Bearer {token}"
            }

            # Estrazione dell'UUID e del ruolo decodificando il JWT (firma non verificata)
            try:
                payload = jwt.decode(token, options={"verify_signature": False})
                sub_uuid = payload.get("sub")
                role = role_from_jwt_payload(payload, fallback=spec.role)
                if sub_uuid:
                    self.identity_map[identity_key] = sub_uuid
                    self.role_map[sub_uuid] = role
                    logger.info(
                        f"IdentityManager: {identity_key} ({spec.username}) -> {sub_uuid} (Ruolo: {role})"
                    )
                else:
                    logger.warning(f"Claim 'sub' non presente nel JWT per {identity_key}")
            except Exception as e:
                logger.error(
                    f"Errore durante l'estrazione dei dati dal JWT per {identity_key}: {e}"
                )

        logger.info(f"Mappa delle identità globali completata: {self.identity_map}")
        logger.info(f"Mappa dei ruoli completata: {self.role_map}")
        return headers_matrix

    def _acquire_token(self, identity_key: str, spec: IdentitySpec) -> str:
        """Token reale dal provider configurato, altrimenti JWT fittizio di fallback."""
        if self.provider == PROVIDER_STATIC_TOKENS:
            token = spec.token()
            if token:
                logger.info(f"Token statico letto da ${spec.token_env} per {spec.username}")
                return token
            logger.warning(
                f"Variabile ${spec.token_env or '<non configurata>'} assente per {identity_key}. "
                "Utilizzo di un JWT di fallback con UUID realistico."
            )
        else:
            password = spec.password(_DEFAULT_PASSWORDS.get(identity_key, ""))
            token = self._fetch_token(spec.username, password)
            if token:
                logger.info(f"Ottenuto token JWT reale da Keycloak per {spec.username}")
                return token
            logger.warning(
                f"Keycloak offline per {identity_key}. Utilizzo di un JWT di fallback con UUID realistico."
            )
        return self._generate_mock_jwt(identity_key, spec)

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

    def _generate_mock_jwt(self, identity_key: str, spec: IdentitySpec | None = None) -> str:
        """
        Genera un token JWT fittizio/mock per fallback, impostando un UUID realistico in 'sub'
        e il ruolo dichiarato nel contratto per l'identità.
        """
        spec = spec or self.config.identity(identity_key)
        sub_uuid = _MOCK_UUIDS.get(identity_key, "00000000-0000-0000-0000-000000000000")

        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": sub_uuid,
            "name": spec.username,
            "preferred_username": spec.username,
            "roles": [spec.role],
        }
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        # Firma fittizia ma con padding base64url valido: senza di essa jwt.decode
        # fallisce ("Invalid crypto padding") e l'UUID non verrebbe mai estratto offline.
        signature = base64.urlsafe_b64encode(b"mock-signature").decode().rstrip("=")
        return f"{header_b64}.{payload_b64}.{signature}"


@dataclass(frozen=True)
class SeedOutcome:
    """
    Esito del seeding cooperante.

    Attributes:
        success (bool): True se l'harness ha accettato il payload.
        resource_ids (dict): Mappa ``{risorsa: {ruolo_logico: id_creato}}`` degli ID
            effettivamente creati dal bersaglio; vuota se l'harness non li riporta.
    """

    success: bool
    resource_ids: dict[str, dict[str, str]] = field(default_factory=dict)


class DatabaseSeeder:
    """
    Gestisce l'iniezione dinamica di dati (Context-Aware Seeding) per le tre identità
    usando gli UUID estratti dai token.

    Il payload inviato è ``{risorsa: {uuid_utente: username}}``. L'harness può rispondere
    con ``{"ids": {risorsa: {username: id_creato}}}``: è il vincolo "ID risorsa = UUID del
    proprietario" reso opzionale, perché un DB reale spesso non accetta ID arbitrari in
    creazione. Gli ID riportati vengono usati negli scenari al posto degli UUID.
    """

    def __init__(self, seed_url: str | None = None, config: BolaTargetConfig | None = None):
        """
        Args:
            seed_url (str | None): URL assoluto dell'endpoint di seeding; se None è
                composto dal contratto (``base_url`` + ``harness.seed``).
            config (BolaTargetConfig | None): Contratto del bersaglio; se None usa quello condiviso.
        """
        self.config = config or get_bola_target_config()
        self.seed_url = seed_url or self.config.seed_url()
        validate_url(self.seed_url, "seed_url")

    def seed_target_application(
        self,
        dynamic_endpoints: list[dict[str, Any]],
        identity_uuids: dict[str, str | None],
    ) -> SeedOutcome:
        """
        Popola il bersaglio con le risorse di test associando ogni risorsa alle tre identità.

        Args:
            dynamic_endpoints (list): Endpoint dinamici dell'inventario (con ``resource_name``).
            identity_uuids (dict): Mappa ruolo logico -> UUID (claim 'sub').

        Returns:
            SeedOutcome: Esito e, se l'harness li riporta, gli ID creati per ogni risorsa.
        """
        if not dynamic_endpoints:
            logger.info("Nessun endpoint dinamico rilevato per il seeding.")
            return SeedOutcome(success=True)

        missing = [key for key in IDENTITY_KEYS if not identity_uuids.get(key)]
        if missing:
            logger.error(f"Impossibile eseguire il seeding: UUID mancanti per {missing}!")
            return SeedOutcome(success=False)

        # Identifica le risorse dinamiche dall'inventario
        resources = {endpoint["resource_name"] for endpoint in dynamic_endpoints}
        usernames = self.config.usernames

        # Costruisce il payload del seeding associando gli UUID agli utenti proprietari
        seed_payload = {
            resource: {identity_uuids[key]: usernames[key] for key in IDENTITY_KEYS}
            for resource in resources
        }

        logger.info(f"Esecuzione Context-Aware Seeding per risorse: {list(resources)}")

        try:
            response = requests.post(
                self.seed_url, json=seed_payload, timeout=HTTP_TIMEOUT_MEDIUM_SECONDS
            )
            if response.status_code == 200:
                logger.info("✅ Database Seeding completato con successo.")
                return SeedOutcome(success=True, resource_ids=self._parse_created_ids(response))
            logger.warning(f"⚠️ Endpoint di seeding ha risposto con codice {response.status_code}.")
        except Exception as e:
            logger.error(f"❌ Eccezione durante il seeding: {e}")

        return SeedOutcome(success=False)

    def _parse_created_ids(self, response: Any) -> dict[str, dict[str, str]]:
        """
        Traduce ``{"ids": {risorsa: {username: id}}}`` in ``{risorsa: {ruolo_logico: id}}``.
        Username sconosciuti al contratto vengono ignorati; risposta senza ``ids`` -> {}.
        """
        try:
            body = response.json()
        except Exception:
            return {}
        raw_ids = body.get("ids") if isinstance(body, dict) else None
        if not isinstance(raw_ids, dict):
            return {}

        created: dict[str, dict[str, str]] = {}
        for resource, by_username in raw_ids.items():
            if not isinstance(by_username, dict):
                continue
            for username, resource_id in by_username.items():
                key = self.config.identity_key_for_username(str(username))
                if key and resource_id not in (None, ""):
                    created.setdefault(str(resource), {})[key] = str(resource_id)
        if created:
            logger.info(f"ID creati riportati dall'harness: {created}")
        return created
