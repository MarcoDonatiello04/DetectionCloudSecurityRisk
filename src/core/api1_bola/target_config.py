"""
Contratto cooperante del bersaglio BOLA (``config/bola_target.yaml``).

Un solo file per bersaglio raccoglie tutto ciò che prima era cablato in quattro
moduli (dynamic_orchestrator, identity_context, attack_vector, state_manager):

- ``target``      URL dell'app e host con cui ZAP (in container) la raggiunge;
- ``harness``     i tre endpoint dell'harness cooperante (seed/snapshot/rollback);
- ``identities``  provider (keycloak | static_tokens | traffic), realm/client e le
                  tre identità di test ``victim`` / ``peer`` / ``privileged``;
- ``assessment``  se in Assessment Mode i metodi mutanti sono ammessi.

Il loader segue lo stesso pattern di ``load_risk_scoring_config``: ogni chiave
assente ricade sul default del modulo, così i test e la modalità Lab restano
identici anche senza file. Le credenziali non stanno nel file (ADR-003): password
e token vengono lette dalle variabili d'ambiente indicate da ``password_env`` e
``token_env``.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from src.core.config import (
    DEFAULT_BOLA_TARGET_CONFIG,
    DEFAULT_CLIENT_ID,
    DEFAULT_KEYCLOAK_REALM,
    DEFAULT_KEYCLOAK_URL,
    DEFAULT_TARGET_BASE_URL,
    DEFAULT_USER_A_USERNAME,
    DEFAULT_USER_B_USERNAME,
    DEFAULT_USER_C_USERNAME,
    _read_yaml_mapping,
    _section,
)

logger = logging.getLogger("SecurityPlatform.BOLA.TargetConfig")

# ─── RUOLI LOGICI DELLE IDENTITÀ DI TEST ─────────────────────────────────────
# Nomi stabili con cui orchestratore, seeder e generatore di attacchi si riferiscono
# alle tre identità, indipendentemente dagli username reali del bersaglio.
IDENTITY_VICTIM = "victim"
IDENTITY_PEER = "peer"
IDENTITY_PRIVILEGED = "privileged"
IDENTITY_KEYS = (IDENTITY_VICTIM, IDENTITY_PEER, IDENTITY_PRIVILEGED)

# Chiavi storiche della headers_matrix (condivise con OwnershipInferenceEngine).
MATRIX_KEY_BY_IDENTITY = {
    IDENTITY_VICTIM: "userA",
    IDENTITY_PEER: "userB",
    IDENTITY_PRIVILEGED: "userC",
}
MATRIX_KEY_ANONYMOUS = "anonymous"

# Identity provider supportati
PROVIDER_KEYCLOAK = "keycloak"
PROVIDER_STATIC_TOKENS = "static_tokens"
PROVIDER_TRAFFIC = "traffic"
SUPPORTED_PROVIDERS = (PROVIDER_KEYCLOAK, PROVIDER_STATIC_TOKENS, PROVIDER_TRAFFIC)

# Host locali riscritti sull'host interno di ZAP
_LOCAL_HOSTS = ("localhost", "127.0.0.1")

DEFAULT_ZAP_INTERNAL_HOST = "api-server"
DEFAULT_HARNESS_SEED_PATH = "/test/seed"
DEFAULT_HARNESS_SNAPSHOT_PATH = "/test/snapshot"
DEFAULT_HARNESS_ROLLBACK_PATH = "/test/rollback"


@dataclass(frozen=True)
class IdentitySpec:
    """
    Una delle tre identità di test del bersaglio.

    Attributes:
        username (str): Username presso l'identity provider (e owner nel seeding).
        role (str): Ruolo atteso nella privilege matrix (``user``, ``admin``, ...).
        password_env (str): Variabile d'ambiente con la password (provider keycloak).
        token_env (str): Variabile d'ambiente con il JWT già emesso (provider static_tokens).
    """

    username: str
    role: str = "user"
    password_env: str = ""
    token_env: str = ""

    def password(self, fallback: str = "") -> str:
        """Password letta dall'ambiente, o ``fallback`` se la variabile è assente."""
        return os.getenv(self.password_env, fallback) if self.password_env else fallback

    def token(self) -> str:
        """JWT letto dall'ambiente (provider ``static_tokens``), o stringa vuota."""
        return os.getenv(self.token_env, "") if self.token_env else ""


def _default_users() -> dict[str, IdentitySpec]:
    return {
        IDENTITY_VICTIM: IdentitySpec(
            DEFAULT_USER_A_USERNAME, "user", "USER_A_PASSWORD", "BOLA_TOKEN_VICTIM"
        ),
        IDENTITY_PEER: IdentitySpec(
            DEFAULT_USER_B_USERNAME, "user", "USER_B_PASSWORD", "BOLA_TOKEN_PEER"
        ),
        IDENTITY_PRIVILEGED: IdentitySpec(
            DEFAULT_USER_C_USERNAME, "admin", "USER_C_PASSWORD", "BOLA_TOKEN_PRIVILEGED"
        ),
    }


@dataclass(frozen=True)
class BolaTargetConfig:
    """
    Contratto cooperante di un bersaglio BOLA, completo in ogni chiave.

    I default coincidono con quelli storici del laboratorio (``data/test_targets``);
    il file YAML può sovrascriverli chiave per chiave (vedi ``load_bola_target_config``).
    """

    base_url: str = DEFAULT_TARGET_BASE_URL
    zap_internal_host: str = DEFAULT_ZAP_INTERNAL_HOST
    seed_path: str = DEFAULT_HARNESS_SEED_PATH
    snapshot_path: str = DEFAULT_HARNESS_SNAPSHOT_PATH
    rollback_path: str = DEFAULT_HARNESS_ROLLBACK_PATH
    identity_provider: str = PROVIDER_KEYCLOAK
    keycloak_url: str = DEFAULT_KEYCLOAK_URL
    realm: str = DEFAULT_KEYCLOAK_REALM
    client_id: str = DEFAULT_CLIENT_ID
    users: dict[str, IdentitySpec] = field(default_factory=_default_users)
    allow_mutations: bool = False

    # ── URL dell'harness ─────────────────────────────────────────────────────

    def harness_url(self, path: str, base_url: str | None = None) -> str:
        """Compone l'URL assoluto di un endpoint dell'harness sul bersaglio."""
        base = (base_url or self.base_url).rstrip("/")
        return f"{base}/{path.lstrip('/')}"

    def seed_url(self, base_url: str | None = None) -> str:
        return self.harness_url(self.seed_path, base_url)

    def snapshot_url(self, base_url: str | None = None) -> str:
        return self.harness_url(self.snapshot_path, base_url)

    def rollback_url(self, base_url: str | None = None) -> str:
        return self.harness_url(self.rollback_path, base_url)

    @property
    def harness_paths(self) -> tuple[str, str, str]:
        """I tre path dell'harness (seed, snapshot, rollback), utili a chi li esclude."""
        return (self.seed_path, self.snapshot_path, self.rollback_path)

    # ── Identità ─────────────────────────────────────────────────────────────

    def identity(self, key: str) -> IdentitySpec:
        """L'identità con ruolo logico ``key`` (victim | peer | privileged)."""
        return self.users[key]

    @property
    def usernames(self) -> dict[str, str]:
        """Mappa ruolo logico -> username (es. ``{"victim": "user_a", ...}``)."""
        return {key: spec.username for key, spec in self.users.items()}

    @property
    def roles(self) -> dict[str, str]:
        """Mappa ruolo logico -> ruolo della privilege matrix."""
        return {key: spec.role for key, spec in self.users.items()}

    def identity_key_for_username(self, username: str) -> str | None:
        """Ruolo logico dell'username dato, o None se non è una delle identità di test."""
        return next((k for k, spec in self.users.items() if spec.username == username), None)

    @property
    def uses_traffic_identities(self) -> bool:
        """True se le identità vanno inferite dal traffico (Assessment Mode)."""
        return self.identity_provider == PROVIDER_TRAFFIC

    # ── Riscrittura per ZAP ──────────────────────────────────────────────────

    def to_zap_url(self, url: str) -> str:
        """
        Riscrive un URL locale sull'host con cui il container di ZAP raggiunge il bersaglio.

        Solo ``localhost``/``127.0.0.1`` vengono sostituiti: un bersaglio remoto o già
        espresso con l'host interno resta invariato. Porta, path e query sono conservati.

        Args:
            url (str): URL assoluto verso il bersaglio.

        Returns:
            str: L'URL con l'host riscritto, oppure l'originale.
        """
        return rewrite_host_for_zap(url, self.zap_internal_host)


def rewrite_host_for_zap(url: str, zap_internal_host: str) -> str:
    """Sostituisce l'host locale di ``url`` con ``zap_internal_host`` (vedi ``to_zap_url``)."""
    if not zap_internal_host:
        return url
    parts = urlsplit(url)
    if parts.hostname not in _LOCAL_HOSTS:
        return url
    netloc = zap_internal_host if parts.port is None else f"{zap_internal_host}:{parts.port}"
    if parts.username:
        auth = parts.username if parts.password is None else f"{parts.username}:{parts.password}"
        netloc = f"{auth}@{netloc}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


# ─── LOADER YAML ─────────────────────────────────────────────────────────────


def _string(section: dict[str, Any], key: str, fallback: str) -> str:
    value = section.get(key)
    return value.strip() if isinstance(value, str) and value.strip() else fallback


def _bool(section: dict[str, Any], key: str, fallback: bool) -> bool:
    value = section.get(key)
    return value if isinstance(value, bool) else fallback


def _users(section: dict[str, Any], defaults: dict[str, IdentitySpec]) -> dict[str, IdentitySpec]:
    """Unisce la sezione ``users`` ai default, identità per identità e chiave per chiave."""
    merged = dict(defaults)
    for key in IDENTITY_KEYS:
        raw = section.get(key)
        if not isinstance(raw, dict):
            continue
        base = defaults[key]
        merged[key] = IdentitySpec(
            username=_string(raw, "username", base.username),
            role=_string(raw, "role", base.role).lower(),
            password_env=_string(raw, "password_env", base.password_env),
            token_env=_string(raw, "token_env", base.token_env),
        )
    unknown = set(section) - set(IDENTITY_KEYS)
    if unknown:
        logger.warning(
            f"Identità non riconosciute in bola_target.yaml ignorate: {sorted(unknown)} "
            f"(attese: {list(IDENTITY_KEYS)})."
        )
    return merged


def load_bola_target_config(path: str | None = None) -> BolaTargetConfig:
    """
    Carica il contratto del bersaglio dal file YAML, ricadendo sui default del modulo.

    Args:
        path (str | None): Percorso del file; se None usa BOLA_TARGET_CONFIG
            (variabile d'ambiente) o ``config/bola_target.yaml``.

    Returns:
        BolaTargetConfig: La configurazione, completa in ogni chiave.
    """
    data = _read_yaml_mapping(path or DEFAULT_BOLA_TARGET_CONFIG)
    defaults = BolaTargetConfig()
    target = _section(data, "target")
    harness = _section(data, "harness")
    identities = _section(data, "identities")
    assessment = _section(data, "assessment")

    provider = _string(identities, "provider", defaults.identity_provider).lower()
    if provider not in SUPPORTED_PROVIDERS:
        logger.error(
            f"Identity provider '{provider}' non supportato (attesi: {list(SUPPORTED_PROVIDERS)}): "
            f"uso '{defaults.identity_provider}'."
        )
        provider = defaults.identity_provider

    return BolaTargetConfig(
        base_url=_string(target, "base_url", defaults.base_url),
        zap_internal_host=_string(target, "zap_internal_host", defaults.zap_internal_host),
        seed_path=_string(harness, "seed", defaults.seed_path),
        snapshot_path=_string(harness, "snapshot", defaults.snapshot_path),
        rollback_path=_string(harness, "rollback", defaults.rollback_path),
        identity_provider=provider,
        keycloak_url=_string(identities, "url", defaults.keycloak_url),
        realm=_string(identities, "realm", defaults.realm),
        client_id=_string(identities, "client_id", defaults.client_id),
        users=_users(_section(identities, "users"), defaults.users),
        allow_mutations=_bool(assessment, "allow_mutations", defaults.allow_mutations),
    )


# ─── ISTANZA CONDIVISA (stesso pattern di risk_config / bola_config) ─────────

_target_config: BolaTargetConfig | None = None


def get_bola_target_config() -> BolaTargetConfig:
    """Ritorna l'istanza condivisa del contratto del bersaglio (caricata una volta)."""
    global _target_config
    if _target_config is None:
        _target_config = load_bola_target_config()
    return _target_config


def reset_bola_target_config(config: BolaTargetConfig | None = None) -> None:
    """Sostituisce (o azzera, se None) l'istanza condivisa: il prossimo accesso la ricarica."""
    global _target_config
    _target_config = config
