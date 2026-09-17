"""
Modulo di Configurazione Centralizzata (Security Platform Core Config).
Fornisce una singola fonte di verità per percorsi, URL, porte, timeout,
credenziali di test e pesi del motore di correlazione.
Supporta l'override via variabili d'ambiente.
"""

import logging
import os
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("SecurityPlatform.Config")

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# ─── PERCORSI E NOMI FILE DEFAULTS ───────────────────────────────────────────
DEFAULT_PLUGINS_DIR = os.getenv("PLUGINS_DIR", "src/plugins")
# Directory bersaglio della pipeline statica: e' il perimetro passato a IScanner.scan().
# Mai la radice della piattaforma, che conterrebbe tutti i bersagli di prova insieme.
DEFAULT_TARGET_DIR = os.getenv("TARGET_DIR", "data/test_targets/repo_target")
DEFAULT_OUTPUT_DIR = os.getenv("OUTPUT_DIR", "output")
DEFAULT_TRAFFIC_FILE = os.getenv("TRAFFIC_FILE", "soluzione_api/src/output/raw_traffic.json")
DEFAULT_FALLBACK_TRAFFIC_FILE = "output/raw_traffic.json"
DEFAULT_OPENAPI_SPEC_PATH = os.getenv("OPENAPI_SPEC_PATH", "data/test_targets/bola/openapi.yaml")

REPORT_FINDINGS_FILENAME = "unified_security_report.json"
REPORT_INVENTORY_FILENAME = "unified_api_inventory.json"
BENCHMARK_RESULTS_FILENAME = "benchmark_results.json"
BOLA_RESULTS_FILENAME = "bola_scan_results.json"

DEFAULT_SEMGREP_RULESET_PATH = "config/scanner_configs/route-detect.yaml"
DEFAULT_SEMGREP_OUTPUT_FILE = "semgrep_routes_discovered.json"
DEFAULT_CHECKOV_CONFIG = ".checkov.yaml"
# Catalogo semantico delle policy Checkov (natura EXPOSURE/HARDENING + severità di base)
DEFAULT_CHECKOV_POLICY_CATALOG = os.getenv(
    "CHECKOV_POLICY_CATALOG", "config/scanner_configs/checkov-policy-catalog.yaml"
)

# ─── SERVIZI E URL (MICROSERVIZI / CONTAINERS / PROXY) ───────────────────────
DEFAULT_KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
DEFAULT_KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "myrealm")
DEFAULT_TARGET_BASE_URL = os.getenv("TARGET_BASE_URL", "http://localhost:5000")
DEFAULT_ZAP_URL = os.getenv("ZAP_URL", "http://localhost:8090")
DEFAULT_OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
DEFAULT_LOCALSTACK_URL = os.getenv("LOCALSTACK_URL", "http://localhost:4566")

# ─── TIMEOUT E INTERVALLI PERMISSION/POLLING ─────────────────────────────────
HTTP_TIMEOUT_SHORT_SECONDS = 3
HTTP_TIMEOUT_MEDIUM_SECONDS = 5
ZAP_POLL_INTERVAL_SECONDS = 2
# Tempo massimo di attesa per la conclusione degli active scan di ZAP: oltre questa
# soglia il polling esce con un warning e gli scan vengono fermati (ZAP puo bloccarsi al 99%).
ZAP_ACTIVE_SCAN_TIMEOUT_SECONDS = int(os.getenv("ZAP_ACTIVE_SCAN_TIMEOUT_SECONDS", "300"))
DEFAULT_SCAN_TIMEOUT_SECONDS = 60

# ─── CREDENZIALI E PARAMETRI DI SEEDING ───────────────────────────────────────
DEFAULT_USER_A_USERNAME = os.getenv("USER_A_USERNAME", "user_a")
DEFAULT_USER_A_PASSWORD = os.getenv("USER_A_PASSWORD", "Password123!")
DEFAULT_USER_B_USERNAME = os.getenv("USER_B_USERNAME", "user_b")
DEFAULT_USER_B_PASSWORD = os.getenv("USER_B_PASSWORD", "Password123!")
DEFAULT_USER_C_USERNAME = os.getenv("USER_C_USERNAME", "admin_user")
DEFAULT_USER_C_PASSWORD = os.getenv("USER_C_PASSWORD", "Password123!")
DEFAULT_CLIENT_ID = os.getenv("CLIENT_ID", "security-platform-client")

# Contratto cooperante del bersaglio BOLA (URL, harness seed/snapshot/rollback,
# identity provider e identità di test): vedi src/core/api1_bola/target_config.py.
DEFAULT_BOLA_TARGET_CONFIG = os.getenv("BOLA_TARGET_CONFIG", "config/bola_target.yaml")

SEED_START_USER_A = 100
SEED_END_USER_A = 110
SEED_START_USER_B = 200
SEED_END_USER_B = 210

# ─── COMANDI TOOL ESTERNI ────────────────────────────────────────────────────
CHECKOV_CMD = "checkov"
SEMGREP_CMD = "semgrep"
SPECTRAL_CMD = "spectral"
DOCKER_CMD = "docker"

# ─── CORRELATION ENGINE SCORING & WEIGHTS ────────────────────────────────────
# Valori di default della formula R = min(MAX, wS·S + wC·(C·norm) + wX·X) (ADR-005).
# Sono sovrascrivibili dal file YAML `config/risk_scoring.yaml` (vedi
# load_risk_scoring_config): ogni chiave assente nel file ricade sul valore qui sotto.
DEFAULT_RISK_SCORING_CONFIG = os.getenv("RISK_SCORING_CONFIG", "config/risk_scoring.yaml")

RISK_WEIGHT_SEVERITY = 0.6
RISK_WEIGHT_CONFIDENCE = 0.2
RISK_WEIGHT_CONTEXT = 0.2

# Punteggio S per livello di severità: CRITICAL vale 10 così che il massimo teorico
# della formula sia esattamente MAX_RISK_SCORE e la guardia min(10, ·) sia effettiva.
SEVERITY_SCORE_CRITICAL = 10.0
SEVERITY_SCORE_HIGH = 7.0
SEVERITY_SCORE_MEDIUM = 4.5
SEVERITY_SCORE_LOW = 2.0
SEVERITY_SCORE_INFO = 0.0

CONTEXT_SCORE_INTERNET_EXPOSED = 4.0
CONTEXT_SCORE_SENSITIVE_DATA = 4.0
CONTEXT_SCORE_PUBLIC_RESOURCE = 2.0

# Contesto di ripiego quando l'adapter non ha allegato alcun RiskContext: vale per
# tutte le categorie, l'esposizione va dichiarata esplicitamente dalla sorgente.
DEFAULT_CONTEXT_OTHER = 3.0
# I finding di irrobustimento (nature=HARDENING) non ricevono il bonus di esposizione:
# una linea di difesa mancante non è di per sé un vettore d'accesso.
DEFAULT_CONTEXT_HARDENING = 0.0

MAX_RISK_SCORE = 10.0
CONFIDENCE_NORMALIZER = 10.0

# ─── CONFIDENZA PER SORGENTE (fattore C della formula, 0.0-1.0) ──────────────
# Checkov: quanto è precisa la regola del catalogo che ha classificato il controllo
CONFIDENCE_BY_CATALOG_MATCH = {"exact": 1.0, "prefix": 0.9, "keyword": 0.8, "default": 0.6}
# ZAP: livello di confidenza dichiarato dall'alert ("False Positive" viene scartato)
CONFIDENCE_BY_ZAP_LEVEL = {"User Confirmed": 1.0, "High": 0.9, "Medium": 0.7, "Low": 0.5}
CONFIDENCE_SEMGREP_POSITIVE_MATCH = 0.95  # decoratore/handler di autenticazione trovato
CONFIDENCE_SEMGREP_INFERRED_ABSENCE = 0.7  # assenza di autenticazione dedotta

# ─── MODULO BOLA (API1): CONFRONTO STRUTTURALE E GERARCHIA RUOLI ─────────────
# Sovrascrivibili dal file YAML `config/bola.yaml` (vedi load_bola_config).
DEFAULT_BOLA_CONFIG = os.getenv("BOLA_CONFIG", "config/bola.yaml")
# Campi JSON ricalcolati ad ogni richiesta (chi ha acceduto, timestamp, ...): ignorati
# nel confronto tra la risposta del proprietario e quella dell'attaccante.
BOLA_VOLATILE_FIELDS = ("accessed_by", "requested_by", "timestamp", "updated_at", "by")
# Gerarchia dei ruoli della privilege matrix: rango maggiore = più privilegi.
BOLA_ROLE_HIERARCHY = {"admin": 3, "manager": 2, "user": 1}


# ─── CONFIGURAZIONE DEL RISK SCORING (YAML + fallback sulle costanti) ────────


def _default_severity_scores() -> dict[str, float]:
    return {
        "CRITICAL": SEVERITY_SCORE_CRITICAL,
        "HIGH": SEVERITY_SCORE_HIGH,
        "MEDIUM": SEVERITY_SCORE_MEDIUM,
        "LOW": SEVERITY_SCORE_LOW,
        "INFO": SEVERITY_SCORE_INFO,
    }


@dataclass(frozen=True)
class RiskScoringConfig:
    """
    Parametri della formula di rischio e delle mappe di confidenza per sorgente.

    I default coincidono con le costanti di questo modulo; il file YAML può
    sovrascriverli chiave per chiave (vedi ``load_risk_scoring_config``).
    """

    weight_severity: float = RISK_WEIGHT_SEVERITY
    weight_confidence: float = RISK_WEIGHT_CONFIDENCE
    weight_context: float = RISK_WEIGHT_CONTEXT
    severity_scores: dict[str, float] = field(default_factory=_default_severity_scores)
    context_internet_exposed: float = CONTEXT_SCORE_INTERNET_EXPOSED
    context_sensitive_data: float = CONTEXT_SCORE_SENSITIVE_DATA
    context_public_resource: float = CONTEXT_SCORE_PUBLIC_RESOURCE
    default_context_other: float = DEFAULT_CONTEXT_OTHER
    default_context_hardening: float = DEFAULT_CONTEXT_HARDENING
    max_risk_score: float = MAX_RISK_SCORE
    confidence_normalizer: float = CONFIDENCE_NORMALIZER
    confidence_by_catalog_match: dict[str, float] = field(
        default_factory=lambda: dict(CONFIDENCE_BY_CATALOG_MATCH)
    )
    confidence_by_zap_level: dict[str, float] = field(
        default_factory=lambda: dict(CONFIDENCE_BY_ZAP_LEVEL)
    )
    confidence_semgrep_positive_match: float = CONFIDENCE_SEMGREP_POSITIVE_MATCH
    confidence_semgrep_inferred_absence: float = CONFIDENCE_SEMGREP_INFERRED_ABSENCE


def _read_yaml_mapping(path: str) -> dict[str, Any]:
    """
    Legge un file YAML atteso come mapping; ritorna {} se assente o non valido.

    Args:
        path (str): Percorso assoluto o relativo (alla cwd o alla radice del progetto).

    Returns:
        dict: Il contenuto del file, oppure un mapping vuoto.
    """
    resolved = next(
        (c for c in (path, os.path.join(_PROJECT_ROOT, path)) if os.path.isfile(c)), None
    )
    if not resolved:
        logger.warning(f"Configurazione '{path}' assente: uso i valori di default.")
        return {}
    try:
        import yaml

        with open(resolved, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except Exception as e:
        logger.error(f"Errore nella lettura di '{resolved}': {e}. Uso i valori di default.")
        return {}
    if not isinstance(data, dict):
        logger.error(f"Configurazione '{resolved}' non valida: atteso un mapping.")
        return {}
    return data


def _section(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    return value if isinstance(value, dict) else {}


def _number(section: dict[str, Any], key: str, fallback: float) -> float:
    value = section.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return fallback
    return float(value)


def _number_map(section: dict[str, Any], key: str, fallback: dict[str, float]) -> dict[str, float]:
    """Unisce una mappa numerica del file ai default, chiave per chiave."""
    merged = dict(fallback)
    for name, value in _section(section, key).items():
        if not isinstance(value, bool) and isinstance(value, (int, float)):
            merged[str(name)] = float(value)
    return merged


def load_risk_scoring_config(path: str | None = None) -> RiskScoringConfig:
    """
    Carica i parametri del risk scoring dal file YAML, ricadendo sui default del modulo.

    Args:
        path (str | None): Percorso del file; se None usa RISK_SCORING_CONFIG
            (variabile d'ambiente) o ``config/risk_scoring.yaml``.

    Returns:
        RiskScoringConfig: La configurazione, completa in ogni chiave.
    """
    data = _read_yaml_mapping(path or DEFAULT_RISK_SCORING_CONFIG)
    defaults = RiskScoringConfig()
    weights = _section(data, "weights")
    context = _section(data, "context")
    confidence = _section(data, "confidence")
    return RiskScoringConfig(
        weight_severity=_number(weights, "severity", defaults.weight_severity),
        weight_confidence=_number(weights, "confidence", defaults.weight_confidence),
        weight_context=_number(weights, "context", defaults.weight_context),
        severity_scores=_number_map(data, "severity_scores", defaults.severity_scores),
        context_internet_exposed=_number(
            context, "internet_exposed", defaults.context_internet_exposed
        ),
        context_sensitive_data=_number(context, "sensitive_data", defaults.context_sensitive_data),
        context_public_resource=_number(
            context, "public_resource", defaults.context_public_resource
        ),
        default_context_other=_number(context, "default_other", defaults.default_context_other),
        default_context_hardening=_number(
            context, "default_hardening", defaults.default_context_hardening
        ),
        max_risk_score=_number(data, "max_risk_score", defaults.max_risk_score),
        confidence_normalizer=_number(
            data, "confidence_normalizer", defaults.confidence_normalizer
        ),
        confidence_by_catalog_match=_number_map(
            confidence, "catalog_match", defaults.confidence_by_catalog_match
        ),
        confidence_by_zap_level=_number_map(
            confidence, "zap_level", defaults.confidence_by_zap_level
        ),
        confidence_semgrep_positive_match=_number(
            confidence, "semgrep_positive_match", defaults.confidence_semgrep_positive_match
        ),
        confidence_semgrep_inferred_absence=_number(
            confidence, "semgrep_inferred_absence", defaults.confidence_semgrep_inferred_absence
        ),
    )


# ─── CONFIGURAZIONE DEL MODULO BOLA (YAML + fallback sulle costanti) ─────────


@dataclass(frozen=True)
class BolaConfig:
    """
    Parametri dell'assertion engine e della privilege matrix del modulo BOLA.

    I default coincidono con le costanti di questo modulo; il file YAML può
    sovrascriverli chiave per chiave (vedi ``load_bola_config``).
    """

    volatile_fields: frozenset[str] = field(default_factory=lambda: frozenset(BOLA_VOLATILE_FIELDS))
    role_hierarchy: dict[str, int] = field(default_factory=lambda: dict(BOLA_ROLE_HIERARCHY))


def load_bola_config(path: str | None = None) -> BolaConfig:
    """
    Carica i parametri del modulo BOLA dal file YAML, ricadendo sui default del modulo.

    Una lista ``volatile_fields`` presente nel file sostituisce integralmente quella di
    default; la mappa ``roles`` viene accettata solo se contiene almeno un ruolo con
    rango intero, altrimenti resta la gerarchia di default.

    Args:
        path (str | None): Percorso del file; se None usa BOLA_CONFIG
            (variabile d'ambiente) o ``config/bola.yaml``.

    Returns:
        BolaConfig: La configurazione, completa in ogni chiave.
    """
    data = _read_yaml_mapping(path or DEFAULT_BOLA_CONFIG)
    defaults = BolaConfig()

    volatile_fields = defaults.volatile_fields
    raw_fields = _section(data, "structural_match").get("volatile_fields")
    if isinstance(raw_fields, list):
        volatile_fields = frozenset(str(f).strip() for f in raw_fields if str(f).strip())

    role_hierarchy = defaults.role_hierarchy
    raw_roles = {
        str(name).lower().strip(): int(rank)
        for name, rank in _section(data, "roles").items()
        if isinstance(rank, int) and not isinstance(rank, bool)
    }
    if raw_roles:
        role_hierarchy = raw_roles
    elif "roles" in data:
        logger.error(
            f"Sezione 'roles' di '{path or DEFAULT_BOLA_CONFIG}' non valida "
            "(atteso mapping ruolo -> rango intero): uso la gerarchia di default."
        )

    return BolaConfig(volatile_fields=volatile_fields, role_hierarchy=role_hierarchy)
