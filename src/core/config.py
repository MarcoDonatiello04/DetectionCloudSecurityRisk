"""
Modulo di Configurazione Centralizzata (Security Platform Core Config).
Fornisce una singola fonte di verità per percorsi, URL, porte, timeout,
credenziali di test e pesi del motore di correlazione.
Supporta l'override via variabili d'ambiente.
"""

import os

# ─── PERCORSI E NOMI FILE DEFAULTS ───────────────────────────────────────────
DEFAULT_PLUGINS_DIR = os.getenv("PLUGINS_DIR", "src/plugins")
DEFAULT_OUTPUT_DIR = os.getenv("OUTPUT_DIR", "output")
DEFAULT_TRAFFIC_FILE = os.getenv("TRAFFIC_FILE", "soluzione_api/src/output/raw_traffic.json")
DEFAULT_FALLBACK_TRAFFIC_FILE = "output/raw_traffic.json"
DEFAULT_OPENAPI_SPEC_PATH = os.getenv("OPENAPI_SPEC_PATH", "test_targets/bola/openapi.yaml")

REPORT_FINDINGS_FILENAME = "unified_security_report.json"
REPORT_INVENTORY_FILENAME = "unified_api_inventory.json"
BENCHMARK_RESULTS_FILENAME = "benchmark_results.json"
BOLA_RESULTS_FILENAME = "bola_scan_results.json"

DEFAULT_SEMGREP_RULESET_PATH = "config/scanner_configs/route-detect.yaml"
DEFAULT_SEMGREP_OUTPUT_FILE = "semgrep_routes_discovered.json"
DEFAULT_CHECKOV_CONFIG = ".checkov.yaml"

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
DEFAULT_SCAN_TIMEOUT_SECONDS = 60

# ─── CREDENZIALI E PARAMETRI DI SEEDING ───────────────────────────────────────
DEFAULT_USER_A_USERNAME = os.getenv("USER_A_USERNAME", "user_a")
DEFAULT_USER_A_PASSWORD = os.getenv("USER_A_PASSWORD", "Password123!")
DEFAULT_USER_B_USERNAME = os.getenv("USER_B_USERNAME", "user_b")
DEFAULT_USER_B_PASSWORD = os.getenv("USER_B_PASSWORD", "Password123!")
DEFAULT_USER_C_USERNAME = os.getenv("USER_C_USERNAME", "admin_user")
DEFAULT_USER_C_PASSWORD = os.getenv("USER_C_PASSWORD", "Password123!")
DEFAULT_CLIENT_ID = os.getenv("CLIENT_ID", "security-platform-client")

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
RISK_WEIGHT_SEVERITY = 0.6
RISK_WEIGHT_CONFIDENCE = 0.2
RISK_WEIGHT_CONTEXT = 0.2

CONTEXT_SCORE_INTERNET_EXPOSED = 4.0
CONTEXT_SCORE_SENSITIVE_DATA = 4.0
CONTEXT_SCORE_PUBLIC_RESOURCE = 2.0

DEFAULT_CONTEXT_AUTHENTICATION_AUTHORIZATION = 6.0
DEFAULT_CONTEXT_OTHER = 3.0

MAX_RISK_SCORE = 10.0
CONFIDENCE_NORMALIZER = 10.0
