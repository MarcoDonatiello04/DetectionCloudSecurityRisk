"""
Gestisce le configurazioni globali e i token di design della GUI.
Responsabilità:
- Definizione dei colori e temi (Dark/Light).
- Gestione dei percorsi dei file e delle directory di output.
- Definizione di costanti per l'interfaccia utente.
"""

import os

# Versione dell'applicazione
APP_VERSION = "1.0.0"
APP_TITLE = "Cloud Security Analyzer"

# Directory di default
DEFAULT_OUTPUT_DIR = "output"
DEFAULT_REPORT_FILE = "unified_security_report.json"
DEFAULT_INVENTORY_FILE = "unified_api_inventory.json"

# Palette di colori per l'interfaccia e la grafica personalizzata (Hex/QColor equivalenti)
COLOR_BACKGROUND_DARK = "#080b11"
COLOR_SURFACE_DARK = "#0e1320"
COLOR_CARD_DARK = "#141b2d"
COLOR_BORDER_DARK = "#20293a"
COLOR_TEXT_PRIMARY_DARK = "#f3f4f6"
COLOR_TEXT_SECONDARY_DARK = "#9ca3af"
COLOR_TEXT_MUTED_DARK = "#6b7280"

# Colori per i livelli di severità (glowing modern palette)
SEVERITY_COLORS = {
    "CRITICAL": "#fb7185",   # Rose/Red
    "HIGH": "#fbbf24",       # Amber/Orange
    "MEDIUM": "#818cf8",     # Indigo
    "LOW": "#38bdf8",        # Sky Blue
    "INFO": "#14b8a6",       # Teal
    "UNTESTED": "#6b7280"    # Muted Gray
}

# Colori per i sorgenti degli scanner
SOURCE_COLORS = {
    "CHECKOV": "#38bdf8",            # IaC (Sky)
    "SEMGREP": "#10b981",            # AST (Emerald)
    "SPECTRAL": "#a78bfa",           # OpenAPI Compliance (Violet)
    "RUNTIME_VALIDATOR": "#fb7185",  # BOLA Stimulator (Rose)
    "SHADOW_API": "#fbbf24",         # Shadow API Detector (Amber)
    "ZAP_DAST": "#f97316"            # DAST scanner (Orange)
}

# Stati di validazione
VALIDATION_STATUS_COLORS = {
    "NOT_VALIDATED": "#6b7280",
    "CONFIRMED": "#10b981",
    "FALSE_POSITIVE": "#ef4444",
    "PARTIALLY_CONFIRMED": "#fbbf24",
    "ERROR": "#b91c1c"
}

def get_absolute_path(relative_path: str) -> str:
    """
    Ritorna il percorso assoluto a partire da quello relativo al workspace.
    """
    workspace_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.abspath(os.path.join(workspace_root, relative_path))
