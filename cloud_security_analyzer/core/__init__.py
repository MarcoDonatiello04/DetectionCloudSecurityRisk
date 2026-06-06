"""
Modulo core contenente funzionalità infrastrutturali della GUI:
- Threading asincrono (Worker)
- Configurazioni e design tokens (Config)
"""

from cloud_security_analyzer.core.config import (
    APP_VERSION,
    APP_TITLE,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_REPORT_FILE,
    DEFAULT_INVENTORY_FILE,
    COLOR_BACKGROUND_DARK,
    COLOR_SURFACE_DARK,
    COLOR_CARD_DARK,
    COLOR_BORDER_DARK,
    COLOR_TEXT_PRIMARY_DARK,
    COLOR_TEXT_SECONDARY_DARK,
    COLOR_TEXT_MUTED_DARK,
    SEVERITY_COLORS,
    SOURCE_COLORS,
    VALIDATION_STATUS_COLORS,
    get_absolute_path
)
from cloud_security_analyzer.core.worker import ThreadWorker, WorkerSignals
