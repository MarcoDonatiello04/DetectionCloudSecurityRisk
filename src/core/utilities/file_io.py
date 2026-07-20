import json
import logging
import os
from typing import Any

logger = logging.getLogger("SecurityPlatform.Utilities.FileIO")


def safe_read_json(filepath: str, default: Any = None) -> Any:
    """
    Legge in modo sicuro un file JSON. Ritorna `default` se il file non esiste o è invalido.
    """
    if default is None:
        default = []

    if not os.path.exists(filepath):
        return default

    try:
        with open(filepath, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Errore durante la lettura del file JSON {filepath}: {e}")
        return default


def safe_write_json(filepath: str, data: Any) -> bool:
    """
    Scrive in modo sicuro dati in formato JSON. Crea le directory intermedie se necessario.
    """
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        logger.error(f"Errore durante la scrittura del file JSON {filepath}: {e}")
        return False
