import json
import logging
import os
from typing import Any

import yaml

logger = logging.getLogger("SecurityPlatform.Utilities.OpenAPI")


def load_openapi_spec(
    search_paths: list[str] | None = None, return_endpoints_list: bool = False
) -> Any:
    """
    Cerca e carica il contratto OpenAPI in formato dizionario o lista di endpoint,
    estraendo la logica di fallback ripetuta.

    Args:
        search_paths: Lista di percorsi file in cui cercare il contratto OpenAPI.
        return_endpoints_list: Se True, non ritorna l'intero dizionario ma una lista normalizzata di endpoint documentati.

    Returns:
        Any: Il dizionario OpenAPI, la lista degli endpoint, oppure None/lista vuota in caso di errore.
    """
    if not search_paths:
        search_paths = [
            "data/test_targets/bola/openapi.yaml",
            "../data/test_targets/bola/openapi.yaml",
            "./openapi.yaml",
            "openapi.json",
        ]

    spec = None
    for p in search_paths:
        if os.path.exists(p):
            try:
                with open(p, encoding="utf-8") as f:
                    if p.endswith(".yaml") or p.endswith(".yml"):
                        spec = yaml.safe_load(f)
                    else:
                        spec = json.load(f)
                break
            except Exception as e:
                logger.error(f"Errore caricamento spec OpenAPI da {p}: {e}")

    if not spec:
        return [] if return_endpoints_list else None

    if return_endpoints_list:
        endpoints = []
        paths = spec.get("paths", {})
        for path, path_item in paths.items():
            if not path_item:
                continue
            for method in ["get", "post", "put", "delete", "patch", "options", "head"]:
                if method in path_item:
                    endpoints.append(
                        {
                            "path": path,
                            "method": method.upper(),
                            "summary": path_item[method].get("summary", ""),
                            "description": path_item[method].get("description", ""),
                            "documented": True,
                        }
                    )
        return endpoints

    return spec


_OPENAPI_SKIP_DIRS = {"node_modules", "venv", ".venv", "__pycache__"}
_OPENAPI_SKIP_FILES = {"openapi_merged_temp.yaml"}


def find_openapi_spec_path(target_dir: str) -> str | None:
    """
    Cerca il contratto OpenAPI/Swagger dentro la directory del bersaglio.

    Stesso criterio di riconoscimento di SpectralScannerAdapter (firma ``openapi:`` o
    ``swagger:`` nei primi KB di un file YAML/JSON), ma con visita ordinata, cosi' che il
    file scelto sia deterministico. Non ricade mai su contratti di altri bersagli: se il
    bersaglio non ne contiene, ritorna None.

    Args:
        target_dir: Directory (o singolo file) del bersaglio.

    Returns:
        Il percorso del primo contratto trovato, oppure None.
    """
    if os.path.isfile(target_dir):
        return target_dir if _looks_like_openapi(target_dir) else None
    if not os.path.isdir(target_dir):
        return None
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d not in _OPENAPI_SKIP_DIRS)
        for name in sorted(files):
            if name in _OPENAPI_SKIP_FILES or not name.endswith((".yaml", ".yml", ".json")):
                continue
            path = os.path.join(root, name)
            if _looks_like_openapi(path):
                return path
    return None


def _looks_like_openapi(path: str) -> bool:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            head = f.read(4096)
    except OSError:
        return False
    return any(sig in head for sig in ("openapi:", "swagger:", '"openapi":', '"swagger":'))
