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
            "test_targets/bola/openapi.yaml",
            "../test_targets/bola/openapi.yaml",
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
