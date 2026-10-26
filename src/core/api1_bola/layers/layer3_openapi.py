"""
Layer 3 — incrocio tra il contratto OpenAPI e l'esito del Layer 1 per API1:2023.

La regola Spectral ``owasp-api1-object-level-security`` segnala già le operazioni su
singolo oggetto prive di requisito ``security``. Questo layer non la duplica: per ogni
finding AST cerca l'operazione corrispondente nel contratto e ne registra lo stato:

- ``security_declared``: il contratto richiede autenticazione ma il codice non lega
  l'oggetto al chiamante. È il punto cieco della regola Spectral (che su questa
  operazione passa) e il caso BOLA più comune; la confidenza sale perché contratto
  e codice concordano sul fatto che l'endpoint sia per utenti autenticati.
- ``security_missing``: anche il contratto è scoperto; il finding si somma a quello
  Spectral sulla stessa chiave ``api:METODO:path``.
- ``not_documented``: l'handler non compare nel contratto (possibile shadow endpoint).
"""

from __future__ import annotations

import logging
from typing import Any

from src.core.api1_bola.models import ObjectAuthzFinding, RouteHandler
from src.normalization.normalizer import APIEndpointNormalizer

logger = logging.getLogger(__name__)

SECURITY_DECLARED = "security_declared"
SECURITY_MISSING = "security_missing"
NOT_DOCUMENTED = "not_documented"

_OPERATIONS = ("get", "put", "post", "patch", "delete")
_CONFIDENCE_BONUS = 0.1
_CONFIDENCE_CAP = 0.95


def detect_spec_version(spec: dict) -> str:
    if "openapi" in spec:
        return str(spec["openapi"])
    if "swagger" in spec:
        return str(spec["swagger"])
    raise ValueError("Unrecognized spec format — missing 'openapi' or 'swagger' key")


def _requires_auth(requirements: Any) -> bool:
    """``[{bearer: []}]`` richiede auth; ``[]`` o ``[{}]`` (auth opzionale) no."""
    if not isinstance(requirements, list):
        return False
    return any(isinstance(req, dict) and len(req) > 0 for req in requirements)


def index_operations(spec: dict) -> dict[tuple[str, str], dict[str, Any]]:
    """Operazioni del contratto indicizzate per (METODO, path normalizzato)."""
    global_security = spec.get("security")
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for raw_path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        norm = APIEndpointNormalizer.normalize_path(str(raw_path))
        for method in _OPERATIONS:
            operation = item.get(method)
            if not isinstance(operation, dict):
                continue
            security = operation.get("security", global_security)
            index[(method.upper(), norm)] = {
                "path": raw_path,
                "operation": operation,
                "security_declared": _requires_auth(security),
            }
    return index


def _match(
    index: dict[tuple[str, str], dict[str, Any]], method: str, path: str
) -> dict[str, Any] | None:
    norm = APIEndpointNormalizer.normalize_path(path)
    exact = index.get((method, norm))
    if exact is not None:
        return exact
    # basePath/servers diversi tra contratto e codice: confronto per suffisso di path
    for (op_method, op_path), entry in index.items():
        if op_method == method and (op_path.endswith(norm) or norm.endswith(op_path)):
            if op_path.count("{id}") == norm.count("{id}") and op_path != "/":
                return entry
    return None


def _enrich(entry: dict[str, Any], finding: ObjectAuthzFinding) -> None:
    operation = entry["operation"]
    analysis = operation.setdefault("x-security-analysis", {})
    if not isinstance(analysis, dict):
        return
    items = analysis.setdefault("api1_findings", [])
    record = {
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "missing_guard": finding.missing_guard,
        "layer": finding.layer,
        "contract_status": finding.contract_status,
    }
    if record not in items:
        items.append(record)


def analyze_openapi(
    spec: dict,
    ast_findings: list[ObjectAuthzFinding],
    handlers: list[RouteHandler] | None = None,
    enrich_spec: bool = False,
) -> list[ObjectAuthzFinding]:
    """
    Annota i finding AST con lo stato del contratto e ne ritorna la lista.

    Args:
        spec: Specifica OpenAPI/Swagger già caricata.
        ast_findings: Finding prodotti dal Layer 1.
        handlers: Handler del Layer 1 (non usati per i finding, riservati a estensioni).
        enrich_spec: Se True aggiunge ``x-security-analysis.api1_findings`` alle operazioni.

    Returns:
        list[ObjectAuthzFinding]: Gli stessi finding con ``contract_status`` e ``layer``.
    """
    try:
        detect_spec_version(spec)
    except ValueError as exc:
        logger.warning("OpenAPI spec ignorata: %s", exc)
        return ast_findings

    index = index_operations(spec)
    for finding in ast_findings:
        method = (finding.http_methods or ["GET"])[0].upper()
        entry = _match(index, method, finding.endpoint or "")
        if entry is None:
            finding.contract_status = NOT_DOCUMENTED
            continue
        finding.layer = "ast+openapi"
        if entry["security_declared"]:
            finding.contract_status = SECURITY_DECLARED
            finding.confidence = round(
                min(finding.confidence + _CONFIDENCE_BONUS, _CONFIDENCE_CAP), 2
            )
        else:
            finding.contract_status = SECURITY_MISSING
        if enrich_spec:
            _enrich(entry, finding)
    return ast_findings
