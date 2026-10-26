"""Costruzione uniforme dei finding API1 a partire da un handler e da un metodo HTTP."""

from __future__ import annotations

from src.core.api1_bola.models import (
    CWE_BOLA,
    RULE_CATEGORY,
    ObjectAuthzFinding,
    RouteHandler,
)
from src.normalization.normalizer import APIEndpointNormalizer

# Metodi per cui l'accesso a un oggetto altrui è una violazione BOLA (HEAD/OPTIONS esclusi).
BOLA_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}


def correlation_key(method: str, path: str) -> str:
    """Chiave condivisa con il validatore runtime BOLA e con Spectral (API1)."""
    return f"api:{method.upper()}:{APIEndpointNormalizer.normalize_path(path)}"


def relevant_methods(handler: RouteHandler) -> list[str]:
    return [m for m in handler.http_methods if m.upper() in BOLA_METHODS]


def make_findings(
    rule_id: str,
    handler: RouteHandler,
    *,
    severity: str,
    confidence: float,
    id_parameter: str | None,
    missing_guard: str,
    evidence: str,
    line_number: int | None,
    found_guard: str | None = None,
    methods: list[str] | None = None,
) -> list[ObjectAuthzFinding]:
    """Un finding per metodo HTTP: la correlazione con il runtime è per ``api:METODO:path``."""
    return [
        ObjectAuthzFinding(
            rule_id=rule_id,
            cwe_id=CWE_BOLA,
            category=RULE_CATEGORY[rule_id],
            severity=severity,
            file_path=handler.file_path,
            line_number=line_number,
            endpoint=handler.path,
            http_methods=[method],
            id_parameter=id_parameter,
            found_guard=found_guard,
            missing_guard=missing_guard,
            evidence=evidence.strip()[:300],
            confidence=round(confidence, 2),
            layer="ast",
            correlation_key=correlation_key(method, handler.path),
        )
        for method in (methods if methods is not None else relevant_methods(handler))
    ]
