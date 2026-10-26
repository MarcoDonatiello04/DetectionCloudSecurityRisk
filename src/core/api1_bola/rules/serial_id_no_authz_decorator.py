"""
OA-005 — ID numerico sequenziale esposto senza guardia di autenticazione.

Un identificativo intero (``<int:id>``, ``id: int``, ``:id(\\d+)`` o convertito con
``int()``/``parseInt()``/``Number()`` nel corpo) è enumerabile: incrementandolo si
percorre l'intero spazio degli oggetti. Se l'handler non dichiara alcuna guardia di
autenticazione (decorator, middleware, dipendenza, ``before_request``) l'enumerazione
è anonima. La regola misura una dimensione diversa dalle altre (predicibilità
dell'ID), quindi non compete con esse in deduplicazione; complementa la regola Spectral
``owasp-api1-object-level-security``, che vede il contratto ma non il tipo reale dell'ID.
"""

from __future__ import annotations

from src.core.api1_bola.models import ObjectAuthzFinding, RouteHandler, RuleID
from src.core.api1_bola.rules._common import make_findings


class SerialIdNoAuthzDecoratorRule:
    rule_id = RuleID.OA_005.value
    severity = "MEDIUM"
    confidence = 0.6

    @classmethod
    def analyze(cls, handlers: list[RouteHandler]) -> list[ObjectAuthzFinding]:
        findings: list[ObjectAuthzFinding] = []
        for handler in handlers:
            if handler.has_authentication:
                continue
            accessed = set(handler.accessed_params)
            for param in handler.numeric_id_params:
                if param not in accessed:
                    continue
                access = handler.first_access(param)
                if access is None:
                    continue
                findings.extend(
                    make_findings(
                        cls.rule_id,
                        handler,
                        severity=cls.severity,
                        confidence=cls.confidence,
                        id_parameter=param,
                        missing_guard=(
                            f"'{param}' è un intero sequenziale enumerabile e l'endpoint non "
                            "dichiara alcuna guardia di autenticazione"
                        ),
                        evidence=access.text,
                        line_number=access.line_number,
                    )
                )
        return findings
