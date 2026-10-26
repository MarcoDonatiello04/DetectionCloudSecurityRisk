"""
OA-002 — Riferimento diretto a un oggetto senza alcun contesto di identità.

L'ID ricevuto dal path arriva all'accesso all'oggetto senza che l'handler abbia una
guardia di autenticazione (decorator, middleware, dipendenza FastAPI, ``before_request``)
né legga l'identità del chiamante prima dell'accesso. Diversamente da OA-001 non c'è
nemmeno un soggetto rispetto a cui verificare l'appartenenza: chiunque conosca o
indovini l'ID raggiunge l'oggetto.
"""

from __future__ import annotations

from src.core.api1_bola.models import ObjectAuthzFinding, RouteHandler, RuleID
from src.core.api1_bola.rules._common import make_findings


class DirectObjectReferenceNoCheckRule:
    rule_id = RuleID.OA_002.value
    severity = "HIGH"
    confidence = 0.7

    @classmethod
    def applies(cls, handler: RouteHandler) -> bool:
        return bool(
            handler.object_accesses
            and not handler.ownership_checks
            and handler.privileged_role_guard is None
            and not handler.is_authenticated
        )

    @classmethod
    def analyze(cls, handlers: list[RouteHandler]) -> list[ObjectAuthzFinding]:
        findings: list[ObjectAuthzFinding] = []
        for handler in handlers:
            if not cls.applies(handler):
                continue
            access = handler.object_accesses[0]
            findings.extend(
                make_findings(
                    cls.rule_id,
                    handler,
                    severity=cls.severity,
                    confidence=cls.confidence,
                    id_parameter=access.id_param,
                    missing_guard=(
                        f"nessun riferimento all'identità o al ruolo del chiamante prima "
                        f"dell'accesso all'oggetto selezionato da '{access.id_param}'"
                    ),
                    evidence=access.text,
                    line_number=access.line_number,
                )
            )
        return findings
