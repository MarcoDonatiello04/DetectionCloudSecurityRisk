"""
OA-001 — Lookup per ID senza filtro sul soggetto autenticato.

Il caso BOLA "da manuale": l'handler è autenticato (decorator, middleware o identità
letta prima dell'accesso) ma recupera o modifica l'oggetto usando solo l'ID ricevuto
dal client, senza legarlo al chiamante (``filter_by(owner_id=current_user.id)``,
confronto ``obj.owner_id != current_user.id``, helper di ownership).
"""

from __future__ import annotations

from src.core.api1_bola.models import ObjectAuthzFinding, RouteHandler, RuleID
from src.core.api1_bola.rules._common import make_findings


class MissingOwnershipFilterRule:
    rule_id = RuleID.OA_001.value
    severity = "HIGH"
    confidence = 0.75

    @classmethod
    def applies(cls, handler: RouteHandler) -> bool:
        return bool(
            handler.object_accesses
            and not handler.ownership_checks
            and handler.privileged_role_guard is None
            and handler.is_authenticated
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
                    found_guard=handler.auth_evidence or handler.identity_evidence,
                    missing_guard=(
                        f"l'oggetto selezionato da '{access.id_param}' non è filtrato né "
                        "confrontato con il soggetto autenticato (ownership check assente)"
                    ),
                    evidence=access.text,
                    line_number=access.line_number,
                )
            )
        return findings
