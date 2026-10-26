"""
OA-004 — Riferimento annidato non validato (``/orders/{id}/items/{item_id}``).

L'handler verifica l'ownership di un oggetto (tipicamente il genitore) ma accede a un
secondo oggetto con un ID che non è legato né al soggetto autenticato né all'oggetto
già validato: l'attaccante combina un ordine proprio con l'item di un ordine altrui.
Un ID si considera legato se il suo accesso è filtrato sull'identità, se l'istruzione
di accesso cita un ID/oggetto già validato (``filter_by(id=item_id, order_id=order_id)``,
``order.items.get(item_id)``) o se un confronto lo aggancia a esso
(``item.order_id != order.id``).
"""

from __future__ import annotations

from src.core.api1_bola.models import ObjectAuthzFinding, RouteHandler, RuleID
from src.core.api1_bola.rules._common import make_findings


class UnvalidatedNestedObjectReferenceRule:
    rule_id = RuleID.OA_004.value
    severity = "HIGH"
    confidence = 0.7

    @classmethod
    def unbound_params(cls, handler: RouteHandler) -> list[str]:
        if len(handler.id_params) < 2 or not handler.validated_params:
            return []
        if handler.privileged_role_guard is not None:
            return []
        if any(c.kind == "decorator" for c in handler.ownership_checks):
            return []
        return [p for p in handler.accessed_params if p not in handler.bound_params]

    @classmethod
    def analyze(cls, handlers: list[RouteHandler]) -> list[ObjectAuthzFinding]:
        findings: list[ObjectAuthzFinding] = []
        for handler in handlers:
            validated = ", ".join(handler.validated_params)
            for param in cls.unbound_params(handler):
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
                        found_guard=f"ownership validato su: {validated}",
                        missing_guard=(
                            f"l'oggetto selezionato da '{param}' non è legato all'oggetto "
                            "validato né al soggetto autenticato"
                        ),
                        evidence=access.text,
                        line_number=access.line_number,
                    )
                )
        return findings
