"""
OA-003 — Ownership check presente su un metodo e assente su un altro della stessa risorsa.

Gli handler vengono raggruppati per path normalizzato (``/orders/{id}``) e linguaggio:
se almeno un metodo lega l'oggetto al chiamante e un altro metodo accede allo stesso
oggetto senza farlo, il secondo è un'omissione quasi certa. Il segnale è più forte di
OA-001 perché lo stesso codice dimostra che l'ownership era un requisito noto.
Gli handler protetti da un ruolo privilegiato non contano in nessuno dei due insiemi:
"lettura al proprietario, cancellazione all'admin" è un disegno legittimo (dominio API5).
"""

from __future__ import annotations

from collections import defaultdict

from src.core.api1_bola.models import ObjectAuthzFinding, RouteHandler, RuleID
from src.core.api1_bola.rules._common import make_findings, relevant_methods
from src.normalization.normalizer import APIEndpointNormalizer


class InconsistentAuthzAcrossMethodsRule:
    rule_id = RuleID.OA_003.value
    severity = "HIGH"
    confidence = 0.85

    @classmethod
    def analyze(cls, handlers: list[RouteHandler]) -> list[ObjectAuthzFinding]:
        groups: dict[tuple[str, str], list[RouteHandler]] = defaultdict(list)
        for handler in handlers:
            if handler.object_accesses and handler.privileged_role_guard is None:
                key = (handler.language, APIEndpointNormalizer.normalize_path(handler.path))
                groups[key].append(handler)

        findings: list[ObjectAuthzFinding] = []
        for group in groups.values():
            protected = [h for h in group if h.ownership_checks]
            unprotected = [h for h in group if not h.ownership_checks]
            if not protected or not unprotected:
                continue
            reference = protected[0]
            check = reference.ownership_checks[0]
            protected_methods = sorted({m for h in protected for m in relevant_methods(h)})
            for handler in unprotected:
                access = handler.object_accesses[0]
                findings.extend(
                    make_findings(
                        cls.rule_id,
                        handler,
                        severity=cls.severity,
                        confidence=cls.confidence,
                        id_parameter=access.id_param,
                        found_guard=(
                            f"ownership check su {', '.join(protected_methods)} "
                            f"({reference.function_name}, riga {check.line_number})"
                        ),
                        missing_guard=(
                            "lo stesso ownership check manca su questo metodo della risorsa"
                        ),
                        evidence=access.text,
                        line_number=access.line_number,
                    )
                )
        return findings
