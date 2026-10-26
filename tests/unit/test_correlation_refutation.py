"""
Esiti runtime "sicuri" nel RiskCorrelationEngine.

Un esito ``dynamic-test-secure`` attesta che l'attacco è stato bloccato: non deve elevare
il finding statico con la stessa chiave (prima lo portava a CRITICAL / confidenza 1.0),
ma registrarne la smentita. Una conferma runtime sulla stessa chiave prevale sempre,
indipendentemente dall'ordine degli esiti.
"""

import pytest

from src.application.correlation.engine import RiskCorrelationEngine
from src.domain.entities import (
    APIContext,
    Finding,
    FindingCategory,
    FindingSource,
    RuntimeEvidence,
    Severity,
)

KEY = "api:GET:/api/orders/{id}"


def _static() -> Finding:
    return Finding.create(
        source=FindingSource.STATIC_ANALYZER,
        category=FindingCategory.AUTHORIZATION,
        title="[API1 OA-001] missing_ownership_filter",
        description="lookup per solo ID",
        severity=Severity.HIGH,
        confidence=0.8,
        rule_id="OA-001",
        target_identifier="app.py|GET|/api/orders/<order_id>|order_id",
        correlation_key=KEY,
    )


def _runtime(rule_id: str, status: int, suffix: str) -> Finding:
    secure = rule_id == "dynamic-test-secure"
    return Finding.create(
        source=FindingSource.RUNTIME_VALIDATOR,
        category=FindingCategory.AUTHORIZATION,
        title=f"Test {suffix}",
        description="",
        severity=Severity.INFO if secure else Severity.HIGH,
        confidence=1.0,
        rule_id=rule_id,
        target_identifier=f"GET:/api/orders/1:{suffix}",
        api=APIContext(endpoint="/api/orders/1", method="GET"),
        runtime_evidence=RuntimeEvidence(tested_url="http://t/api/orders/1", http_status=status),
        correlation_key=KEY,
    )


def test_safe_runtime_result_refutes_instead_of_elevating():
    safe = _runtime("dynamic-test-secure", 403, "BOLA Orizzontale")
    (merged,) = RiskCorrelationEngine().correlate([_static()], [safe])
    assert merged.rule_id == "OA-001"
    assert merged.severity == Severity.HIGH
    assert merged.confidence == pytest.approx(0.4)
    assert merged.runtime_evidence is None
    assert merged.raw_data["runtime_refuted"] is True
    assert merged.raw_data["runtime_refutations"][0]["http_status"] == 403
    assert safe.finding_id in merged.related_findings


@pytest.mark.parametrize("safe_first", [True, False])
def test_confirmation_wins_over_safe_results_in_any_order(safe_first):
    safe = _runtime("dynamic-test-secure", 200, "Privilegio Legittimo")
    vuln = _runtime("dynamic-bola-exploited", 200, "BOLA Orizzontale")
    runtime = [safe, vuln] if safe_first else [vuln, safe]
    (merged,) = RiskCorrelationEngine().correlate([_static()], runtime)
    assert merged.severity == Severity.CRITICAL and merged.confidence == 1.0
    assert merged.runtime_evidence is not None
    assert "runtime_refuted" not in merged.raw_data
    assert {safe.finding_id, vuln.finding_id} <= set(merged.related_findings)


def test_multiple_safe_results_reduce_confidence_once():
    runtime = [
        _runtime("dynamic-test-secure", 403, "BOLA Orizzontale"),
        _runtime("dynamic-test-secure", 403, "BOLA Verticale"),
    ]
    (merged,) = RiskCorrelationEngine().correlate([_static()], runtime)
    assert merged.confidence == pytest.approx(0.4)
    assert len(merged.raw_data["runtime_refutations"]) == 2


def test_safe_result_without_static_finding_stays_visible():
    safe = _runtime("dynamic-test-secure", 403, "BOLA Orizzontale")
    (entry,) = RiskCorrelationEngine().correlate([], [safe])
    assert entry.finding_id == safe.finding_id and entry.severity == Severity.INFO


def test_safe_result_does_not_elevate_runtime_vulnerability():
    vuln = _runtime("dynamic-bola-exploited", 200, "BOLA Orizzontale")
    safe = _runtime("dynamic-test-secure", 403, "BOLA Verticale")
    (entry,) = RiskCorrelationEngine().correlate([], [vuln, safe])
    assert entry.finding_id == vuln.finding_id
    assert entry.severity == Severity.HIGH
    assert safe.finding_id in entry.related_findings
