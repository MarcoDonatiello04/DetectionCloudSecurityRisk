import re
from pathlib import Path

import pytest

from src.application.correlation.engine import RiskCorrelationEngine
from src.application.event_bus import EventBus
from src.domain.entities import Finding, FindingCategory, FindingSource, Severity
from src.normalization.normalizer import APIEndpointNormalizer


def test_event_bus_pub_sub():
    bus = EventBus()
    received_events = []

    def test_handler(event):
        received_events.append(event)

    bus.subscribe("test.event", test_handler)
    bus.publish("test.event", {"data": "hello"})

    assert len(received_events) == 1
    assert received_events[0].name == "test.event"
    assert received_events[0].payload["data"] == "hello"


def test_api_endpoint_normalization():
    normalizer = APIEndpointNormalizer()
    assert normalizer.normalize_path("/api/v1/users/123/profile") == "/api/v1/users/{id}/profile"
    assert (
        normalizer.normalize_path("/orders/550e8400-e29b-41d4-a716-446655440000") == "/orders/{id}"
    )


def test_risk_correlation():
    engine = RiskCorrelationEngine()

    # Finding statico (Semgrep)
    static_finding = Finding.create(
        source=FindingSource.SEMGREP,
        category=FindingCategory.AUTHORIZATION,
        title="BOLA static risk",
        description="Static potential BOLA on users endpoint",
        severity=Severity.HIGH,
        confidence=0.7,
        rule_id="bola-route-static-check",
        target_identifier="/users/{id}",
        correlation_key="api:GET:/users/{id}",
    )

    # Finding runtime (active test finding)
    runtime_finding = Finding.create(
        source=FindingSource.RUNTIME_VALIDATOR,
        category=FindingCategory.AUTHORIZATION,
        title="BOLA validated at runtime",
        description="BOLA validated on users endpoint",
        severity=Severity.HIGH,
        confidence=1.0,
        rule_id="bola-exploit-confirmed",
        target_identifier="GET:/users/123",
        correlation_key="api:GET:/users/{id}",
    )

    correlated = engine.correlate([static_finding], [runtime_finding])

    # Dovrebbe esserci 1 finding correlato
    assert len(correlated) == 1
    corr_finding = correlated[0]

    # Riscontro empirico associato al finding
    assert corr_finding.runtime_evidence is not None
    # Severity elevata da HIGH a CRITICAL
    assert corr_finding.severity == Severity.CRITICAL
    assert corr_finding.confidence == 1.0


SRC_ROOT = Path(__file__).resolve().parents[2] / "src"
_OUTER_LAYERS = re.compile(
    r"^\s*(from|import)\s+src\.(infrastructure|presentation)\b", re.MULTILINE
)


@pytest.mark.parametrize("layer", ["domain", "application"])
def test_inner_layers_do_not_import_outer_layers(layer):
    """
    Regola di dipendenza della Clean Architecture: dominio e applicazione non conoscono
    infrastruttura e presentazione. Le realizzazioni concrete (adapter, provider LLM)
    arrivano dal composition root tramite le interfacce di dominio.
    """
    offenders = [
        str(path.relative_to(SRC_ROOT))
        for path in (SRC_ROOT / layer).rglob("*.py")
        if _OUTER_LAYERS.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == []
