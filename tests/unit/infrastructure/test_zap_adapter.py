"""
Test unitari di ZapClientAdapter: mappatura del livello di confidenza degli alert.

Il demone ZAP è sostituito da un mock: non serve alcun servizio attivo.
"""

from unittest.mock import MagicMock

import pytest

from src.domain.entities import FindingSource
from src.infrastructure.adapters.zap_adapter import ZapClientAdapter

TARGET = "http://localhost:5000"


def _alert(name: str, confidence: str | None, risk: str = "High") -> dict:
    alert = {
        "id": "1",
        "pluginId": "40018",
        "alert": name,
        "description": "desc",
        "url": f"{TARGET}/users/1",
        "method": "GET",
        "param": "id",
        "evidence": "ev",
        "risk": risk,
    }
    if confidence is not None:
        alert["confidence"] = confidence
    return alert


def _adapter_with_alerts(alerts: list[dict]) -> ZapClientAdapter:
    adapter = ZapClientAdapter(zap_url="http://zap.invalid:8090")
    zap = MagicMock()
    zap.core.version = "2.14.0"
    zap.spider.scan.return_value = {"scan": "1"}
    zap.spider.status.return_value = "100"
    zap.core.alerts.return_value = alerts
    adapter.zap = zap
    return adapter


@pytest.mark.parametrize(
    ("level", "expected"),
    [
        ("User Confirmed", 1.0),
        ("High", 0.9),
        ("Medium", 0.7),
        ("Low", 0.5),
        # livello sconosciuto o assente: valore intermedio
        ("Weird", 0.7),
        (None, 0.7),
    ],
)
def test_zap_confidence_level_is_mapped(level, expected):
    findings = _adapter_with_alerts([_alert("SQL Injection", level)]).scan(TARGET)
    assert len(findings) == 1
    assert findings[0].source == FindingSource.ZAP_DAST
    assert findings[0].confidence == pytest.approx(expected)


def test_zap_false_positive_alerts_are_discarded():
    findings = _adapter_with_alerts(
        [
            _alert("SQL Injection", "False Positive"),
            _alert("Missing Header", "Medium", risk="Low"),
        ]
    ).scan(TARGET)
    assert [f.title for f in findings] == ["Missing Header"]
