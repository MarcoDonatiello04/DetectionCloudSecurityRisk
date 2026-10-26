"""
Api3BoplaDetector: the BOPLA report translated into domain Findings (IVulnerabilityDetector).
"""

import json
from pathlib import Path
from unittest.mock import patch

from src.core.api3_bopla.detector import Api3BoplaDetector
from src.domain.entities import Finding, FindingSource, ScanTarget, Severity
from tests.integration.api3_bopla.test_bopla_ground_truth import (
    HEADERS_MATRIX,
    TWINS_DIR,
    _load_app,
    _route_to,
)


def _target(variant: str, tmp_path: Path, **options) -> ScanTarget:
    return ScanTarget(
        target_path=str(TWINS_DIR / variant),
        openapi_spec=json.loads((TWINS_DIR / "openapi.json").read_text()),
        options={
            "output_path": str(tmp_path),
            "runtime_traffic": json.loads((TWINS_DIR / "client_traffic.json").read_text()),
            **options,
        },
    )


def test_static_findings_become_domain_findings(tmp_path: Path):
    findings = Api3BoplaDetector().analyze(_target("vulnerable_app", tmp_path))
    assert findings and all(isinstance(f, Finding) for f in findings)
    by_rule = {f.rule_id: f for f in findings}
    assert set(by_rule) == {"BOPLA-S01", "BOPLA-S02", "BOPLA-S04"}
    s01 = by_rule["BOPLA-S01"]
    assert s01.source == FindingSource.STATIC_ANALYZER
    assert s01.cwe_id == "CWE-915" and s01.owasp_api_category == "API3:2023"
    assert s01.location.file_path == "app.py" and s01.location.start_line == 92
    assert "da verificare" in s01.tags
    assert by_rule["BOPLA-S02"].cwe_id == "CWE-213"


def test_secure_twin_only_documentation_finding(tmp_path: Path):
    findings = Api3BoplaDetector().analyze(_target("secure_app", tmp_path))
    assert [f.rule_id for f in findings] == ["BOPLA-S04"]
    assert findings[0].severity == Severity.LOW


def test_dynamic_phase_adds_confirmed_tests(tmp_path: Path):
    app = _load_app("vulnerable_app")
    target = _target("vulnerable_app", tmp_path, headers_matrix=HEADERS_MATRIX)
    with patch("requests.request", side_effect=_route_to(app)):
        findings = Api3BoplaDetector().analyze(target)
    dynamic = [f for f in findings if f.source == FindingSource.RUNTIME_VALIDATOR]
    static = [f for f in findings if f.source == FindingSource.STATIC_ANALYZER]
    assert {f.rule_id for f in dynamic} >= {"BOPLA-T01", "BOPLA-T03"}
    assert all(f.correlation_key and f.correlation_key.startswith("api:") for f in dynamic)
    confirmed = [f for f in static if f.rule_id in {"BOPLA-S01", "BOPLA-S02"}]
    assert all(f.severity == Severity.CRITICAL for f in confirmed)
    assert all("confermata dinamicamente" in f.tags for f in confirmed)
