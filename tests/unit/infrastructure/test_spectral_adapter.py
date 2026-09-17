import os

from src.domain.entities import FindingSource
from src.infrastructure.adapters.spectral_adapter import SpectralScannerAdapter


def test_spectral_scanner_adapter_execution():
    import json
    from unittest.mock import MagicMock, patch

    # Inizializza l'adapter
    adapter = SpectralScannerAdapter()

    # Verifica che il file del contratto OpenAPI di test esista
    target_openapi = "data/test_targets/bola/openapi.yaml"
    assert os.path.exists(target_openapi), "Il file openapi.yaml di test non esiste"

    mock_data = [
        {
            "code": "owasp:api3:2019-no-numeric-ids",
            "message": "Use uuids instead of numeric ids",
            "severity": 1,
            "source": target_openapi,
            "range": {"start": {"line": 10}},
            "path": ["paths", "/users/{id}", "get"],
        },
        {
            "code": "owasp:api3:2019-no-numeric-ids",
            "message": "Use uuids instead of numeric ids",
            "severity": 0,
            "source": target_openapi,
            "range": {"start": {"line": 20}},
            "path": ["info", "version"],
        },
    ]

    def mock_subprocess_run(cmd, **kwargs):
        report_file = "spectral_report_temp.json"
        if "-o" in cmd:
            idx = cmd.index("-o")
            report_file = cmd[idx + 1]
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(mock_data, f)
        return MagicMock(returncode=0)

    # Esegue lo scan con il mock di subprocess.run
    with patch("subprocess.run", side_effect=mock_subprocess_run):
        findings = adapter.scan(target_openapi)

    # Verifica che la scansione abbia prodotto findings e che siano di tipo SPECTRAL
    assert len(findings) > 0, "Spectral non ha prodotto alcuna segnalazione"

    has_route_specific = False
    has_global = False

    for finding in findings:
        assert finding.source == FindingSource.SPECTRAL
        assert finding.rule_id is not None
        assert finding.description is not None
        # Verifica che il file di origine sia corretto
        assert finding.location is not None
        assert finding.correlation_key is not None
        assert target_openapi in finding.location.file_path

        if finding.api is not None:
            has_route_specific = True
            # Verifica che inizi con spectral:
            assert finding.correlation_key.startswith("spectral:"), (
                f"Atteso correlation_key spectral:*, trovato {finding.correlation_key}"
            )
        else:
            has_global = True
            # Dovrebbe iniziare con openapi: per evitare fusioni totali
            assert finding.correlation_key.startswith("openapi:"), (
                f"Atteso correlation_key openapi:*, trovato {finding.correlation_key}"
            )

    assert has_route_specific, "Dovrebbero esserci violazioni specifiche per le rotte"
    assert has_global, "Dovrebbero esserci violazioni globali del contratto"


def _scan_with_issues(tmp_path, issues):
    import json
    from unittest.mock import MagicMock, patch

    spec = tmp_path / "openapi.yaml"
    spec.write_text(
        "openapi: 3.0.0\ninfo: {title: t, version: '1'}\npaths:\n  /users/{id}:\n    get: {}\n",
        encoding="utf-8",
    )
    for issue in issues:
        issue.setdefault("source", str(spec))
        issue.setdefault("range", {"start": {"line": 5}})

    def fake_run(cmd, **kwargs):
        with open(cmd[cmd.index("-o") + 1], "w", encoding="utf-8") as f:
            json.dump(issues, f)
        return MagicMock(returncode=0)

    with patch("subprocess.run", side_effect=fake_run):
        return SpectralScannerAdapter().scan(str(spec))


def test_api1_rule_maps_to_authorization_with_endpoint_correlation_key(tmp_path):
    from src.domain.entities import FindingCategory, Severity

    findings = _scan_with_issues(
        tmp_path,
        [
            {
                "code": "owasp-api1-object-level-security",
                "message": "Operation must define security",
                "severity": 0,
                "path": ["paths", "/users/{id}", "get"],
            },
            {
                "code": "owasp-api2-operation-security",
                "message": "Operation must define security",
                "severity": 0,
                "path": ["paths", "/users/{id}", "get"],
            },
        ],
    )
    by_rule = {f.rule_id: f for f in findings}

    api1 = by_rule["owasp-api1-object-level-security"]
    assert api1.category == FindingCategory.AUTHORIZATION
    assert api1.severity == Severity.HIGH
    assert api1.risk_context is not None and api1.risk_context.internet_exposed is True
    # Chiave della risorsa, condivisa con Semgrep e con il validatore runtime BOLA
    assert api1.correlation_key == "api:GET:/users/{id}"
    # Le altre regole mantengono la chiave per-regola (nessuna fusione tra violazioni diverse)
    assert by_rule["owasp-api2-operation-security"].correlation_key.startswith("spectral:")


def test_runtime_bola_confirmation_elevates_static_api1_finding(tmp_path):
    from src.application.correlation.engine import RiskCorrelationEngine
    from src.domain.entities import (
        APIContext,
        Finding,
        FindingCategory,
        FindingSource,
        RuntimeEvidence,
        Severity,
    )

    static = _scan_with_issues(
        tmp_path,
        [
            {
                "code": "owasp-api1-object-level-security",
                "message": "Operation must define security",
                "severity": 0,
                "path": ["paths", "/users/{id}", "get"],
            }
        ],
    )
    runtime = Finding.create(
        source=FindingSource.RUNTIME_VALIDATOR,
        category=FindingCategory.AUTHORIZATION,
        title="Vulnerabilità BOLA Orizzontale confermata a runtime",
        description="",
        severity=Severity.HIGH,
        confidence=1.0,
        rule_id="dynamic-bola-exploited",
        target_identifier="GET:/users/42:BOLA",
        api=APIContext(endpoint="/users/42", method="GET"),
        runtime_evidence=RuntimeEvidence(tested_url="http://t/users/42", http_status=200),
        correlation_key="api:GET:/users/{id}",
    )

    correlated = RiskCorrelationEngine().correlate(static, [runtime])

    assert len(correlated) == 1
    elevated = correlated[0]
    assert elevated.rule_id == "owasp-api1-object-level-security"
    assert elevated.severity == Severity.CRITICAL
    assert elevated.runtime_evidence is not None
    assert runtime.finding_id in elevated.related_findings
