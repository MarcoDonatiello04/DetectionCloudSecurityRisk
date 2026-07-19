import os

from src.domain.entities import FindingSource
from src.infrastructure.adapters.spectral_adapter import SpectralScannerAdapter


def test_spectral_scanner_adapter_execution():
    import json
    from unittest.mock import MagicMock, patch

    # Inizializza l'adapter
    adapter = SpectralScannerAdapter()

    # Verifica che il file del contratto OpenAPI di test esista
    target_openapi = "test_targets/bola/openapi.yaml"
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
