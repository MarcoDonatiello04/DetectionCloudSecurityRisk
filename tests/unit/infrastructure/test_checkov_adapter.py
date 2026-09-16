"""
Test unitari di CheckovScannerAdapter: perimetro della scansione e traduzione dei controlli.

Il perimetro deve essere sempre il target_dir passato a scan(): il file .checkov.yaml
della piattaforma, se presente, governa solo le opzioni accessorie.
"""

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from src.core.config import DEFAULT_CHECKOV_CONFIG
from src.domain.entities import FindingCategory, FindingNature, FindingSource, Severity
from src.infrastructure.adapters.checkov_adapter import CheckovScannerAdapter

TARGET = "data/test_targets/repo_target/terraform"


def _exists_factory(config_present: bool):
    """Simula os.path.exists lasciando decidere solo la presenza del file di configurazione."""
    real_exists = os.path.exists

    def fake_exists(path):
        if path == DEFAULT_CHECKOV_CONFIG:
            return config_present
        return real_exists(path)

    return fake_exists


def _flag_value(cmd: list[str], flag: str) -> str:
    assert flag in cmd, f"{flag} assente dal comando: {cmd}"
    return cmd[cmd.index(flag) + 1]


def test_build_command_always_targets_the_requested_directory(monkeypatch):
    monkeypatch.setattr(os.path, "exists", _exists_factory(config_present=True))
    cmd = CheckovScannerAdapter._build_command(TARGET)
    assert _flag_value(cmd, "-d") == TARGET
    assert _flag_value(cmd, "-o") == "json"


def test_build_command_adds_config_file_only_as_extra_options(monkeypatch):
    monkeypatch.setattr(os.path, "exists", _exists_factory(config_present=True))
    cmd = CheckovScannerAdapter._build_command(TARGET)
    assert _flag_value(cmd, "--config-file") == DEFAULT_CHECKOV_CONFIG
    # Il file non sostituisce mai il perimetro: -d resta presente insieme al config.
    assert _flag_value(cmd, "-d") == TARGET


def test_build_command_omits_config_file_when_missing(monkeypatch):
    monkeypatch.setattr(os.path, "exists", _exists_factory(config_present=False))
    cmd = CheckovScannerAdapter._build_command(TARGET)
    assert "--config-file" not in cmd
    assert _flag_value(cmd, "-d") == TARGET


def test_build_command_keeps_target_outside_the_project(monkeypatch, tmp_path):
    monkeypatch.setattr(os.path, "exists", _exists_factory(config_present=True))
    external = str(tmp_path / "infra")
    cmd = CheckovScannerAdapter._build_command(external)
    assert _flag_value(cmd, "-d") == external


def test_platform_config_does_not_define_the_scan_perimeter():
    """Il file .checkov.yaml non deve contenere chiavi che allarghino il perimetro."""
    import yaml

    if not os.path.exists(DEFAULT_CHECKOV_CONFIG):
        pytest.skip("file di configurazione Checkov assente")
    with open(DEFAULT_CHECKOV_CONFIG, encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}
    assert "directory" not in config
    assert "file" not in config
    # Nessuna esclusione generica che possa escludere i sorgenti dei bersagli.
    for generic in ("src", "tests", "output", "reports", "remediation"):
        assert generic not in config.get("skip-path", [])


def test_scan_invokes_checkov_with_target_and_parses_failed_checks(monkeypatch):
    monkeypatch.setattr(os.path, "exists", _exists_factory(config_present=True))
    payload = {
        "check_type": "terraform",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_20",
                    "check_name": "S3 Bucket has an ACL defined which allows public READ access.",
                    "resource": "aws_s3_bucket.public_data",
                    "file_path": "/vulnerable_infra.tf",
                    "file_line_range": [10, 20],
                }
            ]
        },
    }
    captured: dict = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return MagicMock(returncode=1, stdout=json.dumps(payload))

    with patch("subprocess.run", side_effect=fake_run):
        findings = CheckovScannerAdapter().scan(TARGET)

    assert _flag_value(captured["cmd"], "-d") == TARGET
    assert len(findings) == 1
    assert findings[0].rule_id == "CKV_AWS_20"


def test_build_finding_behaviour_is_unchanged():
    finding = CheckovScannerAdapter().build_finding(
        {
            "check_id": "CKV_AWS_20",
            "check_name": "S3 Bucket has an ACL defined which allows public READ access.",
            "resource": "aws_s3_bucket.public_data",
            "file_path": "/vulnerable_infra.tf",
            "file_line_range": [10, 20],
        }
    )
    assert finding.source == FindingSource.CHECKOV
    assert finding.category == FindingCategory.STORAGE
    assert finding.nature == FindingNature.EXPOSURE
    assert finding.severity == Severity.CRITICAL
    assert finding.rule_id == "CKV_AWS_20"
    assert finding.resource_type == "aws_s3_bucket"
    assert finding.resource_name == "public_data"
    assert finding.correlation_key == "public_data"
    # L'identificativo deterministico dipende da (source, rule_id, resource:file_path)
    assert finding.finding_id == finding.generate_deterministic_id(
        FindingSource.CHECKOV, "CKV_AWS_20", "aws_s3_bucket.public_data:/vulnerable_infra.tf"
    )
    assert finding.location.start_line == 10
    assert finding.location.end_line == 20
    assert finding.risk_context is not None
    assert finding.risk_context.internet_exposed is True
    assert finding.risk_context.public_resource is True


def test_build_finding_hardening_check_has_no_public_context():
    finding = CheckovScannerAdapter().build_finding(
        {
            "check_id": "CKV_AWS_18",
            "check_name": "Ensure the S3 bucket has access logging enabled",
            "resource": "aws_s3_bucket.public_data",
            "file_path": "/vulnerable_infra.tf",
            "file_line_range": [10, 20],
        }
    )
    assert finding.nature == FindingNature.HARDENING
    assert finding.severity == Severity.LOW
    assert finding.category == FindingCategory.STORAGE
    assert finding.risk_context is None
