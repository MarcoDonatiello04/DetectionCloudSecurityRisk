import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.core.api8_ssrf.semgrep_runner import (
    SemgrepExecutionError,
    SemgrepTimeoutError,
    check_semgrep_available,
    run_semgrep,
)


def test_semgrep_available():
    """Semgrep deve essere installato nell'ambiente."""
    version = check_semgrep_available()
    assert version  # non vuoto


PROJECT_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists())
SSRF_DIR = PROJECT_ROOT / "src" / "core" / "api8_ssrf"


def test_run_semgrep_on_vulnerable_fixture():
    """Semgrep deve trovare findings sulla fixture vulnerabile."""
    rules_path = SSRF_DIR / "rules" / "semgrep_rules.yml"
    fixture_path = SSRF_DIR / "fixtures" / "vulnerable_app"
    output = run_semgrep(str(fixture_path), str(rules_path))
    assert len(output.get("results", [])) > 0


def test_run_semgrep_on_secure_fixture():
    """Semgrep non deve trovare findings sulla fixture sicura."""
    rules_path = SSRF_DIR / "rules" / "semgrep_rules.yml"
    fixture_path = SSRF_DIR / "fixtures" / "secure_app"
    output = run_semgrep(str(fixture_path), str(rules_path))
    assert len(output.get("results", [])) == 0


def test_semgrep_timeout():
    """SemgrepTimeoutError su timeout molto basso."""
    rules_path = SSRF_DIR / "rules" / "semgrep_rules.yml"
    with pytest.raises(SemgrepTimeoutError):
        run_semgrep(".", str(rules_path), timeout=0)


# Offline / Mock-based unit tests to guarantee safety across different envs


@patch("subprocess.run")
def test_run_semgrep_success(mock_run):
    mock_res = MagicMock()
    mock_res.returncode = 0
    mock_res.stdout = '{"results": []}'
    mock_run.return_value = mock_res

    res = run_semgrep("target_dir", "rules_path.yml")
    assert res == {"results": []}


@patch("subprocess.run")
def test_run_semgrep_timeout_mock(mock_run):
    mock_run.side_effect = subprocess.TimeoutExpired(cmd=["semgrep"], timeout=10)

    with pytest.raises(SemgrepTimeoutError):
        run_semgrep("target_dir", "rules_path.yml", timeout=10)


@patch("subprocess.run")
def test_run_semgrep_failure_mock(mock_run):
    mock_res = MagicMock()
    mock_res.returncode = 2
    mock_res.stdout = "Invalid JSON"
    mock_res.stderr = "Fatal error"
    mock_run.return_value = mock_res

    with pytest.raises(SemgrepExecutionError):
        run_semgrep("target_dir", "rules_path.yml")
