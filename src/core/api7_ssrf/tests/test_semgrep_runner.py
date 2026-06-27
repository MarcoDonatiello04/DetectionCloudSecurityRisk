import pytest
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock
from src.core.api7_ssrf.semgrep_runner import (
    SemgrepNotFoundError,
    SemgrepTimeoutError,
    SemgrepExecutionError,
    check_semgrep_available,
    run_semgrep
)

def test_semgrep_available():
    """Semgrep deve essere installato nell'ambiente."""
    version = check_semgrep_available()
    assert version  # non vuoto

def test_run_semgrep_on_vulnerable_fixture():
    """Semgrep deve trovare findings sulla fixture vulnerabile."""
    rules_path = Path(__file__).parent.parent / "rules" / "semgrep_rules.yml"
    fixture_path = Path(__file__).parent.parent / "fixtures" / "vulnerable_app"
    output = run_semgrep(str(fixture_path), str(rules_path))
    assert len(output.get("results", [])) > 0

def test_run_semgrep_on_secure_fixture():
    """Semgrep non deve trovare findings sulla fixture sicura."""
    rules_path = Path(__file__).parent.parent / "rules" / "semgrep_rules.yml"
    fixture_path = Path(__file__).parent.parent / "fixtures" / "secure_app"
    output = run_semgrep(str(fixture_path), str(rules_path))
    assert len(output.get("results", [])) == 0

def test_semgrep_timeout():
    """SemgrepTimeoutError su timeout molto basso."""
    rules_path = Path(__file__).parent.parent / "rules" / "semgrep_rules.yml"
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
