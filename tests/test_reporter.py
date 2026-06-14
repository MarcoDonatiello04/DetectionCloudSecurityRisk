import pytest
import json
from pathlib import Path
from src.core.broken_authentication.reporter import (
    ReportFinale, VulnerabilitaStatica, RisultatoTestDinamico, generate_markdown, run
)
from src.core.broken_authentication.discovery import StackInfo, Config

# --- Test Data Fixture ---
def get_dummy_report() -> ReportFinale:
    stack = StackInfo(
        linguaggio="Python",
        framework="FastAPI",
        librerie_auth=["jose", "pyjwt"],
        identity_provider="Auth0",
        file_configurazione_rilevanti=["requirements.txt", ".env.example"]
    )
    
    vulns = [
        VulnerabilitaStatica(
            file="auth.py",
            riga=45,
            vulnerabilita="JWT None Algorithm Allowed",
            severita="CRITICAL",
            cwe="CWE-345",
            raccomandazione="Inforce signature validation"
        ),
        VulnerabilitaStatica(
            file="db.py",
            riga=12,
            vulnerabilita="Hardcoded credentials",
            severita="HIGH",
            cwe="CWE-798",
            raccomandazione="Use environment variables"
        )
    ]
    
    tests = [
        RisultatoTestDinamico(
            test_id="T01",
            test_nome="JWT Manipulation",
            risultato="FAIL",
            dettaglio="None algorithm was accepted",
            raccomandazione="Update JWT library config"
        ),
        RisultatoTestDinamico(
            test_id="T02",
            test_nome="Expired Token",
            risultato="PASS",
            dettaglio="Expired token was rejected",
            raccomandazione="Keep configuration as is"
        ),
        RisultatoTestDinamico(
            test_id="T03",
            test_nome="Brute Force",
            risultato="SKIP",
            dettaglio="Endpoint login not found",
            raccomandazione="Double check fallback config"
        )
    ]
    
    return ReportFinale(
        timestamp="2026-06-15 00:30:00",
        repository="my-security-repo",
        stack=stack,
        vulnerabilita_statiche=vulns,
        test_dinamici=tests
    )

# --- Test Cases ---

def test_generate_markdown():
    report = get_dummy_report()
    md = generate_markdown(report)
    
    assert "# Broken Authentication Report" in md
    assert "Data: 2026-06-15 00:30:00" in md
    assert "Repository: my-security-repo" in md
    
    assert "Linguaggio: Python" in md
    assert "Framework: FastAPI" in md
    assert "Librerie Auth: jose, pyjwt" in md
    assert "Identity Provider: Auth0" in md
    
    assert "Vulnerabilità CRITICAL: 1" in md
    assert "Vulnerabilità HIGH: 1" in md
    assert "Vulnerabilità MEDIUM: 0" in md
    assert "Vulnerabilità LOW: 0" in md
    assert "Test PASS: 1" in md
    assert "Test FAIL: 1" in md
    assert "Test SKIP: 1" in md
    
    assert "### CRITICAL - CWE-345" in md
    assert "- File: auth.py (riga 45)" in md
    assert "- Descrizione: JWT None Algorithm Allowed" in md
    
    assert "### T01 - JWT Manipulation: FAIL" in md
    assert "- Dettaglio: None algorithm was accepted" in md

@pytest.mark.asyncio
async def test_run_both(tmp_path):
    config = Config()
    config.output.path = str(tmp_path)
    config.output.formato = "both"
    
    report = get_dummy_report()
    
    await run(report, config)
    
    # Check both files exist
    safe_ts = report.timestamp.replace(":", "-").replace(" ", "_")
    json_file = tmp_path / f"report_{safe_ts}.json"
    md_file = tmp_path / f"report_{safe_ts}.md"
    
    assert json_file.is_file()
    assert md_file.is_file()
    
    # Verify JSON content is a direct dump
    json_data = json.loads(json_file.read_text(encoding="utf-8"))
    assert json_data["timestamp"] == report.timestamp
    assert json_data["repository"] == report.repository
    assert json_data["stack"]["linguaggio"] == "Python"
    
    # Verify MD content
    md_content = md_file.read_text(encoding="utf-8")
    assert "# Broken Authentication Report" in md_content

@pytest.mark.asyncio
async def test_run_json_only(tmp_path):
    config = Config()
    config.output.path = str(tmp_path)
    config.output.formato = "json"
    
    report = get_dummy_report()
    await run(report, config)
    
    safe_ts = report.timestamp.replace(":", "-").replace(" ", "_")
    json_file = tmp_path / f"report_{safe_ts}.json"
    md_file = tmp_path / f"report_{safe_ts}.md"
    
    assert json_file.is_file()
    assert not md_file.is_file()

@pytest.mark.asyncio
async def test_run_markdown_only(tmp_path):
    config = Config()
    config.output.path = str(tmp_path)
    config.output.formato = "markdown"
    
    report = get_dummy_report()
    await run(report, config)
    
    safe_ts = report.timestamp.replace(":", "-").replace(" ", "_")
    json_file = tmp_path / f"report_{safe_ts}.json"
    md_file = tmp_path / f"report_{safe_ts}.md"
    
    assert not json_file.is_file()
    assert md_file.is_file()

@pytest.mark.asyncio
async def test_run_folder_creation(tmp_path):
    # Specify nested directory that does not exist
    nested_dir = tmp_path / "nested" / "output"
    
    config = Config()
    config.output.path = str(nested_dir)
    config.output.formato = "json"
    
    report = get_dummy_report()
    await run(report, config)
    
    safe_ts = report.timestamp.replace(":", "-").replace(" ", "_")
    json_file = nested_dir / f"report_{safe_ts}.json"
    
    assert nested_dir.is_dir()
    assert json_file.is_file()
