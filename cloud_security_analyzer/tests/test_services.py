"""
Test unitari per i servizi applicativi della GUI.
Responsabilità:
- Validare la gestione dei filtri in StateService.
- Validare la verifica dei file in ScanService.
"""

import os
import json
import pytest
from cloud_security_analyzer.services.state_service import StateService
from cloud_security_analyzer.services.scan_service import ScanService

def test_state_service_filter_toggling():
    """
    Verifica che lo StateService gestisca correttamente l'attivazione/disattivazione dei filtri.
    """
    state = StateService()
    
    # All'inizio nessun filtro attivo
    assert len(state.selected_severities) == 0
    assert state.search_query == ""

    # Attiva severità HIGH
    state.toggle_severity_filter("HIGH")
    assert "HIGH" in state.selected_severities
    
    # Disattiva severità HIGH
    state.toggle_severity_filter("HIGH")
    assert "HIGH" not in state.selected_severities

    # Imposta query
    state.set_search_query("test-query")
    assert state.search_query == "test-query"

    # Azzera filtri
    state.clear_all_filters()
    assert len(state.selected_severities) == 0
    assert state.search_query == ""

def test_scan_service_missing_files():
    """
    Verifica che il servizio fallisca la convalida se i file JSON non esistono.
    """
    scan_service = ScanService("/non/existent/path")
    exists, err_msg = scan_service.verify_files_exist()
    
    assert exists is False
    assert "non esiste" in err_msg

def test_scan_service_historical_scans(tmp_path):
    """
    Verifica che il list_historical_scans trovi e decodifichi i file nella cartella reports.
    """
    # Crea un ambiente fittizio
    default_dir = tmp_path / "output"
    default_dir.mkdir()
    
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    
    # Scrive un file di report fittizio con timestamp corretto
    report_file = reports_dir / "unified_report_20260606_120000.json"
    findings_data = [
        {
            "finding_id": "checkov-123",
            "source": "CHECKOV",
            "severity": "CRITICAL",
            "confidence": 1.0,
            "category": "IAM",
            "title": "Vulnerability"
        }
    ]
    with open(report_file, "w") as f:
        json.dump(findings_data, f)
        
    scan_service = ScanService(str(default_dir))
    scans = scan_service.list_historical_scans()
    
    assert len(scans) == 1
    assert scans[0]["total_findings"] == 1
    assert scans[0]["risk_score"] == 9.0
    assert "2026-06-06 12:00:00" in scans[0]["date_str"]
