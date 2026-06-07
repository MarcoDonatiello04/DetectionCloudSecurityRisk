"""
Test unitari per i modelli di dati della GUI.
Responsabilità:
- Validare l'integrazione tra le entità del dominio ed i modelli GUI.
- Validare l'aggregazione statistica di CloudRiskModel.
"""

from datetime import datetime
from src.domain.entities import Finding, Severity, FindingCategory, FindingSource, ValidationStatus, CodeLocation
from cloud_security_analyzer.models.finding_model import FindingModel
from cloud_security_analyzer.models.cloud_risk_model import CloudRiskModel
from cloud_security_analyzer.models.endpoint_model import EndpointModel

def test_finding_model_wrapper():
    """
    Verifica che il FindingModel esponga correttamente le proprietà formattate a partire dall'entità.
    """
    domain_f = Finding.create(
        source=FindingSource.CHECKOV,
        category=FindingCategory.STORAGE,
        title="S3 Bucket Pubblico Rilevato",
        description="Il bucket S3 consente accessi anonimi in lettura.",
        severity=Severity.HIGH,
        confidence=0.9,
        rule_id="CKV_AWS_21",
        target_identifier="my-bucket",
        location=CodeLocation(file_path="infra.tf", start_line=10, end_line=15),
        validation_status=ValidationStatus.CONFIRMED,
        raw_data={"correlated_risk_score": 8.5}
    )

    model = FindingModel(domain_f)
    assert model.id == domain_f.finding_id
    assert model.source == "CHECKOV"
    assert model.category == "STORAGE"
    assert model.title == "S3 Bucket Pubblico Rilevato"
    assert model.severity == "HIGH"
    assert model.confidence == 0.9
    assert model.is_confirmed is True
    assert model.file_path == "infra.tf"
    assert model.line_info == "L10-15"
    assert model.risk_score == 8.5

def test_cloud_risk_model_aggregation():
    """
    Verifica che le statistiche aggregate ed il punteggio complessivo siano calcolati in modo coerente.
    """
    domain_f1 = Finding.create(
        source=FindingSource.CHECKOV,
        category=FindingCategory.STORAGE,
        title="Vuln 1",
        description="Desc 1",
        severity=Severity.CRITICAL,
        confidence=0.8,
        rule_id="R1",
        target_identifier="T1",
        raw_data={"correlated_risk_score": 9.5}
    )

    domain_f2 = Finding.create(
        source=FindingSource.SEMGREP,
        category=FindingCategory.AUTHENTICATION,
        title="Vuln 2",
        description="Desc 2",
        severity=Severity.LOW,
        confidence=0.5,
        rule_id="R2",
        target_identifier="T2",
        raw_data={"correlated_risk_score": 2.5}
    )

    findings = [FindingModel(domain_f1), FindingModel(domain_f2)]
    
    # Crea un mock endpoint per le API
    endpoints = [
        EndpointModel({
            "method": "GET",
            "path": "/api/test",
            "documented": True,
            "shadow": False,
            "bola_status": "SAFE",
            "is_dynamic": True
        })
    ]

    risk_model = CloudRiskModel(findings, endpoints)

    assert risk_model.total_findings == 2
    assert risk_model.critical_count == 1
    assert risk_model.low_count == 1
    assert risk_model.high_count == 0
    assert risk_model.global_risk_score == 9.5
    assert risk_model.status_summary == "PERICOLO CRITICO"
