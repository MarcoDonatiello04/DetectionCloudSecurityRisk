"""
Test della distinzione fra esposizione e irrobustimento (FindingNature, ADR-004).

Copre i quattro livelli della soluzione:
- catalogo semantico delle policy Checkov (classificazione per ID, prefisso, parole chiave);
- adapter Checkov (natura, severità e contesto di rischio sul Finding);
- motore di correlazione (la voce rappresentativa di una risorsa è l'esposizione, non il
  primo controllo incontrato; l'hardening resta come sotto-elemento informativo);
- risk scoring (nessun bonus di contesto per l'hardening).
"""

import pytest

from src.application.correlation.engine import RiskCorrelationEngine
from src.domain.entities import (
    Finding,
    FindingCategory,
    FindingNature,
    FindingSource,
    RiskContext,
    Severity,
)
from src.infrastructure.adapters.checkov_adapter import CheckovScannerAdapter
from src.infrastructure.adapters.checkov_policy_catalog import CheckovPolicyCatalog

# ─── Helper ──────────────────────────────────────────────────────────────────


def _checkov_finding(
    check_id: str,
    title: str,
    severity: Severity,
    nature: FindingNature | None,
    resource: str = "aws_s3_bucket.bucket_1_public_acl",
    risk_context: RiskContext | None = None,
) -> Finding:
    corr_key = resource.split(".")[-1]
    return Finding.create(
        source=FindingSource.CHECKOV,
        category=FindingCategory.STORAGE,
        title=title,
        description=f"{title} per la risorsa {resource}",
        severity=severity,
        confidence=1.0,
        rule_id=check_id,
        target_identifier=f"{resource}:main.tf",
        resource_id=resource,
        correlation_key=corr_key,
        nature=nature,
        risk_context=risk_context,
    )


def _raw_check(check_id: str, check_name: str, resource: str) -> dict:
    return {
        "check_id": check_id,
        "check_name": check_name,
        "resource": resource,
        "file_path": "/terraform/main.tf",
        "file_line_range": [23, 26],
    }


@pytest.fixture(scope="module")
def catalog() -> CheckovPolicyCatalog:
    cat = CheckovPolicyCatalog()
    assert cat.loaded, "Il catalogo di default deve essere caricato dal file YAML del progetto"
    return cat


# ─── Catalogo semantico ──────────────────────────────────────────────────────


def test_catalog_explicit_exposure_policy(catalog):
    result = catalog.classify(
        "CKV_AWS_20", "S3 Bucket has an ACL defined which allows public READ access."
    )
    assert result.nature == FindingNature.EXPOSURE
    assert result.severity == Severity.CRITICAL
    assert result.public_facing is True
    assert result.matched_by == "policy"


def test_catalog_explicit_hardening_policy(catalog):
    result = catalog.classify(
        "CKV2_AWS_62", "Ensure S3 buckets should have event notifications enabled"
    )
    assert result.nature == FindingNature.HARDENING
    assert result.severity == Severity.LOW
    assert result.public_facing is False


def test_catalog_prefix_rule_for_secrets(catalog):
    result = catalog.classify("CKV_SECRET_999", "Some new secret detector")
    assert result.nature == FindingNature.EXPOSURE
    assert result.matched_by == "prefix"


def test_catalog_keywords_operate_on_official_name_not_on_id(catalog):
    # L'ID è opaco: la classificazione deve avvenire sul nome ufficiale del controllo.
    result = catalog.classify("CKV_AWS_99999", "Ensure the widget does not allow public access")
    assert result.nature == FindingNature.EXPOSURE
    assert result.public_facing is True
    assert result.matched_by == "keyword"


def test_catalog_defensive_terms_win_over_exposure_terms(catalog):
    # "secret" è un termine di esposizione, ma "encrypted"/"KMS" indicano un controllo difensivo.
    result = catalog.classify(
        "CKV_AWS_99998", "Ensure that Secrets Manager secret is encrypted using KMS CMK"
    )
    assert result.nature == FindingNature.HARDENING
    assert result.severity == Severity.MEDIUM


def test_catalog_hygiene_terms_are_low_hardening(catalog):
    result = catalog.classify("CKV_AWS_99997", "Ensure the thing has access logging enabled")
    assert result.nature == FindingNature.HARDENING
    assert result.severity == Severity.LOW


def test_catalog_unknown_check_stays_unclassified_medium(catalog):
    result = catalog.classify("CKV_AWS_99996", "Ensure the frobnicator is configured")
    assert result.nature is None
    assert result.severity == Severity.MEDIUM
    assert result.matched_by == "default"


def test_catalog_missing_file_degrades_to_legacy_behaviour(tmp_path):
    cat = CheckovPolicyCatalog(catalog_path=str(tmp_path / "missing.yaml"))
    assert cat.loaded is False
    result = cat.classify(
        "CKV_AWS_20", "S3 Bucket has an ACL defined which allows public READ access."
    )
    assert result.nature is None
    assert result.severity == Severity.MEDIUM


# ─── Adapter Checkov ─────────────────────────────────────────────────────────


def test_adapter_public_acl_is_critical_exposure_with_public_context():
    adapter = CheckovScannerAdapter()
    finding = adapter.build_finding(
        _raw_check(
            "CKV_AWS_20",
            "S3 Bucket has an ACL defined which allows public READ access.",
            "aws_s3_bucket.bucket_1_public_acl",
        )
    )
    assert finding.severity == Severity.CRITICAL
    assert finding.nature == FindingNature.EXPOSURE
    assert finding.is_directly_exploitable is True
    assert finding.category == FindingCategory.STORAGE
    assert finding.risk_context is not None
    assert finding.risk_context.internet_exposed is True
    assert finding.risk_context.public_resource is True
    assert finding.correlation_key == "bucket_1_public_acl"
    assert finding.resource_type == "aws_s3_bucket"
    assert finding.location is not None
    assert finding.location.start_line == 23
    assert finding.to_dict()["nature"] == "EXPOSURE"


def test_adapter_missing_notifications_is_low_hardening_without_context():
    adapter = CheckovScannerAdapter()
    finding = adapter.build_finding(
        _raw_check(
            "CKV2_AWS_62",
            "Ensure S3 buckets should have event notifications enabled",
            "aws_s3_bucket.bucket_5_impenetrable",
        )
    )
    assert finding.severity == Severity.LOW
    assert finding.nature == FindingNature.HARDENING
    assert finding.is_directly_exploitable is False
    assert finding.risk_context is None


def test_adapter_iam_wildcard_policy_is_critical_exposure():
    adapter = CheckovScannerAdapter()
    finding = adapter.build_finding(
        _raw_check(
            "CKV_AWS_62",
            'Ensure IAM policies that allow full "*-*" administrative privileges are not created',
            "aws_iam_role_policy.vulnerable_lambda_policy",
        )
    )
    assert finding.category == FindingCategory.IAM
    assert finding.severity == Severity.CRITICAL
    assert finding.nature == FindingNature.EXPOSURE


# ─── Motore di correlazione ──────────────────────────────────────────────────


def test_exposure_becomes_representative_even_if_encountered_last():
    engine = RiskCorrelationEngine()
    notifications = _checkov_finding(
        "CKV2_AWS_62",
        "Ensure S3 buckets should have event notifications enabled",
        Severity.LOW,
        FindingNature.HARDENING,
    )
    lifecycle = _checkov_finding(
        "CKV2_AWS_61",
        "Ensure that an S3 bucket has a lifecycle configuration",
        Severity.LOW,
        FindingNature.HARDENING,
    )
    public_acl = _checkov_finding(
        "CKV_AWS_20",
        "S3 Bucket has an ACL defined which allows public READ access.",
        Severity.CRITICAL,
        FindingNature.EXPOSURE,
        risk_context=RiskContext(internet_exposed=True, public_resource=True),
    )

    # Ordine di Checkov: le notifiche arrivano prima dell'ACL pubblica
    correlated = engine.correlate([notifications, lifecycle, public_acl], [])

    assert len(correlated) == 1
    representative = correlated[0]
    assert representative.rule_id == "CKV_AWS_20"
    assert representative.title.startswith("S3 Bucket has an ACL")
    assert representative.severity == Severity.CRITICAL
    assert representative.nature == FindingNature.EXPOSURE

    # I controlli di hardening restano collegati come sotto-elementi informativi
    assert set(representative.related_findings) == {
        notifications.finding_id,
        lifecycle.finding_id,
    }
    aggregated = representative.raw_data["aggregated_checks"]
    assert {c["rule_id"] for c in aggregated} == {"CKV2_AWS_62", "CKV2_AWS_61"}
    assert all(c["nature"] == "HARDENING" for c in aggregated)
    assert representative.finding_id not in {c["finding_id"] for c in aggregated}


def test_hardening_never_inflates_exposure_severity():
    engine = RiskCorrelationEngine()
    exposure = _checkov_finding(
        "CKV_AWS_59",
        "Ensure there is no open access to back-end resources through API",
        Severity.HIGH,
        FindingNature.EXPOSURE,
        resource="aws_api_gateway_method.vulnerable_method",
    )
    hardening = _checkov_finding(
        "CKV_AWS_XYZ",
        "Some hardening control with high severity",
        Severity.CRITICAL,
        FindingNature.HARDENING,
        resource="aws_api_gateway_method.vulnerable_method",
    )

    correlated = engine.correlate([exposure, hardening], [])

    assert len(correlated) == 1
    assert correlated[0].rule_id == "CKV_AWS_59"
    assert correlated[0].severity == Severity.HIGH


def test_same_nature_ties_keep_first_encountered():
    engine = RiskCorrelationEngine()
    first = _checkov_finding("CKV_A", "First", Severity.HIGH, FindingNature.EXPOSURE)
    second = _checkov_finding("CKV_B", "Second", Severity.HIGH, FindingNature.EXPOSURE)

    correlated = engine.correlate([first, second], [])

    assert len(correlated) == 1
    assert correlated[0].rule_id == "CKV_A"
    assert correlated[0].severity == Severity.HIGH


def test_same_nature_prefers_higher_severity():
    engine = RiskCorrelationEngine()
    first = _checkov_finding("CKV_A", "First", Severity.HIGH, FindingNature.EXPOSURE)
    second = _checkov_finding("CKV_B", "Second", Severity.HIGH, FindingNature.EXPOSURE)
    third = _checkov_finding("CKV_C", "Third", Severity.CRITICAL, FindingNature.EXPOSURE)

    correlated = engine.correlate([first, second, third], [])

    assert len(correlated) == 1
    assert correlated[0].rule_id == "CKV_C"
    assert correlated[0].severity == Severity.CRITICAL
    # I riferimenti già aggregati dalla voce precedente vengono ereditati
    assert set(correlated[0].related_findings) == {first.finding_id, second.finding_id}
    assert {c["rule_id"] for c in correlated[0].raw_data["aggregated_checks"]} == {
        "CKV_A",
        "CKV_B",
    }


def test_unclassified_findings_keep_legacy_merge_behaviour():
    engine = RiskCorrelationEngine()
    first = _checkov_finding("CKV_A", "First", Severity.MEDIUM, None)
    second = _checkov_finding("CKV_B", "Second", Severity.MEDIUM, None)

    correlated = engine.correlate([first, second], [])

    assert len(correlated) == 1
    assert correlated[0].rule_id == "CKV_A"
    assert correlated[0].severity == Severity.MEDIUM
    assert correlated[0].nature is None
    assert second.finding_id in correlated[0].related_findings


def test_runtime_confirmation_turns_hardening_into_exposure():
    engine = RiskCorrelationEngine()
    static_finding = Finding.create(
        source=FindingSource.SEMGREP,
        category=FindingCategory.AUTHORIZATION,
        title="Static hardening hint",
        description="hint",
        severity=Severity.LOW,
        confidence=0.5,
        rule_id="static-hint",
        target_identifier="/users/{id}",
        correlation_key="api:GET:/users/{id}",
        nature=FindingNature.HARDENING,
    )
    runtime_finding = Finding.create(
        source=FindingSource.RUNTIME_VALIDATOR,
        category=FindingCategory.AUTHORIZATION,
        title="BOLA validated at runtime",
        description="validated",
        severity=Severity.HIGH,
        confidence=1.0,
        rule_id="bola-exploit-confirmed",
        target_identifier="GET:/users/123",
        correlation_key="api:GET:/users/{id}",
    )

    correlated = engine.correlate([static_finding], [runtime_finding])

    assert len(correlated) == 1
    assert correlated[0].nature == FindingNature.EXPOSURE
    assert correlated[0].severity == Severity.HIGH
    assert correlated[0].confidence == 1.0


# ─── Risk scoring ────────────────────────────────────────────────────────────


def test_risk_score_separates_exposure_from_hardening():
    engine = RiskCorrelationEngine()

    public_acl = _checkov_finding(
        "CKV_AWS_20",
        "public ACL",
        Severity.CRITICAL,
        FindingNature.EXPOSURE,
        risk_context=RiskContext(internet_exposed=True, public_resource=True),
    )
    iam_wildcard = _checkov_finding(
        "CKV_AWS_288", "data exfiltration", Severity.HIGH, FindingNature.EXPOSURE
    )
    unclassified = _checkov_finding("CKV_X", "unknown", Severity.MEDIUM, None)
    missing_logs = _checkov_finding(
        "CKV_AWS_18", "access logging", Severity.LOW, FindingNature.HARDENING
    )

    # 0.6*9.0 + 0.2*10 + 0.2*(4+2) = 8.6
    assert engine.calculate_risk_score(public_acl) == pytest.approx(8.6)
    # 0.6*7.0 + 0.2*10 + 0.2*3 = 6.8
    assert engine.calculate_risk_score(iam_wildcard) == pytest.approx(6.8)
    # Comportamento storico invariato per i finding non classificati: 5.3
    assert engine.calculate_risk_score(unclassified) == pytest.approx(5.3)
    # 0.6*2.0 + 0.2*10 + 0.2*0 = 3.2: nessun bonus di contesto per l'hardening
    assert engine.calculate_risk_score(missing_logs) == pytest.approx(3.2)


def test_hardening_ignores_exposure_context_bonus():
    engine = RiskCorrelationEngine()
    hardening_with_context = _checkov_finding(
        "CKV_AWS_18",
        "access logging",
        Severity.LOW,
        FindingNature.HARDENING,
        risk_context=RiskContext(internet_exposed=True, public_resource=True),
    )
    assert engine.calculate_risk_score(hardening_with_context) == pytest.approx(3.2)
