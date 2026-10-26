"""Detector API1: deduplicazione, report, conversione nel dominio e correlazione con il runtime."""

from src.application.correlation.engine import RiskCorrelationEngine
from src.core.api1_bola import detector
from src.core.api1_bola.models import ObjectAuthzFinding
from src.domain.entities import (
    APIContext,
    Finding,
    FindingCategory,
    FindingNature,
    FindingSource,
    RuntimeEvidence,
    Severity,
)
from src.normalization.normalizer import APIEndpointNormalizer

VULNERABLE = """
from flask import Flask, jsonify
from flask_login import current_user, login_required
app = Flask(__name__)

@app.get("/api/orders/<order_id>")
@login_required
def get_order(order_id):
    return jsonify(Order.query.get_or_404(order_id).to_dict())

@app.get("/api/receipts/<int:receipt_id>")
def get_receipt(receipt_id):
    return jsonify(RECEIPTS[receipt_id])
"""


def _f(rule: str, key: str = "api:GET:/a/{id}", file: str = "app.py") -> ObjectAuthzFinding:
    return ObjectAuthzFinding(
        rule_id=rule,
        cwe_id="CWE-639",
        category="c",
        severity="HIGH",
        file_path=file,
        line_number=1,
        endpoint="/a/<id>",
        http_methods=["GET"],
        id_parameter="id",
        found_guard=None,
        missing_guard="m",
        evidence="e",
        confidence=0.7,
        layer="ast",
        correlation_key=key,
    )


def test_dedup_keeps_highest_priority_and_records_absorbed_rules():
    result = detector.deduplicate_findings([_f("OA-001"), _f("OA-003"), _f("OA-005")])
    assert sorted((f.rule_id, tuple(f.related_rules)) for f in result) == [
        ("OA-003", ("OA-001",)),
        ("OA-005", ()),
    ]


def test_dedup_keeps_same_endpoint_in_different_services():
    result = detector.deduplicate_findings([_f("OA-001"), _f("OA-001", file="server.js")])
    assert len(result) == 2


def test_report_summary_and_coverage_signals():
    report = detector.analyze_content(VULNERABLE)
    assert report.handlers_analyzed == 2
    assert report.summary["rule"] == {"OA-001": 1, "OA-002": 1, "OA-005": 1}
    assert report.summary["handlers"]["with_object_access"] == 2
    assert report.coverage_signals["serial_id_no_authz_decorator"] == ["OA-005"]


def test_correlation_key_matches_runtime_format():
    report = detector.analyze_content(VULNERABLE)
    oa001 = next(f for f in report.findings if f.rule_id == "OA-001")
    runtime_path = "/api/orders/7f3c2a1e-0000-4000-8000-000000000001"
    assert oa001.correlation_key == f"api:GET:{APIEndpointNormalizer.normalize_path(runtime_path)}"


def test_domain_conversion():
    report = detector.analyze_content(VULNERABLE)
    findings = detector.to_domain_findings(report)
    oa001 = next(f for f in findings if f.rule_id == "OA-001")
    assert oa001.source == FindingSource.STATIC_ANALYZER
    assert oa001.category == FindingCategory.AUTHORIZATION
    assert oa001.owasp_api_category == "API1:2023" and oa001.cwe_id == "CWE-639"
    assert oa001.api.method == "GET" and oa001.nature == FindingNature.EXPOSURE
    assert oa001.correlation_key == "api:GET:/api/orders/{id}"
    # ID deterministici: due analisi identiche producono gli stessi finding_id
    again = detector.to_domain_findings(detector.analyze_content(VULNERABLE))
    assert {f.finding_id for f in findings} == {f.finding_id for f in again}


def test_runtime_confirmation_elevates_static_finding():
    static = detector.to_domain_findings(detector.analyze_content(VULNERABLE))
    runtime = Finding.create(
        source=FindingSource.RUNTIME_VALIDATOR,
        category=FindingCategory.AUTHORIZATION,
        title="BOLA Orizzontale confermato",
        description="peer ha letto l'ordine della vittima",
        severity=Severity.HIGH,
        confidence=1.0,
        rule_id="BOLA_HORIZONTAL",
        target_identifier="GET /api/orders/101",
        api=APIContext(endpoint="/api/orders/101", method="GET"),
        runtime_evidence=RuntimeEvidence(tested_url="/api/orders/101", http_status=200),
        correlation_key=f"api:GET:{APIEndpointNormalizer.normalize_path('/api/orders/101')}",
    )
    correlated = RiskCorrelationEngine().correlate(static, [runtime])
    merged = next(f for f in correlated if f.correlation_key == "api:GET:/api/orders/{id}")
    assert merged.rule_id == "OA-001"
    assert merged.severity == Severity.CRITICAL and merged.confidence == 1.0
    assert runtime.finding_id in merged.related_findings
    # il runtime si è agganciato al finding statico: nessuna voce separata
    assert all(f.source == FindingSource.STATIC_ANALYZER for f in correlated)
