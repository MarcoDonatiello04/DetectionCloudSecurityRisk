import pytest

from src.core.broken_function_level_authorization.layers.layer3_openapi import (
    analyze_openapi,
    detect_spec_version,
)
from src.core.broken_function_level_authorization.models import FunctionAuthzFinding


def test_detect_spec_version():
    assert detect_spec_version({"openapi": "3.0.0"}) == "3.0.0"
    assert detect_spec_version({"swagger": "2.0"}) == "2.0"
    with pytest.raises(ValueError):
        detect_spec_version({"foo": "bar"})


def test_analyze_openapi_empty():
    findings = analyze_openapi({})
    assert findings == []


def test_analyze_openapi_enrichment():
    spec = {
        "openapi": "3.0.0",
        "paths": {"/users": {"get": {"responses": {"200": {"description": "success"}}}}},
    }
    findings = analyze_openapi(spec, enrich_spec=True)
    assert findings == []
    assert "x-security-analysis" not in spec["paths"]["/users"]["get"]


def test_bf001_privileged_endpoint_no_security():
    spec = {
        "openapi": "3.0.0",
        "paths": {"/admin/users": {"delete": {"summary": "Delete all users"}}},
    }
    findings = analyze_openapi(spec)
    bf001 = [f for f in findings if f.rule_id == "BF-001"]
    assert len(bf001) == 1
    assert bf001[0].severity == "CRITICAL"


def test_shadow_endpoint_detection():
    spec = {"openapi": "3.0.0", "paths": {"/api/users": {"get": {}}}}
    discovered = ["/api/users", "/debug/token-info"]
    findings = analyze_openapi(spec, discovered_endpoints=discovered)
    bf006 = [f for f in findings if f.rule_id == "BF-006"]
    assert len(bf006) == 1
    assert "/debug/token-info" in bf006[0].evidence


def test_no_finding_on_protected_endpoint():
    spec = {
        "openapi": "3.0.0",
        "security": [{"bearerAuth": []}],
        "paths": {"/admin/users": {"delete": {"summary": "Delete all users"}}},
    }
    findings = analyze_openapi(spec)
    bf001 = [f for f in findings if f.rule_id == "BF-001"]
    assert len(bf001) == 0


def test_bf003_method_override_correlation():
    spec = {
        "openapi": "3.0.0",
        "paths": {"/admin/users": {"delete": {"summary": "Delete all users"}}},
    }
    # Create a mock AST finding for BF-003
    ast_findings = [
        FunctionAuthzFinding(
            rule_id="BF-003",
            cwe_id="CWE-650",
            category="http_method_override",
            severity="HIGH",
            file_path="app.py",
            line_number=10,
            endpoint="ANY /admin/users",
            http_methods=[],
            required_role="admin",
            found_guard=None,
            missing_guard="Route registered on a privileged path without explicit methods restriction",
            evidence="@app.route('/admin/users')",
            confidence=0.90,
            layer="ast",
        )
    ]
    findings = analyze_openapi(spec, ast_findings=ast_findings, enrich_spec=True)
    bf003 = [f for f in findings if f.rule_id == "BF-003"]
    assert len(bf003) == 1
    assert bf003[0].layer == "ast+openapi"

    # Verify enrichment in-place
    op = spec["paths"]["/admin/users"]["delete"]
    assert "x-security-analysis" in op
    analysis = op["x-security-analysis"]["api5_findings"]
    bf003_enrich = [entry for entry in analysis if entry["rule_id"] == "BF-003"]
    assert len(bf003_enrich) == 1
    assert bf003_enrich[0]["layer"] == "ast+openapi"
    assert bf003_enrich[0]["correlation"] == "confirmed_by_ast"
