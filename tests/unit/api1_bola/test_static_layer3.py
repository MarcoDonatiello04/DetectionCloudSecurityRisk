"""Layer 3 API1: incrocio contratto OpenAPI / finding AST."""

import copy

from src.core.api1_bola.layers.layer3_openapi import (
    NOT_DOCUMENTED,
    SECURITY_DECLARED,
    SECURITY_MISSING,
    analyze_openapi,
    index_operations,
)
from src.core.api1_bola.models import ObjectAuthzFinding


def _finding(method: str, path: str, confidence: float = 0.75) -> ObjectAuthzFinding:
    return ObjectAuthzFinding(
        rule_id="OA-001",
        cwe_id="CWE-639",
        category="missing_ownership_filter",
        severity="HIGH",
        file_path="app.py",
        line_number=10,
        endpoint=path,
        http_methods=[method],
        id_parameter="order_id",
        found_guard=None,
        missing_guard="x",
        evidence="Order.query.get(order_id)",
        confidence=confidence,
        layer="ast",
    )


SPEC = {
    "openapi": "3.0.3",
    "security": [{"bearerAuth": []}],
    "paths": {
        "/api/orders/{orderId}": {"get": {}, "delete": {"security": []}},
        "/api/public/{itemId}": {"get": {"security": [{}]}},
    },
}


def test_index_resolves_global_and_operation_security():
    index = index_operations(SPEC)
    assert index[("GET", "/api/orders/{id}")]["security_declared"] is True
    assert index[("DELETE", "/api/orders/{id}")]["security_declared"] is False
    # [{}] = autenticazione opzionale: non è un requisito
    assert index[("GET", "/api/public/{id}")]["security_declared"] is False


def test_security_declared_is_the_spectral_blind_spot():
    (f,) = analyze_openapi(SPEC, [_finding("GET", "/api/orders/<order_id>")])
    assert f.contract_status == SECURITY_DECLARED
    assert f.layer == "ast+openapi" and f.confidence == 0.85


def test_security_missing_and_not_documented():
    missing, undocumented = analyze_openapi(
        SPEC,
        [_finding("DELETE", "/api/orders/<order_id>"), _finding("GET", "/api/users/<user_id>")],
    )
    assert (missing.contract_status, missing.layer, missing.confidence) == (
        SECURITY_MISSING,
        "ast+openapi",
        0.75,
    )
    assert (undocumented.contract_status, undocumented.layer) == (NOT_DOCUMENTED, "ast")


def test_matching_tolerates_base_path_differences():
    (f,) = analyze_openapi(SPEC, [_finding("GET", "/orders/:orderId")])
    assert f.contract_status == SECURITY_DECLARED


def test_enrich_spec_annotates_operation():
    spec = copy.deepcopy(SPEC)
    analyze_openapi(spec, [_finding("GET", "/api/orders/<order_id>")], enrich_spec=True)
    entries = spec["paths"]["/api/orders/{orderId}"]["get"]["x-security-analysis"]["api1_findings"]
    assert entries[0]["rule_id"] == "OA-001"
    assert entries[0]["contract_status"] == SECURITY_DECLARED


def test_invalid_spec_leaves_findings_untouched():
    (f,) = analyze_openapi({"paths": {}}, [_finding("GET", "/api/orders/<order_id>")])
    assert f.contract_status is None and f.layer == "ast"
