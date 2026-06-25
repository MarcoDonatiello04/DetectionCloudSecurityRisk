"""
Tests for Layer 3 OpenAPI Spec Enrichment — API4:2023 Unrestricted Resource Consumption.

Specs are defined inline as Python dicts (no external files required).
Each test covers:
  - RC-010: pagination parameter without maximum
  - RC-011: upload endpoint without maxLength/maxItems
  - RC-012: expensive endpoint without rate protection
  - Enrichment: x-security-analysis added correctly
  - Robustness: empty/malformed specs don't crash

All tests are deterministic and require no network or LLM calls.
"""

from __future__ import annotations

import copy

import pytest

from src.core.api4_unrestricted_resource_consumption.layers.layer3_openapi import (
    analyze_openapi,
    detect_spec_version,
)


# ---------------------------------------------------------------------------
# Base spec factory
# ---------------------------------------------------------------------------

def _openapi3(paths: dict, global_security: list | None = None) -> dict:
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "Test API", "version": "1.0.0"},
        "paths": paths,
    }
    if global_security is not None:
        spec["security"] = global_security
    return spec


def _swagger2(paths: dict) -> dict:
    return {
        "swagger": "2.0",
        "info": {"title": "Test API", "version": "1.0.0"},
        "paths": paths,
    }


def _rule_ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


# ===========================================================================
# detect_spec_version
# ===========================================================================

class TestDetectSpecVersion:

    def test_openapi3(self):
        assert detect_spec_version({"openapi": "3.0.3"}) == "3.0.3"

    def test_openapi31(self):
        assert detect_spec_version({"openapi": "3.1.0"}) == "3.1.0"

    def test_swagger2(self):
        assert detect_spec_version({"swagger": "2.0"}) == "2.0"

    def test_unknown_raises(self):
        with pytest.raises(ValueError):
            detect_spec_version({"info": "no version key"})


# ===========================================================================
# RC-010 — Pagination parameter without maximum
# ===========================================================================

class TestRC010PaginationMax:

    # --- TRUE POSITIVE: limit parameter without maximum ---
    def test_tp_limit_no_maximum(self):
        spec = _openapi3({
            "/users": {
                "get": {
                    "parameters": [
                        {
                            "name": "limit",
                            "in": "query",
                            "schema": {"type": "integer", "default": 10},
                        }
                    ]
                }
            }
        })
        findings = analyze_openapi(spec)
        rc010 = [f for f in findings if f.rule_id == "RC-010"]
        assert rc010, "Expected RC-010 for limit without maximum"
        assert rc010[0].parameter == "limit"
        assert rc010[0].severity == "HIGH"
        assert rc010[0].endpoint == "GET /users"

    # --- TRUE NEGATIVE: limit parameter WITH maximum ---
    def test_tn_limit_with_maximum(self):
        spec = _openapi3({
            "/users": {
                "get": {
                    "parameters": [
                        {
                            "name": "limit",
                            "in": "query",
                            "schema": {"type": "integer", "default": 10, "maximum": 100},
                        }
                    ]
                }
            }
        })
        findings = analyze_openapi(spec)
        rc010 = [f for f in findings if f.rule_id == "RC-010"]
        assert not rc010, f"Unexpected RC-010 when maximum is set: {rc010}"

    # --- LOW severity when maximum > 1000 ---
    def test_tp_oversized_maximum_low_severity(self):
        spec = _openapi3({
            "/items": {
                "get": {
                    "parameters": [
                        {
                            "name": "page_size",
                            "in": "query",
                            "schema": {"type": "integer", "maximum": 5000},
                        }
                    ]
                }
            }
        })
        findings = analyze_openapi(spec)
        rc010 = [f for f in findings if f.rule_id == "RC-010"]
        assert rc010
        assert rc010[0].severity == "LOW"

    # --- All pagination param names trigger ---
    @pytest.mark.parametrize("param_name", [
        "limit", "page_size", "per_page", "count", "size",
        "max", "take", "top", "n",
    ])
    def test_tp_all_pagination_names(self, param_name: str):
        spec = _openapi3({
            f"/{param_name}": {
                "get": {
                    "parameters": [
                        {
                            "name": param_name,
                            "in": "query",
                            "schema": {"type": "integer"},
                        }
                    ]
                }
            }
        })
        findings = analyze_openapi(spec)
        rc010 = [f for f in findings if f.rule_id == "RC-010"]
        assert rc010, f"Expected RC-010 for param '{param_name}'"

    # --- requestBody json schema ---
    def test_tp_request_body_limit(self):
        spec = _openapi3({
            "/search": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "limit": {"type": "integer"},
                                        "query": {"type": "string"},
                                    }
                                }
                            }
                        }
                    }
                }
            }
        })
        findings = analyze_openapi(spec)
        rc010 = [f for f in findings if f.rule_id == "RC-010"]
        assert rc010

    # --- Swagger 2.0 compatibility ---
    def test_tp_swagger2_inline_maximum(self):
        spec = _swagger2({
            "/users": {
                "get": {
                    "parameters": [
                        {"name": "limit", "in": "query", "type": "integer"}
                    ]
                }
            }
        })
        findings = analyze_openapi(spec)
        rc010 = [f for f in findings if f.rule_id == "RC-010"]
        assert rc010, "RC-010 should fire on Swagger 2.0 spec"

    # --- Non-pagination param names ignored ---
    def test_tn_non_pagination_param_ignored(self):
        spec = _openapi3({
            "/users": {
                "get": {
                    "parameters": [
                        {"name": "user_id", "in": "query", "schema": {"type": "string"}}
                    ]
                }
            }
        })
        findings = analyze_openapi(spec)
        rc010 = [f for f in findings if f.rule_id == "RC-010"]
        assert not rc010


# ===========================================================================
# RC-011 — Upload without maxLength / maxItems
# ===========================================================================

class TestRC011UploadSize:

    # --- TRUE POSITIVE: multipart/form-data binary without maxLength ---
    def test_tp_binary_no_max_length(self):
        spec = _openapi3({
            "/upload": {
                "post": {
                    "requestBody": {
                        "content": {
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "file": {
                                            "type": "string",
                                            "format": "binary",
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        })
        findings = analyze_openapi(spec)
        rc011 = [f for f in findings if f.rule_id == "RC-011"]
        assert rc011, "Expected RC-011 for binary without maxLength"
        assert rc011[0].severity == "HIGH"
        assert rc011[0].parameter == "file"

    # --- TRUE NEGATIVE: binary WITH maxLength ---
    def test_tn_binary_with_max_length(self):
        spec = _openapi3({
            "/upload": {
                "post": {
                    "requestBody": {
                        "content": {
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "file": {
                                            "type": "string",
                                            "format": "binary",
                                            "maxLength": 10485760,
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        })
        findings = analyze_openapi(spec)
        rc011 = [f for f in findings if f.rule_id == "RC-011"]
        assert not rc011, f"Unexpected RC-011 when maxLength is set: {rc011}"

    # --- TRUE POSITIVE: array without maxItems ---
    def test_tp_array_no_max_items(self):
        spec = _openapi3({
            "/batch": {
                "post": {
                    "requestBody": {
                        "content": {
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "files": {
                                            "type": "array",
                                            "items": {"type": "string", "format": "binary"},
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        })
        findings = analyze_openapi(spec)
        rc011 = [f for f in findings if f.rule_id == "RC-011"]
        assert rc011
        assert rc011[0].severity == "MEDIUM"

    # --- TRUE NEGATIVE: array WITH maxItems ---
    def test_tn_array_with_max_items(self):
        spec = _openapi3({
            "/batch": {
                "post": {
                    "requestBody": {
                        "content": {
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "files": {
                                            "type": "array",
                                            "maxItems": 10,
                                            "items": {"type": "string", "format": "binary"},
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        })
        findings = analyze_openapi(spec)
        rc011 = [f for f in findings if f.rule_id == "RC-011"]
        assert not rc011

    # --- application/octet-stream also triggers ---
    def test_tp_octet_stream(self):
        spec = _openapi3({
            "/upload": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/octet-stream": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "data": {"type": "string", "format": "binary"}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        })
        findings = analyze_openapi(spec)
        rc011 = [f for f in findings if f.rule_id == "RC-011"]
        assert rc011

    # --- application/json does not trigger RC-011 ---
    def test_tn_json_body_no_rc011(self):
        spec = _openapi3({
            "/data": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "file": {"type": "string", "format": "binary"}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        })
        findings = analyze_openapi(spec)
        rc011 = [f for f in findings if f.rule_id == "RC-011"]
        assert not rc011


# ===========================================================================
# RC-012 — Expensive endpoint without protection
# ===========================================================================

class TestRC012ExpensiveEndpoint:

    # --- TRUE POSITIVE: /sms/send without security ---
    def test_tp_sms_no_security(self):
        spec = _openapi3({
            "/sms/send": {
                "post": {
                    "summary": "Send SMS",
                    "description": "Send a text message.",
                }
            }
        })
        findings = analyze_openapi(spec)
        rc012 = [f for f in findings if f.rule_id == "RC-012"]
        assert rc012, "Expected RC-012 for /sms/send without security"
        assert rc012[0].severity == "HIGH"

    # --- TRUE NEGATIVE: /sms/send WITH endpoint-level security ---
    def test_tn_sms_with_security(self):
        spec = _openapi3({
            "/sms/send": {
                "post": {
                    "summary": "Send SMS",
                    "security": [{"bearerAuth": []}],
                }
            }
        })
        findings = analyze_openapi(spec)
        rc012 = [f for f in findings if f.rule_id == "RC-012"]
        assert not rc012, f"Unexpected RC-012 when security is set: {rc012}"

    # --- TRUE NEGATIVE: global security covers expensive endpoint ---
    def test_tn_expensive_with_global_security(self):
        spec = _openapi3(
            paths={
                "/notify": {
                    "post": {"summary": "Send notification"}
                }
            },
            global_security=[{"bearerAuth": []}],
        )
        findings = analyze_openapi(spec)
        rc012 = [f for f in findings if f.rule_id == "RC-012"]
        assert not rc012

    # --- TRUE NEGATIVE: x-rate-limit extension counts as protection ---
    def test_tn_rate_limit_extension(self):
        spec = _openapi3({
            "/export": {
                "get": {
                    "summary": "Export data",
                    "x-rate-limit": "10/hour",
                }
            }
        })
        findings = analyze_openapi(spec)
        rc012 = [f for f in findings if f.rule_id == "RC-012"]
        assert not rc012

    # --- TRUE NEGATIVE: throttle keyword in description ---
    def test_tn_throttle_keyword_in_description(self):
        spec = _openapi3({
            "/notify": {
                "post": {
                    "summary": "Send notification",
                    "description": "Rate limited to 5 calls per user per hour.",
                }
            }
        })
        findings = analyze_openapi(spec)
        rc012 = [f for f in findings if f.rule_id == "RC-012"]
        assert not rc012

    # --- Parametric: expensive patterns ---
    @pytest.mark.parametrize("path,expected", [
        ("/sms/send", True),
        ("/otp/verify", True),
        ("/email/send", True),
        ("/export/csv", True),
        ("/payment/charge", True),
        ("/ai/predict", True),
        ("/users", False),
        ("/health", False),
    ])
    def test_expensive_path_patterns(self, path: str, expected: bool):
        spec = _openapi3({
            path: {
                "post": {"summary": "Test endpoint"}
            }
        })
        findings = analyze_openapi(spec)
        rc012 = [f for f in findings if f.rule_id == "RC-012"]
        if expected:
            assert rc012, f"Expected RC-012 for {path}"
        else:
            assert not rc012, f"Unexpected RC-012 for {path}: {rc012}"

    # --- empty security list = explicitly unauthenticated ---
    def test_tp_empty_security_list(self):
        spec = _openapi3({
            "/sms/send": {
                "post": {
                    "summary": "Send SMS",
                    "security": [],  # explicitly unauthenticated
                }
            }
        })
        findings = analyze_openapi(spec)
        rc012 = [f for f in findings if f.rule_id == "RC-012"]
        assert rc012, "Empty security list means no protection"


# ===========================================================================
# Enrichment — x-security-analysis extension
# ===========================================================================

class TestEnrichment:

    def test_enrichment_adds_x_security_analysis(self):
        spec = _openapi3({
            "/users": {
                "get": {
                    "parameters": [
                        {
                            "name": "limit",
                            "in": "query",
                            "schema": {"type": "integer"},
                        }
                    ]
                }
            }
        })
        findings = analyze_openapi(spec, enrich_spec=True)
        assert findings  # at least RC-010
        # Check spec was enriched
        op = spec["paths"]["/users"]["get"]
        assert "x-security-analysis" in op, "x-security-analysis not added to spec"
        api4 = op["x-security-analysis"]["api4_findings"]
        assert isinstance(api4, list) and len(api4) > 0
        assert api4[0]["rule_id"] == "RC-010"

    def test_enrichment_does_not_overwrite_existing_fields(self):
        spec = _openapi3({
            "/users": {
                "get": {
                    "summary": "Get users",  # should be preserved
                    "parameters": [
                        {
                            "name": "limit",
                            "in": "query",
                            "schema": {"type": "integer"},
                        }
                    ],
                    "x-security-analysis": {
                        "api4_findings": [{"rule_id": "EXISTING", "severity": "INFO"}]
                    },
                }
            }
        })
        findings = analyze_openapi(spec, enrich_spec=True)
        op = spec["paths"]["/users"]["get"]
        # Should have appended, not replaced
        api4 = op["x-security-analysis"]["api4_findings"]
        rule_ids = {e["rule_id"] for e in api4}
        assert "EXISTING" in rule_ids, "Existing entry was overwritten"
        assert op["summary"] == "Get users", "Non-x- field was modified"

    def test_enrichment_false_does_not_modify_spec(self):
        spec = _openapi3({
            "/users": {
                "get": {
                    "parameters": [
                        {
                            "name": "limit",
                            "in": "query",
                            "schema": {"type": "integer"},
                        }
                    ]
                }
            }
        })
        spec_copy = copy.deepcopy(spec)
        analyze_openapi(spec, enrich_spec=False)
        assert spec == spec_copy, "Spec was modified when enrich_spec=False"

    def test_findings_still_returned_with_enrichment(self):
        spec = _openapi3({
            "/sms/send": {
                "post": {"summary": "Send SMS"}
            }
        })
        findings = analyze_openapi(spec, enrich_spec=True)
        assert any(f.rule_id == "RC-012" for f in findings)


# ===========================================================================
# Robustness
# ===========================================================================

class TestRobustness:

    def test_empty_spec_returns_empty(self):
        assert analyze_openapi({}) == []

    def test_none_like_spec_returns_empty(self):
        # Non-dict input
        assert analyze_openapi("not a dict") == []  # type: ignore

    def test_spec_without_paths(self):
        spec = {"openapi": "3.0.3", "info": {"title": "T", "version": "1"}}
        findings = analyze_openapi(spec)
        assert findings == []

    def test_spec_with_empty_paths(self):
        spec = _openapi3({})
        findings = analyze_openapi(spec)
        assert findings == []

    def test_spec_unknown_version_still_analyzed(self):
        # Missing version key — still attempt analysis
        spec = {
            "info": {"title": "T", "version": "1"},
            "paths": {
                "/users": {
                    "get": {
                        "parameters": [
                            {"name": "limit", "in": "query", "schema": {"type": "integer"}}
                        ]
                    }
                }
            },
        }
        findings = analyze_openapi(spec)
        assert any(f.rule_id == "RC-010" for f in findings), \
            "Analysis should proceed even without a recognized version key"

    def test_malformed_parameter_list_no_crash(self):
        spec = _openapi3({
            "/broken": {
                "get": {
                    "parameters": "not_a_list"  # deliberately broken
                }
            }
        })
        findings = analyze_openapi(spec)
        assert isinstance(findings, list)

    def test_all_findings_have_layer_openapi(self):
        spec = _openapi3({
            "/users": {
                "get": {
                    "parameters": [
                        {"name": "limit", "in": "query", "schema": {"type": "integer"}}
                    ]
                }
            },
            "/sms/send": {
                "post": {"summary": "Send SMS"}
            },
        })
        findings = analyze_openapi(spec)
        assert all(f.layer == "openapi" for f in findings)

    def test_all_findings_have_endpoint(self):
        spec = _openapi3({
            "/users": {
                "get": {
                    "parameters": [
                        {"name": "limit", "in": "query", "schema": {"type": "integer"}}
                    ]
                }
            }
        })
        findings = analyze_openapi(spec)
        rc010 = [f for f in findings if f.rule_id == "RC-010"]
        assert all(f.endpoint for f in rc010)


# ===========================================================================
# Integration — multi-rule spec
# ===========================================================================

class TestMultiRuleSpec:

    def test_all_three_rules_on_one_spec(self):
        spec = _openapi3({
            "/users": {
                "get": {
                    "parameters": [
                        {"name": "limit", "in": "query", "schema": {"type": "integer"}}
                    ]
                }
            },
            "/upload": {
                "post": {
                    "requestBody": {
                        "content": {
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "file": {"type": "string", "format": "binary"}
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/sms/send": {
                "post": {"summary": "Send SMS"}
            },
        })
        findings = analyze_openapi(spec)
        found_rules = _rule_ids(findings)
        assert "RC-010" in found_rules
        assert "RC-011" in found_rules
        assert "RC-012" in found_rules

    def test_secure_spec_no_findings(self):
        spec = _openapi3(
            paths={
                "/users": {
                    "get": {
                        "parameters": [
                            {
                                "name": "limit",
                                "in": "query",
                                "schema": {"type": "integer", "maximum": 100},
                            }
                        ]
                    }
                },
                "/upload": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "file": {
                                                "type": "string",
                                                "format": "binary",
                                                "maxLength": 10485760,
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "/sms/send": {
                    "post": {
                        "summary": "Send SMS",
                        "security": [{"bearerAuth": []}],
                    }
                },
            },
            global_security=None,
        )
        findings = analyze_openapi(spec)
        assert not findings, (
            f"Secure spec should produce no findings, got: "
            f"{[(f.rule_id, f.endpoint) for f in findings]}"
        )
