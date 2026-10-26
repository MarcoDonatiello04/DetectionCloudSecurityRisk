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

from src.core.api4_resource_consumption.layers.layer3_openapi import (
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
        spec = _openapi3(
            {
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
            }
        )
        findings = analyze_openapi(spec)
        rc010 = [f for f in findings if f.rule_id == "RC-010"]
        assert rc010, "Expected RC-010 for limit without maximum"
        assert rc010[0].parameter == "limit"
        assert rc010[0].severity == "HIGH"
        assert rc010[0].endpoint == "GET /users"

    # --- TRUE NEGATIVE: limit parameter WITH maximum ---
    def test_tn_limit_with_maximum(self):
        spec = _openapi3(
            {
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
            }
        )
        findings = analyze_openapi(spec)
        rc010 = [f for f in findings if f.rule_id == "RC-010"]
        assert not rc010, f"Unexpected RC-010 when maximum is set: {rc010}"

    # --- LOW severity when maximum > 1000 ---
    def test_tp_oversized_maximum_low_severity(self):
        spec = _openapi3(
            {
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
            }
        )
        findings = analyze_openapi(spec)
        rc010 = [f for f in findings if f.rule_id == "RC-010"]
        assert rc010
        assert rc010[0].severity == "LOW"

    # --- All pagination param names trigger ---
    @pytest.mark.parametrize(
        "param_name",
        [
            "limit",
            "page_size",
            "per_page",
            "count",
            "size",
            "max",
            "take",
            "top",
            "n",
        ],
    )
    def test_tp_all_pagination_names(self, param_name: str):
        spec = _openapi3(
            {
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
            }
        )
        findings = analyze_openapi(spec)
        rc010 = [f for f in findings if f.rule_id == "RC-010"]
        assert rc010, f"Expected RC-010 for param '{param_name}'"

    # --- requestBody json schema ---
    def test_tp_request_body_limit(self):
        spec = _openapi3(
            {
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
                                        },
                                    }
                                }
                            }
                        }
                    }
                }
            }
        )
        findings = analyze_openapi(spec)
        rc010 = [f for f in findings if f.rule_id == "RC-010"]
        assert rc010

    # --- Swagger 2.0 compatibility ---
    def test_tp_swagger2_inline_maximum(self):
        spec = _swagger2(
            {
                "/users": {
                    "get": {"parameters": [{"name": "limit", "in": "query", "type": "integer"}]}
                }
            }
        )
        findings = analyze_openapi(spec)
        rc010 = [f for f in findings if f.rule_id == "RC-010"]
        assert rc010, "RC-010 should fire on Swagger 2.0 spec"

    # --- Non-pagination param names ignored ---
    def test_tn_non_pagination_param_ignored(self):
        spec = _openapi3(
            {
                "/users": {
                    "get": {
                        "parameters": [
                            {"name": "user_id", "in": "query", "schema": {"type": "string"}}
                        ]
                    }
                }
            }
        )
        findings = analyze_openapi(spec)
        rc010 = [f for f in findings if f.rule_id == "RC-010"]
        assert not rc010


# ===========================================================================
# RC-011 — Upload without maxLength / maxItems
# ===========================================================================


class TestRC011UploadSize:
    # --- TRUE POSITIVE: multipart/form-data binary without maxLength ---
    def test_tp_binary_no_max_length(self):
        spec = _openapi3(
            {
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
                                        },
                                    }
                                }
                            }
                        }
                    }
                }
            }
        )
        findings = analyze_openapi(spec)
        rc011 = [f for f in findings if f.rule_id == "RC-011"]
        assert rc011, "Expected RC-011 for binary without maxLength"
        assert rc011[0].severity == "HIGH"
        assert rc011[0].parameter == "file"

    # --- TRUE NEGATIVE: binary WITH maxLength ---
    def test_tn_binary_with_max_length(self):
        spec = _openapi3(
            {
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
                                        },
                                    }
                                }
                            }
                        }
                    }
                }
            }
        )
        findings = analyze_openapi(spec)
        rc011 = [f for f in findings if f.rule_id == "RC-011"]
        assert not rc011, f"Unexpected RC-011 when maxLength is set: {rc011}"

    # --- TRUE POSITIVE: array without maxItems ---
    def test_tp_array_no_max_items(self):
        spec = _openapi3(
            {
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
                                        },
                                    }
                                }
                            }
                        }
                    }
                }
            }
        )
        findings = analyze_openapi(spec)
        rc011 = [f for f in findings if f.rule_id == "RC-011"]
        assert rc011
        assert rc011[0].severity == "MEDIUM"

    # --- TRUE NEGATIVE: array WITH maxItems ---
    def test_tn_array_with_max_items(self):
        spec = _openapi3(
            {
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
                                        },
                                    }
                                }
                            }
                        }
                    }
                }
            }
        )
        findings = analyze_openapi(spec)
        rc011 = [f for f in findings if f.rule_id == "RC-011"]
        assert not rc011

    # --- application/octet-stream also triggers ---
    def test_tp_octet_stream(self):
        spec = _openapi3(
            {
                "/upload": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/octet-stream": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "data": {"type": "string", "format": "binary"}
                                        },
                                    }
                                }
                            }
                        }
                    }
                }
            }
        )
        findings = analyze_openapi(spec)
        rc011 = [f for f in findings if f.rule_id == "RC-011"]
        assert rc011

    # --- application/json does not trigger RC-011 ---
    def test_tn_json_body_no_rc011(self):
        spec = _openapi3(
            {
                "/data": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "file": {"type": "string", "format": "binary"}
                                        },
                                    }
                                }
                            }
                        }
                    }
                }
            }
        )
        findings = analyze_openapi(spec)
        rc011 = [f for f in findings if f.rule_id == "RC-011"]
        assert not rc011


# ===========================================================================
# RC-012 — Expensive endpoint without protection
# ===========================================================================


class TestRC012ExpensiveEndpoint:
    # --- TRUE POSITIVE: /sms/send without security ---
    def test_tp_sms_no_security(self):
        spec = _openapi3(
            {
                "/sms/send": {
                    "post": {
                        "summary": "Send SMS",
                        "description": "Send a text message.",
                    }
                }
            }
        )
        findings = analyze_openapi(spec)
        rc012 = [f for f in findings if f.rule_id == "RC-012"]
        assert rc012, "Expected RC-012 for /sms/send without security"
        assert rc012[0].severity == "HIGH"

    # --- TRUE NEGATIVE: /sms/send WITH endpoint-level security ---
    def test_tn_sms_with_security(self):
        spec = _openapi3(
            {
                "/sms/send": {
                    "post": {
                        "summary": "Send SMS",
                        "security": [{"bearerAuth": []}],
                    }
                }
            }
        )
        findings = analyze_openapi(spec)
        rc012 = [f for f in findings if f.rule_id == "RC-012"]
        assert not rc012, f"Unexpected RC-012 when security is set: {rc012}"

    # --- TRUE NEGATIVE: global security covers expensive endpoint ---
    def test_tn_expensive_with_global_security(self):
        spec = _openapi3(
            paths={"/notify": {"post": {"summary": "Send notification"}}},
            global_security=[{"bearerAuth": []}],
        )
        findings = analyze_openapi(spec)
        rc012 = [f for f in findings if f.rule_id == "RC-012"]
        assert not rc012

    # --- TRUE NEGATIVE: x-rate-limit extension counts as protection ---
    def test_tn_rate_limit_extension(self):
        spec = _openapi3(
            {
                "/export": {
                    "get": {
                        "summary": "Export data",
                        "x-rate-limit": "10/hour",
                    }
                }
            }
        )
        findings = analyze_openapi(spec)
        rc012 = [f for f in findings if f.rule_id == "RC-012"]
        assert not rc012

    # --- TRUE NEGATIVE: throttle keyword in description ---
    def test_tn_throttle_keyword_in_description(self):
        spec = _openapi3(
            {
                "/notify": {
                    "post": {
                        "summary": "Send notification",
                        "description": "Rate limited to 5 calls per user per hour.",
                    }
                }
            }
        )
        findings = analyze_openapi(spec)
        rc012 = [f for f in findings if f.rule_id == "RC-012"]
        assert not rc012

    # --- Parametric: expensive patterns ---
    @pytest.mark.parametrize(
        "path,expected",
        [
            ("/sms/send", True),
            ("/otp/verify", True),
            ("/email/send", True),
            ("/export/csv", True),
            ("/payment/charge", True),
            ("/ai/predict", True),
            ("/users", False),
            ("/health", False),
        ],
    )
    def test_expensive_path_patterns(self, path: str, expected: bool):
        spec = _openapi3({path: {"post": {"summary": "Test endpoint"}}})
        findings = analyze_openapi(spec)
        rc012 = [f for f in findings if f.rule_id == "RC-012"]
        if expected:
            assert rc012, f"Expected RC-012 for {path}"
        else:
            assert not rc012, f"Unexpected RC-012 for {path}: {rc012}"

    # --- Resource keywords: costly only when the operation creates/triggers them ---
    @pytest.mark.parametrize(
        "path,method,expected",
        [
            ("/api/invoices/{id}", "get", False),  # plain read of a stored invoice
            ("/api/invoices/{id}", "put", False),
            ("/api/invoices/{id}", "delete", False),
            ("/api/invoices", "get", False),
            ("/api/invoices", "post", True),  # issuing an invoice
            ("/payments", "post", True),
            ("/notifications/{id}", "get", False),
            ("/api/invoices/{id}/download", "get", True),  # action keyword: any method
            ("/reports/export", "get", True),
        ],
    )
    def test_resource_keyword_depends_on_operation(self, path: str, method: str, expected: bool):
        spec = _openapi3({path: {method: {"summary": "Test endpoint"}}})
        rc012 = [f for f in analyze_openapi(spec) if f.rule_id == "RC-012"]
        assert bool(rc012) == expected, f"{method.upper()} {path}: {rc012}"

    # --- Whole-word matching: short keywords do not fire inside other words ---
    @pytest.mark.parametrize(
        "path,summary",
        [
            ("/users/{id}/detail", "Show user details"),  # "ai" inside "detail"
            ("/pages/html", "Render HTML page"),  # "ml" inside "html"
            ("/profile/emailPreferences", "Update the mailing list"),  # "ai" inside "mailing"
            ("/supports", "List supported locales"),  # "report"-like substrings
        ],
    )
    def test_short_keywords_match_whole_words_only(self, path: str, summary: str):
        spec = _openapi3({path: {"get": {"summary": summary}}})
        rc012 = [f for f in analyze_openapi(spec) if f.rule_id == "RC-012"]
        assert not rc012, f"Unexpected RC-012 for {path}: {rc012}"

    def test_operation_id_camel_case_is_split(self):
        spec = _openapi3({"/v1/jobs": {"post": {"operationId": "createPaymentIntent"}}})
        rc012 = [f for f in analyze_openapi(spec) if f.rule_id == "RC-012"]
        assert rc012 and "payment" in rc012[0].evidence

    # --- Operation shape: a non-POST method can still trigger the costly work ---
    @pytest.mark.parametrize(
        "path,method,operation,expected",
        [
            ("/sms", "put", {}, True),  # collection-level PUT: no item to update
            ("/notifications", "patch", {}, True),
            ("/api/invoices/{id}/send", "put", {}, True),  # trigger verb in the path
            ("/api/invoices/{id}", "put", {"operationId": "resendInvoice"}, True),
            ("/api/invoices/{id}", "put", {"operationId": "updateInvoice"}, False),
            ("/api/invoices/{id}", "patch", {}, False),
            ("/sms/{id}", "delete", {}, False),
        ],
    )
    def test_operation_shape_triggers_cost(
        self, path: str, method: str, operation: dict, expected: bool
    ):
        spec = _openapi3({path: {method: operation}})
        rc012 = [f for f in analyze_openapi(spec) if f.rule_id == "RC-012"]
        assert bool(rc012) == expected, f"{method.upper()} {path}: {rc012}"

    # --- Structural signals: costly endpoints with neutral names ---
    @staticmethod
    def _json_body(properties: dict) -> dict:
        return {
            "requestBody": {
                "content": {
                    "application/json": {"schema": {"type": "object", "properties": properties}}
                }
            }
        }

    @pytest.mark.parametrize(
        "properties,severity",
        [
            ({"phone_number": {"type": "string"}, "text": {"type": "string"}}, "HIGH"),
            ({"to": {"type": "string"}, "subject": {"type": "string"}}, "HIGH"),
            ({"amount": {"type": "integer"}, "currency": {"type": "string"}}, "HIGH"),
            ({"prompt": {"type": "string"}}, "HIGH"),
            ({"options": {"type": "object", "properties": {"maxTokens": {}}}}, "HIGH"),
        ],
    )
    def test_neutral_name_detected_by_request_fields(self, properties: dict, severity: str):
        spec = _openapi3({"/v1/jobs": {"post": self._json_body(properties)}})
        rc012 = [f for f in analyze_openapi(spec) if f.rule_id == "RC-012"]
        assert rc012, f"Expected RC-012 for fields {list(properties)}"
        assert rc012[0].severity == severity
        assert "structural cost signal" in rc012[0].evidence

    def test_request_fields_resolved_through_ref(self):
        spec = _openapi3(
            {
                "/v1/actions": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Transfer"}
                                }
                            }
                        }
                    }
                }
            }
        )
        spec["components"] = {
            "schemas": {
                "Transfer": {
                    "type": "object",
                    "properties": {"amount": {"type": "number"}, "currency": {}},
                }
            }
        }
        rc012 = [f for f in analyze_openapi(spec) if f.rule_id == "RC-012"]
        assert rc012 and "Financial transaction" in rc012[0].evidence

    @pytest.mark.parametrize(
        "properties",
        [
            {"recipient": {}, "message": {}},  # internal chat: no provider behind it
            {"phone": {}, "name": {}},  # a profile with a phone number
            {"path_to_file": {}, "subject": {}},  # "to" only as a whole field name
            {"price": {}, "currency": {}},
        ],
    )
    def test_ordinary_request_fields_not_flagged(self, properties: dict):
        spec = _openapi3({"/v1/items": {"post": self._json_body(properties)}})
        rc012 = [f for f in analyze_openapi(spec) if f.rule_id == "RC-012"]
        assert not rc012, f"Unexpected RC-012 for fields {list(properties)}: {rc012}"

    @pytest.mark.parametrize(
        "responses",
        [
            {"202": {"description": "Queued"}},
            {"200": {"content": {"application/pdf": {}}}},
            {"200": {"content": {"text/csv; charset=utf-8": {}}}},
            {"200": {"content": {"video/mp4": {}}}},
        ],
    )
    def test_neutral_name_detected_by_response(self, responses: dict):
        spec = _openapi3({"/v1/documents/{id}": {"get": {"responses": responses}}})
        rc012 = [f for f in analyze_openapi(spec) if f.rule_id == "RC-012"]
        assert rc012 and rc012[0].severity == "MEDIUM"

    def test_json_response_not_flagged(self):
        spec = _openapi3(
            {
                "/v1/documents/{id}": {
                    "get": {"responses": {"200": {"content": {"application/json": {}}}}}
                }
            }
        )
        assert not [f for f in analyze_openapi(spec) if f.rule_id == "RC-012"]

    def test_structural_signal_respects_documented_protection(self):
        operation = self._json_body({"prompt": {}})
        operation["x-rate-limit"] = "10/minute"
        spec = _openapi3({"/v1/jobs": {"post": operation}})
        assert not [f for f in analyze_openapi(spec) if f.rule_id == "RC-012"]

    # --- empty security list = explicitly unauthenticated ---
    def test_tp_empty_security_list(self):
        spec = _openapi3(
            {
                "/sms/send": {
                    "post": {
                        "summary": "Send SMS",
                        "security": [],  # explicitly unauthenticated
                    }
                }
            }
        )
        findings = analyze_openapi(spec)
        rc012 = [f for f in findings if f.rule_id == "RC-012"]
        assert rc012, "Empty security list means no protection"


# ===========================================================================
# Enrichment — x-security-analysis extension
# ===========================================================================


class TestEnrichment:
    def test_enrichment_adds_x_security_analysis(self):
        spec = _openapi3(
            {
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
            }
        )
        findings = analyze_openapi(spec, enrich_spec=True)
        assert findings  # at least RC-010
        # Check spec was enriched
        op = spec["paths"]["/users"]["get"]
        assert "x-security-analysis" in op, "x-security-analysis not added to spec"
        api4 = op["x-security-analysis"]["api4_findings"]
        assert isinstance(api4, list) and len(api4) > 0
        assert api4[0]["rule_id"] == "RC-010"

    def test_enrichment_does_not_overwrite_existing_fields(self):
        spec = _openapi3(
            {
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
            }
        )
        analyze_openapi(spec, enrich_spec=True)
        op = spec["paths"]["/users"]["get"]
        # Should have appended, not replaced
        api4 = op["x-security-analysis"]["api4_findings"]
        rule_ids = {e["rule_id"] for e in api4}
        assert "EXISTING" in rule_ids, "Existing entry was overwritten"
        assert op["summary"] == "Get users", "Non-x- field was modified"

    def test_enrichment_false_does_not_modify_spec(self):
        spec = _openapi3(
            {
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
            }
        )
        spec_copy = copy.deepcopy(spec)
        analyze_openapi(spec, enrich_spec=False)
        assert spec == spec_copy, "Spec was modified when enrich_spec=False"

    def test_findings_still_returned_with_enrichment(self):
        spec = _openapi3({"/sms/send": {"post": {"summary": "Send SMS"}}})
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
        assert any(f.rule_id == "RC-010" for f in findings), (
            "Analysis should proceed even without a recognized version key"
        )

    def test_malformed_parameter_list_no_crash(self):
        spec = _openapi3(
            {
                "/broken": {
                    "get": {
                        "parameters": "not_a_list"  # deliberately broken
                    }
                }
            }
        )
        findings = analyze_openapi(spec)
        assert isinstance(findings, list)

    def test_all_findings_have_layer_openapi(self):
        spec = _openapi3(
            {
                "/users": {
                    "get": {
                        "parameters": [
                            {"name": "limit", "in": "query", "schema": {"type": "integer"}}
                        ]
                    }
                },
                "/sms/send": {"post": {"summary": "Send SMS"}},
            }
        )
        findings = analyze_openapi(spec)
        assert all(f.layer == "openapi" for f in findings)

    def test_all_findings_have_endpoint(self):
        spec = _openapi3(
            {
                "/users": {
                    "get": {
                        "parameters": [
                            {"name": "limit", "in": "query", "schema": {"type": "integer"}}
                        ]
                    }
                }
            }
        )
        findings = analyze_openapi(spec)
        rc010 = [f for f in findings if f.rule_id == "RC-010"]
        assert all(f.endpoint for f in rc010)


# ===========================================================================
# Integration — multi-rule spec
# ===========================================================================


class TestMultiRuleSpec:
    def test_all_three_rules_on_one_spec(self):
        spec = _openapi3(
            {
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
                                        },
                                    }
                                }
                            }
                        }
                    }
                },
                "/sms/send": {"post": {"summary": "Send SMS"}},
            }
        )
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
                                        },
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


# ===========================================================================
# RC-013 — Batch / Array payload without maxItems
# ===========================================================================


class TestRC013BatchPayload:
    # --- TRUE POSITIVE: Top-level array without maxItems ---
    def test_tp_json_top_level_array_no_max_items(self):
        spec = _openapi3(
            {
                "/batch-items": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {"type": "string"},
                                    }
                                }
                            }
                        }
                    }
                }
            }
        )
        findings = analyze_openapi(spec)
        rc013 = [f for f in findings if f.rule_id == "RC-013"]
        assert rc013, "Expected RC-013 for top-level array without maxItems"
        assert rc013[0].severity == "HIGH"  # 'batch' in path

    # --- TRUE POSITIVE: Object property array without maxItems ---
    def test_tp_json_property_array_no_max_items(self):
        spec = _openapi3(
            {
                "/bulk-create": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "items": {
                                                "type": "array",
                                                "items": {"type": "object"},
                                            }
                                        },
                                    }
                                }
                            }
                        }
                    }
                }
            }
        )
        findings = analyze_openapi(spec)
        rc013 = [f for f in findings if f.rule_id == "RC-013"]
        assert rc013, "Expected RC-013 for array property without maxItems"
        assert rc013[0].parameter == "items"

    # --- TRUE NEGATIVE: Array with maxItems set ---
    def test_tn_json_array_with_max_items(self):
        spec = _openapi3(
            {
                "/batch-items": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {"type": "string"},
                                        "maxItems": 50,
                                    }
                                }
                            }
                        }
                    }
                }
            }
        )
        findings = analyze_openapi(spec)
        rc013 = [f for f in findings if f.rule_id == "RC-013"]
        assert not rc013, "Expected no RC-013 when maxItems is specified"

    # --- TRUE NEGATIVE: Non-array JSON body ---
    def test_tn_json_non_array_body(self):
        spec = _openapi3(
            {
                "/users": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "username": {"type": "string"},
                                            "email": {"type": "string"},
                                        },
                                    }
                                }
                            }
                        }
                    }
                }
            }
        )
        findings = analyze_openapi(spec)
        rc013 = [f for f in findings if f.rule_id == "RC-013"]
        assert not rc013
