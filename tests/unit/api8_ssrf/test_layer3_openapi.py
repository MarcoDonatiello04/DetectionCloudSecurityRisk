from src.core.api8_ssrf.layers.layer3_openapi import analyze_openapi


def test_analyze_openapi_parameters():
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/api/v1/fetch": {
                "get": {
                    "parameters": [{"name": "url", "in": "query", "schema": {"type": "string"}}]
                }
            }
        },
    }

    findings = analyze_openapi(spec, enrich_spec=True)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "SS-006"
    assert finding.endpoint == "GET /api/v1/fetch"
    assert finding.source == "parameter 'url' in query"
    assert finding.validation_found is False
    assert finding.validation_type is None

    # Check enrichment in spec
    operation = spec["paths"]["/api/v1/fetch"]["get"]
    assert "x-security-analysis" in operation
    assert "api7_findings" in operation["x-security-analysis"]
    assert len(operation["x-security-analysis"]["api7_findings"]) == 1


def test_analyze_openapi_request_body():
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/api/v1/webhook": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"webhook_url": {"type": "string"}},
                                }
                            }
                        }
                    }
                }
            }
        },
    }

    findings = analyze_openapi(spec, enrich_spec=False)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "SS-006"
    assert finding.endpoint == "POST /api/v1/webhook"
    assert finding.source == "body property 'webhook_url'"
    assert finding.validation_found is False
    assert finding.validation_type is None
