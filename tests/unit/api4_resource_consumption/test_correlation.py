"""
Cross-layer correlation for API4 (src/core/api4_resource_consumption/correlation.py).

  - route resolution for code findings (Flask/FastAPI decorators, Express calls)
  - corroborated: same defect in code and contract on the same endpoint
  - compensated: body size limit enforced by configuration
  - derived: RC-006 in code proves the cost of a neutrally-named contract operation
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from src.core.api4_resource_consumption import detector
from src.core.api4_resource_consumption.correlation import resolve_route

FLASK_APP = textwrap.dedent(
    """
    from flask import Flask, request, jsonify
    from twilio.rest import Client

    app = Flask(__name__)
    twilio = Client("sid", "token")


    @app.get("/users")
    def list_users():
        limit = request.args.get("limit", 10, type=int)
        return jsonify(list(range(1000))[:limit])


    @app.post("/upload")
    def upload_file():
        file = request.files["file"]
        file.save(f"/tmp/{file.filename}")
        return "ok"


    @app.post("/batch-process")
    def batch():
        items = request.json["items"]
        for item in items:
            print(item)
        return "done"


    @app.route("/account/recovery", methods=["POST"])
    def recovery():
        phone = request.json["phone"]
        twilio.messages.create(to=phone, from_="+1", body="code")
        return "sent"
    """
)


def _spec(paths: dict) -> dict:
    return {"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": paths}


CONTRACT = _spec(
    {
        "/users": {
            "get": {"parameters": [{"name": "limit", "in": "query", "schema": {"type": "integer"}}]}
        },
        "/upload": {
            "post": {
                "requestBody": {
                    "content": {
                        "multipart/form-data": {
                            "schema": {
                                "type": "object",
                                "properties": {"file": {"type": "string", "format": "binary"}},
                            }
                        }
                    }
                }
            }
        },
        "/batch-process": {
            "post": {
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {"items": {"type": "array", "items": {}}},
                            }
                        }
                    }
                }
            }
        },
        # Neutral name: nothing in the contract says it is expensive
        "/account/recovery": {"post": {"summary": "Start account recovery"}},
    }
)


@pytest.fixture
def target(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(FLASK_APP, encoding="utf-8")
    return tmp_path


def _by_rule(report, rule_id: str):
    return [f for f in report.findings if f.rule_id == rule_id]


# ---------------------------------------------------------------------------
# Route resolution
# ---------------------------------------------------------------------------


class TestResolveRoute:
    def test_flask_shortcut_decorator(self, target: Path):
        path = str(target / "app.py")
        line = (
            FLASK_APP.splitlines().index('    limit = request.args.get("limit", 10, type=int)') + 1
        )
        assert resolve_route(path, line) == (frozenset({"GET"}), "/users")

    def test_flask_route_with_methods(self, target: Path):
        path = str(target / "app.py")
        line = FLASK_APP.splitlines().index('    phone = request.json["phone"]') + 1
        assert resolve_route(path, line) == (frozenset({"POST"}), "/account/recovery")

    def test_nested_helper_resolves_to_outer_handler(self, tmp_path: Path):
        source = textwrap.dedent(
            """
            @router.post("/jobs/{job_id}")
            async def run_job(job_id: str):
                def helper(items):
                    for item in items:
                        pass
                return helper([])
            """
        )
        f = tmp_path / "api.py"
        f.write_text(source, encoding="utf-8")
        line = next(i for i, text in enumerate(source.splitlines(), 1) if "for item" in text)
        assert resolve_route(str(f), line) == (frozenset({"POST"}), "/jobs/{job_id}")

    def test_module_level_code_has_no_route(self, target: Path):
        path = str(target / "app.py")
        assert (
            resolve_route(path, FLASK_APP.splitlines().index("app = Flask(__name__)") + 1) is None
        )

    def test_express_route(self, tmp_path: Path):
        source = "router.post('/api/files', (req, res) => {\n  const f = req.files.doc;\n});\n"
        f = tmp_path / "routes.js"
        f.write_text(source, encoding="utf-8")
        assert resolve_route(str(f), 2) == (frozenset({"POST"}), "/api/files")


# ---------------------------------------------------------------------------
# Correlation in the detector
# ---------------------------------------------------------------------------


class TestCorroboration:
    @pytest.mark.parametrize(
        "code_rule,contract_rule,endpoint",
        [
            ("RC-001", "RC-010", "GET /users"),
            ("RC-002", "RC-011", "POST /upload"),
            ("RC-005", "RC-013", "POST /batch-process"),
        ],
    )
    def test_same_defect_linked_across_layers(
        self, target: Path, code_rule: str, contract_rule: str, endpoint: str
    ):
        report = detector.analyze(str(target), CONTRACT)
        code = [f for f in _by_rule(report, code_rule) if f.endpoint == endpoint]
        contract = [f for f in _by_rule(report, contract_rule) if f.endpoint == endpoint]
        assert code and contract, f"{code_rule}/{contract_rule} missing on {endpoint}"
        assert contract[0].key in code[0].correlated_with
        assert code[0].key in contract[0].correlated_with
        assert code[0].correlation in {"corroborated", "compensated"}

    def test_corroboration_raises_confidence(self, target: Path):
        alone = detector.analyze(str(target))
        rc001_alone = next(f for f in _by_rule(alone, "RC-001"))
        report = detector.analyze(str(target), CONTRACT)
        rc001 = next(f for f in _by_rule(report, "RC-001"))
        assert rc001.confidence > rc001_alone.confidence

    def test_different_endpoint_not_linked(self, target: Path):
        spec = _spec(
            {
                "/orders": {
                    "get": {
                        "parameters": [
                            {"name": "limit", "in": "query", "schema": {"type": "integer"}}
                        ]
                    }
                }
            }
        )
        report = detector.analyze(str(target), spec)
        assert not next(f for f in _by_rule(report, "RC-010")).correlated_with

    def test_without_contract_code_findings_get_endpoint(self, target: Path):
        report = detector.analyze(str(target))
        assert next(f for f in _by_rule(report, "RC-001")).endpoint == "GET /users"


class TestCompensation:
    def test_upload_compensated_by_nginx_body_limit(self, target: Path):
        (target / "nginx.conf").write_text("http { client_max_body_size 10M; }\n")
        report = detector.analyze(str(target), CONTRACT)
        for rule in ("RC-002", "RC-011"):
            f = _by_rule(report, rule)[0]
            assert f.correlation == "compensated"
            assert f.severity == "INFO" and f.original_severity in {"HIGH", "MEDIUM"}
            assert "client_max_body_size 10M" in f.compensated_by
        assert report.summary["correlation"]["compensated"] == 2

    def test_env_max_content_length_compensates(self, target: Path):
        (target / ".env").write_text("MAX_CONTENT_LENGTH=16777216\n")
        report = detector.analyze(str(target))
        assert _by_rule(report, "RC-002")[0].correlation == "compensated"

    def test_oversized_limit_does_not_compensate(self, target: Path):
        (target / "nginx.conf").write_text("http { client_max_body_size 2G; }\n")
        report = detector.analyze(str(target))
        assert _by_rule(report, "RC-002")[0].severity != "INFO"

    def test_body_limit_does_not_compensate_other_rules(self, target: Path):
        (target / "nginx.conf").write_text("http { client_max_body_size 10M; }\n")
        report = detector.analyze(str(target), CONTRACT)
        assert all(f.severity != "INFO" for f in _by_rule(report, "RC-005"))


class TestDerivedExpensiveEndpoint:
    def test_paid_sdk_in_code_proves_cost_of_neutral_endpoint(self, target: Path):
        report = detector.analyze(str(target), CONTRACT)
        rc012 = [f for f in _by_rule(report, "RC-012") if f.endpoint == "POST /account/recovery"]
        assert rc012, "RC-006 in code should derive RC-012 on the contract operation"
        assert rc012[0].correlation == "derived"
        assert any(k.startswith("RC-006@") for k in rc012[0].correlated_with)
        assert any(c["type"] == "derived" for c in report.correlations)

    def test_no_derivation_when_contract_documents_protection(self, target: Path):
        spec = _spec({"/account/recovery": {"post": {"x-rate-limit": "5/hour"}}})
        report = detector.analyze(str(target), spec)
        assert not _by_rule(report, "RC-012")

    def test_no_duplicate_when_name_already_matched(self, target: Path):
        spec = _spec({"/account/recovery": {"post": {"summary": "Send OTP via SMS"}}})
        report = detector.analyze(str(target), spec)
        assert len(_by_rule(report, "RC-012")) == 1
