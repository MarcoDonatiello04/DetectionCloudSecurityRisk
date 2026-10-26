"""
Static BOPLA findings S02–S04 and their correlation with the dynamic phase
(src/core/api3_bopla/static_rules.py), plus the dashboard view of the report.
"""

import json
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from src.core.api2_broken_auth.discovery import Config
from src.core.api3_bopla.models import DynamicPropertyFinding, PropertyEvidence
from src.core.api3_bopla.orchestrator import BOPLAOrchestrator, to_dashboard_items
from src.core.api3_bopla.static_rules import (
    correlate_with_dynamic,
    scan_contract,
    scan_excessive_exposure,
    scan_undocumented,
)
from tests.integration.api3_bopla.test_bopla_ground_truth import (
    HEADERS_MATRIX,
    TWINS_DIR,
    _load_app,
    _route_to,
)

PROTECTED = [
    PropertyEvidence(
        object_name="User",
        property=prop,
        found_in_ast=True,
        authorization_contexts=["@roles_required('admin')"],
        confidence=0.4,
    )
    for prop in ("role", "salary")
]


def _exposures(tmp_path: Path, name: str, source: str):
    (tmp_path / name).write_text(textwrap.dedent(source), encoding="utf-8")
    return scan_excessive_exposure(str(tmp_path), PROTECTED)


# ---------------------------------------------------------------------------
# BOPLA-S02 — excessive exposure
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "source",
    [
        # whole object, ownership check only: the owner still reads protected fields
        """
        def get_user(current_user, user_id):
            user = DB.get(user_id)
            if current_user.id != user.id and current_user.role != "admin":
                return 403, {}
            return 200, dict(vars(user))
        """,
        """
        @app.get("/users/<id>")
        def get_user(id):
            user = User.query.get(id)
            return jsonify(user.to_dict())
        """,
        """
        def get_user(id):
            user = User.query.get(id)
            return user.__dict__
        """,
    ],
)
def test_whole_serialization_reported(tmp_path: Path, source: str):
    findings = _exposures(tmp_path, "app.py", source)
    assert len(findings) == 1, findings
    assert findings[0].rule_id == "BOPLA-S02"
    assert findings[0].entity == "User"
    assert findings[0].properties_at_risk == ["role", "salary"]


@pytest.mark.parametrize(
    "source",
    [
        # field selection
        """
        def get_user(id):
            user = User.query.get(id)
            return {"id": user.id, "name": user.name}
        """,
        # whole object only for administrators
        """
        def get_user(current_user, id):
            user = User.query.get(id)
            if current_user.role == "admin":
                return vars(user)
            return {"name": user.name}
        """,
        # role guard with early exit
        """
        def get_user(current_user, id):
            if current_user.role != "admin":
                abort(403)
            user = User.query.get(id)
            return user.to_dict()
        """,
        # function reserved to a role
        """
        @roles_required("admin")
        def get_user(id):
            user = User.query.get(id)
            return user.to_dict()
        """,
        # entity without protected properties
        """
        def get_project(id):
            project = Project.query.get(id)
            return project.to_dict()
        """,
    ],
)
def test_protected_or_selected_serialization_not_reported(tmp_path: Path, source: str):
    assert _exposures(tmp_path, "app.py", source) == []


def test_js_whole_document_sent(tmp_path: Path):
    source = """
    router.get('/users/:id', async (req, res) => {
      const user = await User.findById(req.params.id);
      res.json(user);
    });
    """
    findings = _exposures(tmp_path, "routes.js", source)
    assert [(f.entity, f.language) for f in findings] == [("User", "javascript")]


def test_no_protected_properties_no_exposure_scan(tmp_path: Path):
    (tmp_path / "app.py").write_text("def f():\n    u = User()\n    return vars(u)\n")
    assert scan_excessive_exposure(str(tmp_path), []) == []


# ---------------------------------------------------------------------------
# BOPLA-S03 — contract inconsistencies
# ---------------------------------------------------------------------------


def _spec(paths: dict, schemas: dict | None = None) -> dict:
    return {"openapi": "3.0.0", "paths": paths, "components": {"schemas": schemas or {}}}


def _json(schema: dict) -> dict:
    return {"content": {"application/json": {"schema": schema}}}


def test_readonly_accepted_by_another_request_schema():
    spec = _spec(
        {
            "/users/{id}": {
                "get": {"responses": {"200": _json({"$ref": "#/components/schemas/User"})}},
                "patch": {
                    "requestBody": _json(
                        {"type": "object", "properties": {"role": {"type": "string"}}}
                    )
                },
            }
        },
        {"User": {"type": "object", "properties": {"role": {"type": "string", "readOnly": True}}}},
    )
    findings = scan_contract(spec)
    assert [(f.kind, f.entity, f.properties_at_risk) for f in findings] == [
        ("readonly_writable", "User", ["role"])
    ]


def test_writeonly_returned_by_a_response():
    spec = _spec(
        {
            "/users": {
                "post": {
                    "requestBody": _json(
                        {"type": "object", "properties": {"password": {"writeOnly": True}}}
                    )
                }
            },
            "/users/{id}": {
                "get": {
                    "responses": {"200": _json({"type": "object", "properties": {"password": {}}})}
                }
            },
        }
    )
    assert [f.kind for f in scan_contract(spec)] == ["writeonly_readable"]


def test_same_schema_with_readonly_is_consistent():
    schema = {"$ref": "#/components/schemas/User"}
    spec = _spec(
        {
            "/users/{id}": {
                "get": {"responses": {"200": _json(schema)}},
                "put": {"requestBody": _json(schema)},
            }
        },
        {"User": {"type": "object", "properties": {"role": {"readOnly": True}}}},
    )
    assert scan_contract(spec) == []


# ---------------------------------------------------------------------------
# BOPLA-S04 — protected property outside the contract
# ---------------------------------------------------------------------------


def test_undocumented_only_for_protected_properties():
    issue = ["Property observed at runtime but absent from API specification."]
    protected = PROTECTED[0].model_copy(update={"documentation_issues": issue})
    ordinary = PropertyEvidence(object_name="User", property="nickname", documentation_issues=issue)
    findings = scan_undocumented([protected, ordinary])
    assert [(f.rule_id, f.properties_at_risk) for f in findings] == [("BOPLA-S04", ["role"])]


# ---------------------------------------------------------------------------
# Correlation with the dynamic phase
# ---------------------------------------------------------------------------


def _dynamic(test_id: str, prop: str, verified: bool) -> DynamicPropertyFinding:
    return DynamicPropertyFinding(
        test_id=test_id,
        endpoint="/api/users/{id}",
        method="PUT",
        property_name=prop,
        request={},
        response={},
        verified=verified,
        confidence=0.4,
    )


def test_correlation_uses_direction_and_property(tmp_path: Path):
    source = "def update(user, body):\n    for k, v in body.items():\n        setattr(user, k, v)\n"
    (tmp_path / "app.py").write_text(source)
    from src.core.api3_bopla.mass_assignment import scan_mass_assignment

    write = scan_mass_assignment(str(tmp_path), PROTECTED)
    correlate_with_dynamic(write, [_dynamic("T01", "role", True)])  # read test: wrong direction
    assert write[0].status == "unverified" and not write[0].verified

    correlate_with_dynamic(write, [_dynamic("T03", "role", True)])
    assert write[0].status == "confirmed" and write[0].verified
    assert write[0].confirmed_by == ["T03:role"] and write[0].severity == "CRITICAL"


def test_tested_and_held_is_not_confirmed(tmp_path: Path):
    source = "def update(user, body):\n    for k, v in body.items():\n        setattr(user, k, v)\n"
    (tmp_path / "app.py").write_text(source)
    from src.core.api3_bopla.mass_assignment import scan_mass_assignment

    findings = scan_mass_assignment(str(tmp_path), PROTECTED)
    correlate_with_dynamic(findings, [_dynamic("T07", "salary", False)])
    assert findings[0].status == "not_confirmed" and not findings[0].verified


def _run_twin(variant: str, tmp_path: Path, with_identities: bool) -> dict:
    app = _load_app(variant)
    config = Config()
    config.output.path = str(tmp_path)
    with patch("requests.request", side_effect=_route_to(app)):
        return BOPLAOrchestrator(config).run_assessment(
            repo_path=str(TWINS_DIR / variant),
            openapi_spec=json.loads((TWINS_DIR / "openapi.json").read_text()),
            runtime_traffic=json.loads((TWINS_DIR / "client_traffic.json").read_text()),
            headers_matrix=HEADERS_MATRIX if with_identities else None,
        )


def test_twins_static_findings_confirmed_by_dynamic_phase(tmp_path: Path):
    vulnerable = _run_twin("vulnerable_app", tmp_path, with_identities=True)
    by_rule = {f["rule_id"]: f for f in vulnerable["static_findings"]}
    assert by_rule["BOPLA-S01"]["status"] == "confirmed"
    assert any(c.split(":")[0] in {"T02", "T03"} for c in by_rule["BOPLA-S01"]["confirmed_by"])
    assert by_rule["BOPLA-S02"]["status"] == "confirmed"
    assert {c.split(":")[0] for c in by_rule["BOPLA-S02"]["confirmed_by"]} <= {"T01", "T06"}
    assert vulnerable["static_findings_confirmed"] == len(vulnerable["static_findings"])

    secure = _run_twin("secure_app", tmp_path, with_identities=True)
    assert {f["rule_id"] for f in secure["static_findings"]} == {"BOPLA-S04"}
    # role travels outside the contract, but the dynamic tests show it is protected
    assert secure["static_findings"][0]["status"] == "not_confirmed"
    assert secure["static_findings_confirmed"] == 0


def test_dashboard_items_without_dynamic_phase(tmp_path: Path):
    report = _run_twin("vulnerable_app", tmp_path, with_identities=False)
    items = to_dashboard_items(report)
    assert {i["rule_id"] for i in items} == {"BOPLA-S01", "BOPLA-S02", "BOPLA-S04"}
    assert all(i["category"] == "Statica — da verificare" for i in items)
    assert all(i["title"] and i["severity"] for i in items)


def test_dashboard_items_with_dynamic_phase(tmp_path: Path):
    report = _run_twin("vulnerable_app", tmp_path, with_identities=True)
    items = to_dashboard_items(report)
    dynamic = [i for i in items if i.get("test_id")]
    static = [i for i in items if i.get("rule_id")]
    assert dynamic and all(i["verified"] for i in dynamic)
    assert all(i["category"] == "Statica — confermata dinamicamente" for i in static)


def test_unreachable_target_is_not_a_dynamic_phase(tmp_path: Path):
    """Identities but no test outcome (target down): the score must not look verified."""
    config = Config()
    config.output.path = str(tmp_path)
    with patch("requests.request", side_effect=ConnectionError("target down")):
        report = BOPLAOrchestrator(config).run_assessment(
            repo_path=str(TWINS_DIR / "vulnerable_app"),
            openapi_spec=json.loads((TWINS_DIR / "openapi.json").read_text()),
            runtime_traffic=json.loads((TWINS_DIR / "client_traffic.json").read_text()),
            headers_matrix=HEADERS_MATRIX,
        )
    assert report["dynamic_phase_executed"] is False
    assert all(f["status"] == "unverified" for f in report["static_findings"])
