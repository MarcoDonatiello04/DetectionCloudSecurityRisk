"""
Contract reading, object identity and nested properties (B.6, B.9, B.11).

The module is never told which properties are protected: it uses only what the contract of
the application declares (`$ref` of each operation, readOnly/writeOnly) and what the traffic
shows, attributing each property to the object that really owns it.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.core.api3_bopla import contract
from src.core.api3_bopla.discovery import PropertyDiscoveryEngine as Discovery
from src.core.api3_bopla.dynamic_tester import BOPLADynamicTester
from src.core.api3_bopla.models import PropertyEvidence, PropertyInventory
from src.core.api3_bopla.property_inference import PropertyAuthorizationInferenceEngine as Engine
from src.core.api3_bopla.static_rules import scan_contract


def _json(schema: dict) -> dict:
    return {"content": {"application/json": {"schema": schema}}}


def _ref(name: str) -> dict:
    return {"$ref": f"#/components/schemas/{name}"}


def _spec(paths: dict, schemas: dict | None = None) -> dict:
    return {"openapi": "3.0.0", "paths": paths, "components": {"schemas": schemas or {}}}


EMPLOYEE = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "salary": {"type": "number", "readOnly": True},
        "password": {"type": "string", "writeOnly": True},
        "address": {"type": "object", "properties": {"city": {"type": "string"}}},
    },
}

STAFF_SPEC = _spec(
    {
        "/staff/{id}": {
            "get": {"responses": {"200": _json(_ref("Employee"))}},
            "patch": {
                "requestBody": _json(_ref("Employee")),
                "responses": {"200": _json(_ref("Employee"))},
            },
        }
    },
    {"Employee": EMPLOYEE},
)


def _evidences(tmp_path: Path, spec: dict | None = None, traffic: list | None = None):
    inventory = Discovery.discover_properties(str(tmp_path), spec, traffic)
    evidences = Engine.run_inference(str(tmp_path), inventory, spec, traffic)
    return inventory, {(e.object_name, e.property): e for e in evidences}


# ---------------------------------------------------------------------------
# B.6 — operations associated with their schema
# ---------------------------------------------------------------------------


def test_operation_reads_and_writes_the_referenced_schema(tmp_path: Path):
    inventory, evidences = _evidences(tmp_path, STAFF_SPEC)
    assert "Employee" in inventory.root
    assert "Staff" not in inventory.root
    name = evidences[("Employee", "name")]
    assert name.read_endpoints == ["GET /staff/{id}"]
    assert name.write_endpoints == ["PATCH /staff/{id}"]


def test_readonly_is_a_write_authorization_context(tmp_path: Path):
    _, evidences = _evidences(tmp_path, STAFF_SPEC)
    salary = evidences[("Employee", "salary")]
    assert salary.contract_flags == ["readOnly"]
    assert "contract(readOnly)" in salary.authorization_contexts
    assert Engine.is_protected_property(salary)
    assert Engine.is_protected_property(salary, direction="write")
    # a readOnly value is legitimately returned: not a read restriction
    assert not Engine.is_protected_property(salary, direction="read")
    # an ordinary property of the same schema stays unprotected
    assert not Engine.is_protected_property(evidences[("Employee", "name")])


def test_writeonly_is_a_read_authorization_context(tmp_path: Path):
    _, evidences = _evidences(tmp_path, STAFF_SPEC)
    password = evidences[("Employee", "password")]
    assert "contract(writeOnly)" in password.authorization_contexts
    assert Engine.is_protected_property(password, direction="read")
    assert not Engine.is_protected_property(password, direction="write")


def test_nested_contract_properties_are_dotted(tmp_path: Path):
    inventory, _ = _evidences(tmp_path, STAFF_SPEC)
    props = {p.name for p in inventory.root["Employee"].properties}
    assert {"address", "address.city"} <= props
    assert "city" not in props


def test_allof_merges_the_parts_and_names_the_object():
    spec = _spec(
        {
            "/managers/{id}": {
                "get": {
                    "responses": {
                        "200": _json(
                            {
                                "allOf": [
                                    _ref("Person"),
                                    {"properties": {"budget": {"type": "number"}}},
                                ]
                            }
                        )
                    }
                }
            }
        },
        {"Person": {"type": "object", "properties": {"name": {"type": "string"}}}},
    )
    (operation,) = contract.iter_operations(spec)
    assert operation.response_objects() == [
        ("Person", {"name": contract._flags({}, {}), "budget": contract._flags({}, {})})
    ]


def test_oneof_and_arrays_describe_each_object():
    schemas = {
        "Cat": {"type": "object", "properties": {"meows": {"type": "boolean"}}},
        "Dog": {"type": "object", "properties": {"barks": {"type": "boolean"}}},
    }
    schema = {"type": "array", "items": {"oneOf": [_ref("Cat"), _ref("Dog")]}}
    objects = contract.schema_objects(schema, _spec({}, schemas))
    assert [(name, sorted(props)) for name, props in objects] == [
        ("Cat", ["meows"]),
        ("Dog", ["barks"]),
    ]


def test_recursive_schema_terminates():
    schemas = {
        "Node": {
            "type": "object",
            "properties": {"value": {"type": "string"}, "parent": _ref("Node")},
        }
    }
    props = contract.schema_properties(_ref("Node"), _spec({}, schemas))
    assert set(props) == {"value", "parent"}


def test_scan_contract_follows_allof_and_the_operation_schema():
    spec = _spec(
        {
            "/staff/{id}": {
                "get": {"responses": {"200": _json(_ref("Employee"))}},
                "patch": {
                    "requestBody": _json(
                        {"allOf": [{"properties": {"salary": {"type": "number"}}}]}
                    ),
                    "responses": {"200": _json(_ref("Employee"))},
                },
            }
        },
        {"Employee": EMPLOYEE},
    )
    findings = scan_contract(spec)
    assert [(f.kind, f.entity, f.properties_at_risk) for f in findings] == [
        ("readonly_writable", "Employee", ["salary"])
    ]


# ---------------------------------------------------------------------------
# B.9 — canonical object names
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path,expected",
    [
        ("/status", "Status"),
        ("/api/v1/news", "News"),
        ("/people/{id}", "Person"),
        ("/categories", "Category"),
        ("/addresses/{id}", "Address"),
        ("/workshop/api/shop/apply_coupon", "ApplyCoupon"),
        ("/identity/api/v2/user/change-email", "ChangeEmail"),
        ("/posts/{id}/comments", "Comment"),
        ("/users/me", "User"),
    ],
)
def test_object_name_from_path_is_canonical(path: str, expected: str):
    assert Discovery.get_object_name_from_path(path) == expected


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("ApplyCouponRequest", "ApplyCoupon"),
        ("Apply_coupon", "ApplyCoupon"),
        ("apply-coupon", "ApplyCoupon"),
        ("Comments", "Comment"),
        ("CRAPIConfig", "CRAPIConfig"),
        ("Status", "Status"),
    ],
)
def test_clean_object_name_is_canonical(raw: str, expected: str):
    assert Discovery.clean_object_name(raw) == expected


def test_code_contract_and_path_share_the_same_object(tmp_path: Path):
    (tmp_path / "models.py").write_text(
        "class Apply_coupon:\n    coupon_code: str\n", encoding="utf-8"
    )
    spec = _spec(
        {
            "/shop/apply_coupon": {
                "post": {"requestBody": _json({"properties": {"amount": {"type": "number"}}})}
            }
        },
        {"ApplyCouponRequest": {"properties": {"coupon_code": {"type": "string"}}}},
    )
    inventory, _ = _evidences(tmp_path, spec)
    assert set(inventory.root) == {"ApplyCoupon"}
    props = {p.name: p.sources for p in inventory.root["ApplyCoupon"].properties}
    assert props == {"coupon_code": ["ast", "openapi"], "amount": ["openapi"]}


def test_me_reads_the_object_of_its_response_schema(tmp_path: Path):
    user = {"type": "object", "properties": {"email": {"type": "string"}}}
    spec = _spec({"/api/me": {"get": {"responses": {"200": _json(_ref("User"))}}}}, {"User": user})
    traffic = [{"method": "GET", "path": "/api/me", "response_body": {"email": "a@b.c", "x": 1}}]
    inventory, evidences = _evidences(tmp_path, spec, traffic)
    assert set(inventory.root) == {"User"}
    assert evidences[("User", "email")].read_endpoints == ["GET /api/me"]
    assert evidences[("User", "x")].found_runtime


def test_me_without_schema_keeps_the_path_object():
    traffic = [{"method": "GET", "path": "/api/me", "response_body": {"email": "a@b.c"}}]
    assert Discovery.extract_runtime_properties(traffic) == {"Me": {"email"}}


# ---------------------------------------------------------------------------
# B.11 — nested objects are not flattened
# ---------------------------------------------------------------------------


def test_traffic_keeps_nested_properties_dotted(tmp_path: Path):
    traffic = [
        {
            "method": "GET",
            "path": "/users/1",
            "response_body": {
                "name": "Ann",
                "manager": {"name": "Bob", "salary": 9000},
                "teams": [{"title": "core"}],
            },
        }
    ]
    inventory, evidences = _evidences(tmp_path, None, traffic)
    props = {p.name for p in inventory.root["User"].properties}
    assert props == {"name", "manager", "manager.name", "manager.salary", "teams", "teams.title"}
    assert "salary" not in props
    assert evidences[("User", "manager.salary")].read_endpoints == ["GET /users/{id}"]


def test_dynamic_tester_never_sends_dotted_keys():
    evidences = [
        PropertyEvidence(
            object_name="User",
            property="manager.salary",
            found_in_ast=True,
            found_runtime=True,
            read_endpoints=["GET /users/{id}"],
            write_endpoints=["PUT /users/{id}"],
            authorization_contexts=["if(current_user.is_admin)"],
            confidence=0.9,
        ),
        PropertyEvidence(
            object_name="User",
            property="salary",
            found_in_openapi=True,
            read_endpoints=["GET /users/{id}"],
            write_endpoints=["PUT /users/{id}"],
            authorization_contexts=["contract(readOnly)"],
            contract_flags=["readOnly"],
            confidence=0.5,
        ),
    ]
    inventory = PropertyInventory.model_validate(
        {"User": {"properties": [{"name": "salary", "sources": ["openapi"]}]}}
    )
    tester = BOPLADynamicTester(
        "http://target",
        inventory,
        evidences,
        Engine.build_authorization_graph(evidences),
        {"userA": {"Authorization": "Bearer a"}, "userC": {"Authorization": "Bearer c"}},
    )
    sent: list[tuple[str, dict | None]] = []

    def fake_request(method, url, **kwargs):
        sent.append((method, kwargs.get("json")))
        response = MagicMock(status_code=200, text="{}")
        # the readOnly value is returned, as the contract allows
        response.json.return_value = {"name": "Ann", "salary": 1}
        return response

    with patch("src.core.api3_bopla.dynamic_tester.requests.request", side_effect=fake_request):
        findings = tester.run_all_tests()

    payloads = [body for _method, body in sent if body]
    assert payloads, "the readOnly property must be tried in writing"
    assert all("." not in key for body in payloads for key in body)
    assert all(f.property_name != "manager.salary" for f in findings)
    # a readOnly property returned in a read is not an exposure
    assert not [f for f in findings if f.test_id in ("T01", "T06") and f.verified]


def test_inline_request_is_not_given_to_a_generic_envelope():
    spec = _spec(
        {
            "/user/change-email": {
                "post": {
                    "requestBody": _json({"properties": {"new_email": {"type": "string"}}}),
                    "responses": {"200": _json(_ref("CRAPIResponse"))},
                }
            }
        },
        {"CRAPIResponse": {"properties": {"message": {"type": "string"}}}},
    )
    (operation,) = contract.iter_operations(spec)
    assert [name for name, _ in operation.request_objects()] == ["ChangeEmail"]
    assert [name for name, _ in operation.response_objects()] == ["CRAPI"]
