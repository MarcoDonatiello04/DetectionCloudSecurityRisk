import base64
import json
from unittest.mock import MagicMock, patch

import pytest

from src.core.api3_bopla.dynamic_tester import BOPLADynamicTester
from src.core.api3_bopla.models import (
    PropertyAuthorizationGraph,
    PropertyEvidence,
    PropertyInventory,
)


@pytest.fixture
def mock_inventory():
    return PropertyInventory.model_validate(
        {
            "User": {
                "properties": [
                    {"name": "id", "sources": ["openapi", "ast", "runtime"]},
                    {"name": "email", "sources": ["openapi", "ast"]},
                    {"name": "salary", "sources": ["ast", "runtime"]},
                    {"name": "role", "sources": ["ast"]},
                ]
            }
        }
    )


@pytest.fixture
def mock_evidences():
    return [
        PropertyEvidence(
            object_name="User",
            property="id",
            found_in_ast=True,
            found_in_openapi=True,
            found_runtime=True,
            read_endpoints=["GET /api/users/{id}"],
            write_endpoints=["PUT /api/users/{id}"],
            confidence=0.5,
        ),
        PropertyEvidence(
            object_name="User",
            property="salary",
            found_in_ast=True,
            found_runtime=True,
            found_in_openapi=False,
            read_endpoints=["GET /api/users/{id}"],
            write_endpoints=["PUT /api/users/{id}"],
            authorization_contexts=["if(current_user.is_admin)"],
            confidence=0.8,
        ),
        PropertyEvidence(
            object_name="User",
            property="role",
            found_in_ast=True,
            found_in_openapi=False,
            read_endpoints=[],
            write_endpoints=["PUT /api/users/{id}"],
            confidence=0.4,
        ),
    ]


@pytest.fixture
def mock_graph(mock_evidences):
    # Construct graph from evidences
    from src.core.api3_bopla.property_inference import (
        PropertyAuthorizationInferenceEngine,
    )

    return PropertyAuthorizationInferenceEngine.build_authorization_graph(mock_evidences)


@pytest.fixture
def mock_headers_matrix():
    # standard base64 encoded JWT payload mock helper
    # Header: {"alg": "HS256", "typ": "JWT"}
    # Payloads with different sub claims
    header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    payload_a = base64_encode_json({"sub": "user_a_uuid", "roles": ["user"]})
    payload_c = base64_encode_json({"sub": "admin_uuid", "roles": ["admin"]})

    token_a = f"{header}.{payload_a}.signature"
    token_c = f"{header}.{payload_c}.signature"

    return {
        "userA": {"Authorization": f"Bearer {token_a}"},
        "userB": {"Authorization": "Bearer invalid_token_fallback"},
        "userC": {"Authorization": f"Bearer {token_c}"},
        "anonymous": {},
    }


def base64_encode_json(d: dict) -> str:
    s = json.dumps(d)
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")


def test_jwt_sub_extraction(mock_headers_matrix):
    tester = BOPLADynamicTester(
        target_base_url="http://localhost:5000",
        inventory=PropertyInventory({}),
        evidences=[],
        graph=PropertyAuthorizationGraph(),
        headers_matrix=mock_headers_matrix,
    )
    # Check Alice UUID is extracted
    assert tester.uuid_alice == "user_a_uuid"
    # Check Admin UUID is extracted
    assert tester.uuid_charlie == "admin_uuid"
    # Check fallback for User B
    assert tester.uuid_bob == "f81d4fae-7dec-11d0-a765-00a0c91e6bfb"


def test_resolve_path(mock_headers_matrix):
    tester = BOPLADynamicTester(
        target_base_url="http://localhost:5000",
        inventory=PropertyInventory({}),
        evidences=[],
        graph=PropertyAuthorizationGraph(),
        headers_matrix=mock_headers_matrix,
    )
    assert tester._resolve_path("/api/users/{id}", "123") == "/api/users/123"
    assert tester._resolve_path("/api/orders/<userId>/items", "abc") == "/api/orders/abc/items"


@patch("requests.request")
def test_run_t01_exposure(
    mock_req, mock_inventory, mock_evidences, mock_graph, mock_headers_matrix
):
    # Mock GET response containing sensitive property 'salary'
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"id": 42, "email": "alice@test.com", "salary": 12000}'
    mock_resp.json.return_value = {"id": 42, "email": "alice@test.com", "salary": 12000}
    mock_req.return_value = mock_resp

    tester = BOPLADynamicTester(
        target_base_url="http://localhost:5000",
        inventory=mock_inventory,
        evidences=mock_evidences,
        graph=mock_graph,
        headers_matrix=mock_headers_matrix,
    )

    findings = tester.run_t01()

    # We expect one finding for 'salary' since it is returned in GET and has confidence >= 0.4
    assert len(findings) >= 1
    salary_finding = next(f for f in findings if f.property_name == "salary")
    assert salary_finding.test_id == "T01"
    assert salary_finding.verified is True
    assert "salary" in salary_finding.request or "/api/users/" in salary_finding.endpoint


@patch("requests.request")
def test_run_t02_unauthorized_modification(
    mock_req, mock_inventory, mock_evidences, mock_graph, mock_headers_matrix
):
    # Dynamic side_effect function to handle any sequence of calls
    def mock_side_effect(method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if method == "GET":
            resp.text = '{"id": 42, "salary": 999999}'
            resp.json.return_value = {"id": 42, "salary": 999999}
        else:
            resp.text = '{"status": "success"}'
            resp.json.return_value = {"status": "success"}
        return resp

    mock_req.side_effect = mock_side_effect

    tester = BOPLADynamicTester(
        target_base_url="http://localhost:5000",
        inventory=mock_inventory,
        evidences=mock_evidences,
        graph=mock_graph,
        headers_matrix=mock_headers_matrix,
    )

    findings = tester.run_t02()
    assert len(findings) >= 1
    salary_finding = next(f for f in findings if f.property_name == "salary")
    assert salary_finding.test_id == "T02"
    assert salary_finding.verified is True


@patch("requests.request")
def test_run_t03_mass_assignment(
    mock_req, mock_inventory, mock_evidences, mock_graph, mock_headers_matrix
):
    # Mock PUT/PATCH accepting modification
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"id": 42, "salary": 99999}'
    mock_resp.json.return_value = {"id": 42, "salary": 99999}
    mock_req.return_value = mock_resp

    tester = BOPLADynamicTester(
        target_base_url="http://localhost:5000",
        inventory=mock_inventory,
        evidences=mock_evidences,
        graph=mock_graph,
        headers_matrix=mock_headers_matrix,
    )

    findings = tester.run_t03()
    assert len(findings) >= 1
    salary_finding = next(f for f in findings if f.property_name == "salary")
    assert salary_finding.test_id == "T03"
    assert salary_finding.verified is True


@patch("requests.request")
def test_run_t04_hidden_injection(
    mock_req, mock_inventory, mock_evidences, mock_graph, mock_headers_matrix
):
    # salary is in AST/Runtime but not in OpenAPI (found_in_openapi = False)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"id": 42, "salary": 88888}'
    mock_resp.json.return_value = {"id": 42, "salary": 88888}
    mock_req.return_value = mock_resp

    tester = BOPLADynamicTester(
        target_base_url="http://localhost:5000",
        inventory=mock_inventory,
        evidences=mock_evidences,
        graph=mock_graph,
        headers_matrix=mock_headers_matrix,
    )

    findings = tester.run_t04()
    assert len(findings) >= 1
    salary_finding = next(f for f in findings if f.property_name == "salary")
    assert salary_finding.test_id == "T04"
    assert salary_finding.verified is True


def _stateful_server(accept_user_writes: bool = True, admin_only: set[str] | None = None):
    """
    In-memory resource: PUT/PATCH/POST merge the body into the state (mass assignment) unless
    the caller is the standard user and `accept_user_writes` is False, in which case the fields
    are silently ignored with a 200 (the case a status-only check would misreport).
    Properties in `admin_only` are removed from the standard user's GET.
    """
    state = {"id": 42, "email": "alice@test.com", "salary": 12000, "role": "user"}
    admin_only = admin_only or set()

    def side_effect(method, url, **kwargs):
        is_admin = "admin_uuid" in json.dumps(kwargs.get("headers", {})) or _is_admin_token(
            kwargs.get("headers", {})
        )
        resp = MagicMock()
        resp.status_code = 200
        if method == "GET":
            body = dict(state)
            if not is_admin:
                for prop in admin_only:
                    body.pop(prop, None)
        else:
            if is_admin or accept_user_writes:
                state.update(kwargs.get("json") or {})
            body = {"status": "success"}
        resp.text = json.dumps(body)
        resp.json.return_value = body
        return resp

    return side_effect


def _is_admin_token(headers: dict) -> bool:
    token = headers.get("Authorization", "").split(" ")[-1]
    parts = token.split(".")
    if len(parts) < 2:
        return False
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    return payload.get("sub") == "admin_uuid"


@patch("requests.request")
def test_write_accepted_but_not_persisted_is_not_a_finding(
    mock_req, mock_inventory, mock_evidences, mock_graph, mock_headers_matrix
):
    mock_req.side_effect = _stateful_server(accept_user_writes=False)
    tester = BOPLADynamicTester(
        target_base_url="http://localhost:5000",
        inventory=mock_inventory,
        evidences=mock_evidences,
        graph=mock_graph,
        headers_matrix=mock_headers_matrix,
    )
    for run in (tester.run_t02, tester.run_t03, tester.run_t04, tester.run_t05):
        assert [f for f in run() if f.verified] == []


@patch("requests.request")
def test_ordinary_field_without_authorization_context_is_not_tested(
    mock_req, mock_inventory, mock_evidences, mock_graph, mock_headers_matrix
):
    # 'id' has confidence 0.5 but no authorization context: it is returned to the user as
    # expected and must not be reported as an exposed protected property.
    mock_req.side_effect = _stateful_server()
    tester = BOPLADynamicTester(
        target_base_url="http://localhost:5000",
        inventory=mock_inventory,
        evidences=mock_evidences,
        graph=mock_graph,
        headers_matrix=mock_headers_matrix,
    )
    assert "id" not in {f.property_name for f in tester.run_t01()}


@patch("requests.request")
def test_run_t05_read_write_mismatch(
    mock_req, mock_inventory, mock_evidences, mock_graph, mock_headers_matrix
):
    # role has write_endpoints but no read_endpoints; the write is persisted
    mock_req.side_effect = _stateful_server()

    tester = BOPLADynamicTester(
        target_base_url="http://localhost:5000",
        inventory=mock_inventory,
        evidences=mock_evidences,
        graph=mock_graph,
        headers_matrix=mock_headers_matrix,
    )

    findings = tester.run_t05()
    role_finding = next(f for f in findings if f.property_name == "role")
    assert role_finding.test_id == "T05"
    assert role_finding.verified is True


@patch("requests.request")
def test_run_t06_protected_property_visible_to_user(
    mock_req, mock_inventory, mock_evidences, mock_graph, mock_headers_matrix
):
    mock_req.side_effect = _stateful_server()
    tester = BOPLADynamicTester(
        target_base_url="http://localhost:5000",
        inventory=mock_inventory,
        evidences=mock_evidences,
        graph=mock_graph,
        headers_matrix=mock_headers_matrix,
    )

    findings = tester.run_t06()
    diff_finding = next(f for f in findings if f.property_name == "salary")
    assert diff_finding.test_id == "T06"
    assert diff_finding.verified is True


@patch("requests.request")
def test_run_t06_admin_only_visibility_is_the_expected_outcome(
    mock_req, mock_inventory, mock_evidences, mock_graph, mock_headers_matrix
):
    mock_req.side_effect = _stateful_server(admin_only={"salary"})
    tester = BOPLADynamicTester(
        target_base_url="http://localhost:5000",
        inventory=mock_inventory,
        evidences=mock_evidences,
        graph=mock_graph,
        headers_matrix=mock_headers_matrix,
    )

    findings = tester.run_t06()
    salary = next(f for f in findings if f.property_name == "salary")
    assert salary.verified is False
    assert not [f for f in findings if f.verified]


@patch("requests.request")
def test_run_t07_differential_update(
    mock_req, mock_inventory, mock_evidences, mock_graph, mock_headers_matrix
):
    mock_req.side_effect = _stateful_server()

    tester = BOPLADynamicTester(
        target_base_url="http://localhost:5000",
        inventory=mock_inventory,
        evidences=mock_evidences,
        graph=mock_graph,
        headers_matrix=mock_headers_matrix,
    )

    findings = tester.run_t07()
    salary_vun = next(f for f in findings if f.verified and f.property_name == "salary")
    assert salary_vun.test_id == "T07"


@patch("requests.request")
def test_run_t07_user_write_ignored_is_protected(
    mock_req, mock_inventory, mock_evidences, mock_graph, mock_headers_matrix
):
    mock_req.side_effect = _stateful_server(accept_user_writes=False)

    tester = BOPLADynamicTester(
        target_base_url="http://localhost:5000",
        inventory=mock_inventory,
        evidences=mock_evidences,
        graph=mock_graph,
        headers_matrix=mock_headers_matrix,
    )

    findings = tester.run_t07()
    salary = next(f for f in findings if f.property_name == "salary")
    assert salary.verified is False
