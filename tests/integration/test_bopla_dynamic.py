import base64
import json
from unittest.mock import MagicMock, patch

import pytest

from src.core.broken_object_property_level_access.dynamic_tester import BOPLADynamicTester
from src.core.broken_object_property_level_access.models import (
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
    from src.core.broken_object_property_level_access.property_inference import (
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


@patch("requests.request")
def test_run_t05_read_write_mismatch(
    mock_req, mock_inventory, mock_evidences, mock_graph, mock_headers_matrix
):
    # role has write_endpoints but empty read_endpoints
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"id": 42, "role": "admin"}'
    mock_resp.json.return_value = {"id": 42, "role": "admin"}
    mock_req.return_value = mock_resp

    tester = BOPLADynamicTester(
        target_base_url="http://localhost:5000",
        inventory=mock_inventory,
        evidences=mock_evidences,
        graph=mock_graph,
        headers_matrix=mock_headers_matrix,
    )

    findings = tester.run_t05()
    assert len(findings) >= 1
    role_finding = next(f for f in findings if f.property_name == "role")
    assert role_finding.test_id == "T05"
    assert role_finding.verified is True


@patch("requests.request")
def test_run_t06_differential_response(
    mock_req, mock_inventory, mock_evidences, mock_graph, mock_headers_matrix
):
    # Keep track of which call number this is to alternate responses
    calls = []

    def mock_side_effect(method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if not calls:
            # First call is User
            resp.text = '{"id": 42, "email": "alice@test.com"}'
            resp.json.return_value = {"id": 42, "email": "alice@test.com"}
            calls.append(1)
        else:
            # Second call is Admin
            resp.text = '{"id": 42, "email": "alice@test.com", "salary": 12000}'
            resp.json.return_value = {"id": 42, "email": "alice@test.com", "salary": 12000}
        return resp

    mock_req.side_effect = mock_side_effect

    tester = BOPLADynamicTester(
        target_base_url="http://localhost:5000",
        inventory=mock_inventory,
        evidences=mock_evidences,
        graph=mock_graph,
        headers_matrix=mock_headers_matrix,
    )

    findings = tester.run_t06()
    assert len(findings) >= 1
    diff_finding = next(f for f in findings if f.property_name == "salary")
    assert diff_finding.test_id == "T06"
    assert diff_finding.verified is True


@patch("requests.request")
def test_run_t07_differential_update(
    mock_req, mock_inventory, mock_evidences, mock_graph, mock_headers_matrix
):
    # Always succeed with 200 to simulate vulnerability
    def mock_side_effect(method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
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

    findings = tester.run_t07()
    vulnerable_findings = [f for f in findings if f.verified is True]
    assert len(vulnerable_findings) >= 1
    salary_vun = next(f for f in vulnerable_findings if f.property_name == "salary")
    assert salary_vun.test_id == "T07"
