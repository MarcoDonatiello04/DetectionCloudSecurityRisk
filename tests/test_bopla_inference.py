import pytest
import json
from pathlib import Path

from src.core.broken_object_property_level_access.models import PropertyInventory, PropertyEvidence, PropertyAuthorizationGraph
from src.core.broken_object_property_level_access.discovery import PropertyDiscoveryEngine
from src.core.broken_object_property_level_access.property_inference import PropertyAuthorizationInferenceEngine


def test_confidence_score_calculation():
    # Test 1: Full evidence (max score 1.0)
    ev1 = PropertyEvidence(
        object_name="User",
        property="salary",
        found_in_ast=True,          # +0.20
        found_in_openapi=True,      # +0.20
        found_runtime=True,         # +0.20
        read_endpoints=["GET /profile"],  # +0.10
        write_endpoints=["PATCH /profile"], # +0.10
        authorization_contexts=["@roles_required(admin)"], # +0.20
        cross_model_occurrences=["UserDTO", "UserEntity"], # +0.10
    )
    score1 = PropertyAuthorizationInferenceEngine.calculate_confidence(ev1)
    assert score1 == 1.0

    # Test 2: Minimal evidence (only AST and OpenAPI)
    ev2 = PropertyEvidence(
        object_name="User",
        property="email",
        found_in_ast=True,          # +0.20
        found_in_openapi=True,      # +0.20
    )
    score2 = PropertyAuthorizationInferenceEngine.calculate_confidence(ev2)
    assert score2 == 0.40

    # Test 3: Only runtime evidence
    ev3 = PropertyEvidence(
        object_name="User",
        property="temp_token",
        found_runtime=True,         # +0.20
        read_endpoints=["GET /temp"], # +0.10
    )
    score3 = PropertyAuthorizationInferenceEngine.calculate_confidence(ev3)
    assert score3 == 0.30


def test_is_auth_expression():
    assert PropertyAuthorizationInferenceEngine._is_auth_expression("current_user.is_admin") is True
    assert PropertyAuthorizationInferenceEngine._is_auth_expression("user.role == 'manager'") is True
    assert PropertyAuthorizationInferenceEngine._is_auth_expression("x == y") is False


def test_scan_text_for_auth_regex():
    content = """
@roles_required("admin")
def get_user_salary(self):
    return user.salary

def update_profile(self):
    if current_user.is_admin:
        x = user.email
"""
    discovered = {
        "User": {"salary", "email", "name"}
    }
    results = {
        "User": {"salary": [], "email": [], "name": []}
    }
    PropertyAuthorizationInferenceEngine._scan_text_for_auth_regex(content, ".py", discovered, results)
    
    # check salary has decorator context
    assert any("roles_required" in c for c in results["User"]["salary"])
    # check email has if context
    assert any("current_user.is_admin" in c for c in results["User"]["email"])
    # check name has no contexts
    assert not results["User"]["name"]


def test_documentation_correlation():
    # email is in AST and OpenAPI
    # salary is in AST and Runtime, but NOT in OpenAPI
    mock_openapi = {
        "components": {
            "schemas": {
                "User": {
                    "properties": {
                        "id": {"type": "integer"},
                        "email": {"type": "string"}
                    }
                }
            }
        }
    }
    
    # Inventory from phase 1
    inv_data = {
        "User": {
            "properties": [
                {"name": "id", "sources": ["openapi", "runtime"]},
                {"name": "email", "sources": ["openapi", "ast"]},
                {"name": "salary", "sources": ["ast", "runtime"]} # absent from openapi
            ]
        }
    }
    inventory = PropertyInventory(inv_data)
    
    evidences = PropertyAuthorizationInferenceEngine.run_inference(
        repo_path=".",
        inventory=inventory,
        openapi_spec=mock_openapi,
        runtime_traffic=[]
    )
    
    # check salary evidence has the documentation anomaly
    salary_ev = next(e for e in evidences if e.property == "salary")
    assert "Property observed at runtime but absent from API specification." in salary_ev.documentation_issues
    assert salary_ev.found_in_openapi is False
    assert salary_ev.found_runtime is True
    
    # check email has no issues
    email_ev = next(e for e in evidences if e.property == "email")
    assert not email_ev.documentation_issues


def test_cross_model_correlation(tmp_path):
    # Write mock files with different model names representing User object
    f1 = tmp_path / "dtos.py"
    f1.write_text("""
class UserDTO:
    id: int
    salary: float
""", encoding="utf-8")

    f2 = tmp_path / "entities.py"
    f2.write_text("""
class UserEntity:
    id: int
    salary: float
    password_hash: str
""", encoding="utf-8")

    discovered = {"User": {"id", "salary", "password_hash"}}
    res = PropertyAuthorizationInferenceEngine.build_cross_model_occurrences(str(tmp_path), "python", discovered)
    
    assert "UserDTO" in res["User"]["salary"]
    assert "UserEntity" in res["User"]["salary"]
    
    assert "UserEntity" in res["User"]["password_hash"]
    assert "UserDTO" not in res["User"]["password_hash"]


def test_build_authorization_graph():
    evidences = [
        PropertyEvidence(
            object_name="User",
            property="email",
            read_endpoints=["GET /profile"],
            write_endpoints=["PATCH /profile"],
            authorization_contexts=[]
        ),
        PropertyEvidence(
            object_name="User",
            property="salary",
            read_endpoints=["GET /admin/profile"],
            write_endpoints=["PATCH /salary"],
            authorization_contexts=["@roles_required(admin)"]
        )
    ]
    
    graph = PropertyAuthorizationInferenceEngine.build_authorization_graph(evidences)
    assert isinstance(graph, PropertyAuthorizationGraph)
    assert "User" in graph.objects
    
    user_node = graph.objects["User"]
    assert "email" in user_node.properties
    assert "salary" in user_node.properties
    
    salary_node = user_node.properties["salary"]
    assert "GET /admin/profile" in salary_node.read_operations
    assert "PATCH /salary" in salary_node.write_operations
    assert "@roles_required(admin)" in salary_node.authorization_contexts
