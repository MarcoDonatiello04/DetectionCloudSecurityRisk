import pytest
import json
from pathlib import Path

from src.core.broken_object_property_level_access.discovery import PropertyDiscoveryEngine
from src.core.broken_object_property_level_access.models import PropertyInventory


def test_clean_object_name():
    assert PropertyDiscoveryEngine.clean_object_name("UserDTO") == "User"
    assert PropertyDiscoveryEngine.clean_object_name("UserRequest") == "User"
    assert PropertyDiscoveryEngine.clean_object_name("OrderModel") == "Order"
    assert PropertyDiscoveryEngine.clean_object_name("UserEntity") == "User"
    assert PropertyDiscoveryEngine.clean_object_name("signup_request") == "Signup"


def test_get_object_name_from_path():
    assert PropertyDiscoveryEngine.get_object_name_from_path("/api/orders/101") == "Order"
    assert PropertyDiscoveryEngine.get_object_name_from_path("/users") == "User"
    assert PropertyDiscoveryEngine.get_object_name_from_path("/api/v1/notes/{id}") == "Note"


def test_extract_openapi_properties():
    mock_openapi = {
        "components": {
            "schemas": {
                "UserDTO": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "email": {"type": "string"},
                        "role": {"type": "string"}
                    }
                }
            }
        },
        "definitions": {
            "Order": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "total": {"type": "number"}
                }
            }
        }
    }
    
    res = PropertyDiscoveryEngine.extract_openapi_properties(mock_openapi)
    assert "User" in res
    assert "id" in res["User"]
    assert "email" in res["User"]
    assert "role" in res["User"]
    
    assert "Order" in res
    assert "id" in res["Order"]
    assert "total" in res["Order"]


def test_extract_runtime_properties():
    mock_traffic = [
        {
            "method": "POST",
            "path": "/api/orders",
            "body_params": {"item": "book", "quantity": 2},
            "response": {"id": 123, "status": "pending"}
        },
        {
            "method": "GET",
            "path": "/users/10",
            "body_params": None,
            "response_body": {"id": 10, "username": "alice", "profile": {"age": 30}}
        }
    ]
    
    res = PropertyDiscoveryEngine.extract_runtime_properties(mock_traffic)
    assert "Order" in res
    assert "item" in res["Order"]
    assert "quantity" in res["Order"]
    assert "id" in res["Order"]
    assert "status" in res["Order"]
    
    assert "User" in res
    assert "id" in res["User"]
    assert "username" in res["User"]
    assert "profile" in res["User"]
    assert "age" in res["User"]


def test_extract_properties_via_regex():
    py_content = """
class UserDTO(BaseModel):
    id: int
    email: str
    is_active: bool = True

class Order:
    id = None
    price = 0.0
"""
    res = PropertyDiscoveryEngine.extract_properties_via_regex(py_content, ".py")
    assert len(res) == 2
    assert res[0][0] == "UserDTO"
    assert "id" in res[0][1]
    assert "email" in res[0][1]
    assert "is_active" in res[0][1]
    
    assert res[1][0] == "Order"
    assert "id" in res[1][1]
    assert "price" in res[1][1]

    ts_content = """
interface UserRequest {
    username: string;
    email?: string;
}
class Profile {
    age: number;
}
"""
    res_ts = PropertyDiscoveryEngine.extract_properties_via_regex(ts_content, ".ts")
    assert len(res_ts) == 2
    assert res_ts[0][0] == "UserRequest"
    assert "username" in res_ts[0][1]
    assert "email" in res_ts[0][1]
    assert res_ts[1][0] == "Profile"
    assert "age" in res_ts[1][1]


def test_discover_properties_orchestration(tmp_path):
    # Setup mock AST python model file
    py_file = tmp_path / "models.py"
    py_file.write_text("""
class UserDTO:
    id: int
    salary: float
""", encoding="utf-8")
    
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
    
    mock_traffic = [
        {
            "method": "GET",
            "path": "/users",
            "response": {"id": 1, "salary": 1000}
        }
    ]
    
    inventory = PropertyDiscoveryEngine.discover_properties(
        repo_path=str(tmp_path),
        openapi_spec=mock_openapi,
        runtime_traffic=mock_traffic
    )
    
    assert isinstance(inventory, PropertyInventory)
    
    # Serialize to JSON and inspect structure
    serialized = inventory.model_dump()
    assert "User" in serialized
    properties = serialized["User"]["properties"]
    
    # Check id is in openapi, ast, and runtime
    id_prop = next(p for p in properties if p["name"] == "id")
    assert set(id_prop["sources"]) == {"openapi", "ast", "runtime"}
    
    # Check email is only in openapi
    email_prop = next(p for p in properties if p["name"] == "email")
    assert set(email_prop["sources"]) == {"openapi"}
    
    # Check salary is in ast and runtime
    salary_prop = next(p for p in properties if p["name"] == "salary")
    assert set(salary_prop["sources"]) == {"ast", "runtime"}
