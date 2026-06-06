import pytest
import jwt
from src.core.bola.ownership_inference import OwnershipInferenceEngine

def test_ownership_inference_flow():
    # Helper to generate a token with a specific sub
    def make_token(sub, username, role):
        payload = {
            "sub": sub,
            "preferred_username": username,
            "roles": [role]
        }
        import base64, json
        h_b64 = base64.urlsafe_b64encode(b'{"alg":"HS256"}').decode().rstrip("=")
        p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        return f"{h_b64}.{p_b64}.mock"

    token_alice = make_token("alice-uuid", "alice", "user")
    token_bob = make_token("bob-uuid", "bob", "user")
    token_charlie = make_token("admin-uuid", "charlie", "admin")

    traffic = [
        # Alice accesses her order 500
        {
            "method": "GET",
            "path": "/api/orders/500",
            "status": 200,
            "auth_header": f"Bearer {token_alice}"
        },
        # Bob accesses his order 600
        {
            "method": "GET",
            "path": "/api/orders/600",
            "status": 200,
            "auth_header": f"Bearer {token_bob}"
        },
        # Charlie (admin) accesses an invoice 900
        {
            "method": "GET",
            "path": "/api/invoices/900",
            "status": 200,
            "auth_header": f"Bearer {token_charlie}"
        },
        # A failed request (should not infer anything)
        {
            "method": "GET",
            "path": "/api/orders/999",
            "status": 403,
            "auth_header": f"Bearer {token_alice}"
        }
    ]

    engine = OwnershipInferenceEngine()
    engine.analyze_traffic(traffic)

    # Verify ownership map
    omap = engine.ownership_map
    assert "alice-uuid" in omap
    assert "bob-uuid" in omap
    assert "admin-uuid" in omap

    assert "500" in omap["alice-uuid"]["resources"]["orders"]
    assert "600" in omap["bob-uuid"]["resources"]["orders"]
    assert "900" in omap["admin-uuid"]["resources"]["invoices"]
    assert "999" not in omap["alice-uuid"]["resources"].get("orders", set())

    # Get inferred identities for the test scenarios
    uuid_alice, uuid_bob, uuid_charlie, role_map, headers_matrix = engine.get_inferred_identities()
    
    assert uuid_alice == "alice-uuid"
    assert uuid_bob == "bob-uuid"
    assert uuid_charlie == "admin-uuid"
    assert role_map[uuid_alice] == "user"
    assert role_map[uuid_bob] == "user"
    assert role_map[uuid_charlie] == "admin"
    assert headers_matrix["userA"]["Authorization"] == f"Bearer {token_alice}"
    assert headers_matrix["userB"]["Authorization"] == f"Bearer {token_bob}"
    assert headers_matrix["userC"]["Authorization"] == f"Bearer {token_charlie}"
