import os
import sys
import json
import base64
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.bopla.models import PropertyInventory, PropertyEvidence, PropertyAuthorizationGraph
from src.core.bopla.discovery import PropertyDiscoveryEngine
from src.core.bopla.property_inference import PropertyAuthorizationInferenceEngine
from src.core.bopla.dynamic_tester import BOPLADynamicTester


def mock_request_side_effect(method, url, **kwargs):
    """
    Simulates a vulnerable endpoint that returns sensitive data to standard users
    and allows unauthorized property modification.
    """
    method = method.upper()
    resp = MagicMock()
    resp.status_code = 200

    # 1. T01 / T06 GET profile simulation
    if "profile" in url or "users" in url:
        if method == "GET":
            # If standard user (user_a_uuid), return sensitive salary
            if "Authorization" in kwargs.get("headers", {}) and "user_a_uuid" in kwargs["headers"]["Authorization"]:
                resp.text = '{"id": 101, "email": "alice@example.com", "salary": 9000, "role": "user"}'
                resp.json.return_value = {"id": 101, "email": "alice@example.com", "salary": 9000, "role": "user"}
            else:
                # Admin user response
                resp.text = '{"id": 101, "email": "alice@example.com", "salary": 9000, "role": "user", "isAdmin": false}'
                resp.json.return_value = {"id": 101, "email": "alice@example.com", "salary": 9000, "role": "user", "isAdmin": False}
        else:
            # PUT/PATCH simulation (accepts modification)
            resp.text = '{"status": "success", "modified_keys": ["salary", "role"]}'
            resp.json.return_value = {"status": "success", "modified_keys": ["salary", "role"]}
    else:
        # Default response
        resp.text = '{"status": "ok"}'
        resp.json.return_value = {"status": "ok"}
    
    return resp


def main():
    print("=====================================================================")
    print("🛡️  AVVIO SIMULATORE E DIMOSTRAZIONE BOPLA DYNAMIC TESTER (FASE 3)")
    print("=====================================================================")

    # 1. Phase 1 - Discovery Mock Data
    print("\n🔍 [Fase 1] Caricamento Property Inventory (Discovery)...")
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
            "path": "/api/users/101",
            "response": {"id": 101, "email": "alice@example.com", "salary": 9000}
        }
    ]

    inventory = PropertyDiscoveryEngine.discover_properties(
        repo_path=".",
        openapi_spec=mock_openapi,
        runtime_traffic=mock_traffic
    )
    print(f"Inventory generato con successo: {list(inventory.root.keys())} oggetti rilevati.")

    # 2. Phase 2 - Inference
    print("\n⚙️ [Fase 2] Esecuzione Property Authorization Inference Engine...")
    evidences = PropertyAuthorizationInferenceEngine.run_inference(
        repo_path=".",
        inventory=inventory,
        openapi_spec=mock_openapi,
        runtime_traffic=mock_traffic
    )
    
    # Enrich evidences with some decorator context for the demo
    for ev in evidences:
        if ev.property == "salary":
            ev.authorization_contexts = ["@roles_required(admin)"]
            ev.read_endpoints = ["GET /api/users/{id}"]
            ev.write_endpoints = ["PUT /api/users/{id}"]
            ev.confidence = 0.8
        elif ev.property == "role":
            ev.write_endpoints = ["PUT /api/users/{id}"]
            ev.confidence = 0.5

    graph = PropertyAuthorizationInferenceEngine.build_authorization_graph(evidences)
    print(f"Inference completata. {len(evidences)} evidenze e Grafo di Autorizzazione generati.")

    # 3. Setup JWT headers matrix
    # Header: {"alg": "HS256", "typ": "JWT"}
    # Payloads: sub claim contains uuids
    header_b64 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    payload_user = base64.urlsafe_b64encode(b'{"sub": "user_a_uuid", "roles": ["user"]}').decode().rstrip("=")
    payload_admin = base64.urlsafe_b64encode(b'{"sub": "admin_uuid", "roles": ["admin"]}').decode().rstrip("=")
    
    headers_matrix = {
        "userA": {"Authorization": f"Bearer {header_b64}.{payload_user}.signature"},
        "userB": {"Authorization": "Bearer invalid_token_fallback"},
        "userC": {"Authorization": f"Bearer {header_b64}.{payload_admin}.signature"},
        "anonymous": {}
    }

    # 4. Instantiate and run BOPLADynamicTester with requests.request mocked
    print("\n⚡ [Fase 3] Esecuzione targeted tests (T01 - T07)...")
    
    tester = BOPLADynamicTester(
        target_base_url="http://localhost:5000",
        inventory=inventory,
        evidences=evidences,
        graph=graph,
        headers_matrix=headers_matrix,
        runtime_traffic=mock_traffic,
        openapi_spec=mock_openapi
    )

    with patch("requests.request", side_effect=mock_request_side_effect) as mock_req:
        findings = tester.run_all_tests()

    print(f"Test completati. Rilevati {len(findings)} findings di vulnerabilità BOPLA.")

    # Show findings summaries
    for f in findings:
        print(f"\n[{f.test_id}] Proprietà: {f.property_name} su endpoint: {f.endpoint} ({f.method})")
        print(f"  Vulnerabilità confermata: {f.verified}")
        print(f"  Evidenze:")
        for ev_msg in f.evidence:
            print(f"    - {ev_msg}")

    # 5. Save output JSON
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    output_path = output_dir / "bopla_dynamic_findings_example.json"
    
    serialized_findings = [f.model_dump() for f in findings]
    with open(output_path, "w", encoding="utf-8") as out:
        json.dump(serialized_findings, out, indent=4)

    print(f"\n🏆 DIMOSTRAZIONE COMPLETATA. Output JSON salvato in: {output_path}")
    print("=====================================================================")


if __name__ == "__main__":
    main()
