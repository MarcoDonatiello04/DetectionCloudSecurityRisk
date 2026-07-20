import json
import os
import sys
from pathlib import Path

import yaml

# Add root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.api2_broken_auth.discovery import Config
from src.core.api3_bopla.orchestrator import BOPLAOrchestrator
from src.core.identity_context import IdentityManager


def main():
    repo_path = "."

    # 1. Load config
    config_path = Path("config/config.yaml")
    config = Config.load(config_path)

    # 2. Load OpenAPI specification
    openapi_spec = None
    openapi_paths = ["test_targets/bola/openapi.yaml", "openapi.yaml", "openapi.json"]
    for path in openapi_paths:
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    if path.endswith(".yaml") or path.endswith(".yml"):
                        openapi_spec = yaml.safe_load(f)
                    else:
                        openapi_spec = json.load(f)
                break
            except Exception:
                pass

    # 3. Load Runtime Traffic
    runtime_traffic = None
    traffic_paths = ["soluzione_api/src/output/raw_traffic.json", "output/raw_traffic.json"]
    for path in traffic_paths:
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    runtime_traffic = json.load(f)
                break
            except Exception:
                pass

    # 4. Fetch Authentication Headers using IdentityManager
    headers_matrix = None
    try:
        identity_manager = IdentityManager(
            keycloak_url=os.getenv("KEYCLOAK_URL", "http://localhost:8080")
        )
        headers_matrix = identity_manager.get_headers_for_identities()
    except Exception as e:
        print(
            f"[-] Impossibile inizializzare IdentityManager: {e}. I test dinamici utilizzeranno mock o verranno ignorati."
        )

    # 5. Execute BOPLA Orchestrator
    orchestrator = BOPLAOrchestrator(config)
    report_data = orchestrator.run_assessment(
        repo_path=repo_path,
        openapi_spec=openapi_spec,
        runtime_traffic=runtime_traffic,
        headers_matrix=headers_matrix,
    )

    # 6. Display final summary block requested by USER
    print("=========================================")
    print("BOPLA Assessment Completed")
    print(f"Objects discovered: {report_data['objects_discovered']}")
    print(f"Properties discovered: {report_data['properties_discovered']}")
    print(f"Dynamic tests executed: {report_data['tests_executed']}")
    print(f"Findings: {report_data['vulnerabilities_detected']}")
    print(f"Property Authorization Score: {report_data['score']}/100")
    print(f"Risk Level: {report_data['risk_level']}")
    print("Reports saved in:")
    print(f"{config.output.path}/bopla/")
    print("=========================================")


if __name__ == "__main__":
    main()
