import os
import json
import subprocess
import yaml
from typing import List
from src.parsers.normalizer import normalize_path
from src.scanners.spectral_runner import is_openapi_file
from src.models.finding import Finding, FindingSource, FindingCategory, Severity, APIContext

def run_shadow_api_hunter(target_dir=".") -> List[Finding]:
    print("🚀 Esecuzione Shadow API Hunter (con Auth Discrepancy Control)...")
    semgrep_bin = "semgrep"
    if os.path.exists("./.venv/bin/semgrep"):
        semgrep_bin = "./.venv/bin/semgrep"

    ruleset_path = "rules/route-detect.yaml"
    if not os.path.exists(ruleset_path):
        ruleset_path = os.path.join(os.path.dirname(__file__), "../../rules/route-detect.yaml")

    # Fase A: Estrazione con Semgrep
    cmd = [semgrep_bin, "scan", f"--config={ruleset_path}", "--json", "-o", "semgrep_routes.json", target_dir]
    subprocess.run(cmd, capture_output=True, text=True)
    
    code_routes = {}
    if os.path.exists("semgrep_routes.json"):
        with open("semgrep_routes.json", "r") as f:
            try:
                data = json.load(f)
                for res in data.get("results", []):
                    msg = res.get("extra", {}).get("message", "")
                    check_id = res.get("check_id", "")
                    if "Route Detected:" in msg:
                        route = msg.split("Route Detected:")[1].strip().strip("'\"")
                        if route not in code_routes:
                            code_routes[route] = {"is_secured": False}
                        
                        if check_id == "extract-python-secured-route":
                            code_routes[route]["is_secured"] = True
            except:
                pass

    # Fase B: Estrazione da OpenAPI e Normalizzazione
    openapi_routes = {}
    openapi_file = None
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        for file in files:
            if file.endswith(('.yaml', '.yml', '.json')) and is_openapi_file(os.path.join(root, file)):
                openapi_file = os.path.join(root, file)
                break
        if openapi_file: break

    if openapi_file:
        with open(openapi_file, 'r') as f:
            spec = yaml.safe_load(f)
            global_security = bool(spec.get("security", []))
            
            paths = spec.get("paths", {})
            for p, methods in paths.items():
                is_secured = global_security
                if isinstance(methods, dict):
                    for method, details in methods.items():
                        if isinstance(details, dict) and "security" in details:
                            if details["security"]:
                                is_secured = True
                            else:
                                is_secured = False
                openapi_routes[p] = {"is_secured": is_secured}
                
    normalized_semgrep = {normalize_path(r): (r, data["is_secured"]) for r, data in code_routes.items()}
    normalized_openapi = {normalize_path(r): (r, data["is_secured"]) for r, data in openapi_routes.items()}

    api_issues = []
    idx = 0
    
    # Fase C: Diff Analysis (Shadow API & Auth Discrepancy)
    for norm_route, (orig_route, code_secured) in normalized_semgrep.items():
        corr_key = norm_route
        if norm_route not in normalized_openapi:
            api_ctx = APIContext(endpoint=orig_route, requires_authentication=code_secured)
            finding_id = Finding.generate_deterministic_id(FindingSource.SHADOW_API, "shadow-api", orig_route)
            finding = Finding(
                finding_id=finding_id,
                source=FindingSource.SHADOW_API,
                category=FindingCategory.API_EXPOSURE,
                title="Shadow API Rilevata",
                description=f"Shadow API rilevata: {orig_route} (non documentata in OpenAPI)",
                severity=Severity.HIGH,
                confidence=1.0,
                rule_id="shadow-api",
                rule_name="Improper Inventory Management",
                api=api_ctx,
                correlation_key=corr_key,
                owasp_api_category="OWASP API8:2023"
            )
            api_issues.append(finding)
        else:
            _, oas_secured = normalized_openapi[norm_route]
            if oas_secured and not code_secured:
                api_ctx = APIContext(endpoint=orig_route, requires_authentication=code_secured)
                finding_id = Finding.generate_deterministic_id(FindingSource.SHADOW_API, "auth-discrepancy", orig_route)
                finding = Finding(
                    finding_id=finding_id,
                    source=FindingSource.SHADOW_API,
                    category=FindingCategory.AUTHENTICATION,
                    title="Auth Discrepancy (Mancante in Codice)",
                    description=f"Auth Discrepancy su {orig_route}: L'OpenAPI richiede Auth, ma il codice NON implementa difese!",
                    severity=Severity.CRITICAL,
                    confidence=1.0,
                    rule_id="auth-discrepancy",
                    rule_name="Broken Authentication",
                    api=api_ctx,
                    correlation_key=corr_key,
                    owasp_api_category="OWASP API2:2023"
                )
                api_issues.append(finding)
            elif code_secured and not oas_secured:
                api_ctx = APIContext(endpoint=orig_route, requires_authentication=code_secured)
                finding_id = Finding.generate_deterministic_id(FindingSource.SHADOW_API, "auth-discrepancy-oas", orig_route)
                finding = Finding(
                    finding_id=finding_id,
                    source=FindingSource.SHADOW_API,
                    category=FindingCategory.AUTHENTICATION,
                    title="Auth Discrepancy (Contratto Obsoleto)",
                    description=f"Auth Discrepancy su {orig_route}: Il codice implementa Auth, ma non è dichiarata nell'OpenAPI (Contratto Obsoleto).",
                    severity=Severity.MEDIUM,
                    confidence=1.0,
                    rule_id="auth-discrepancy-oas",
                    rule_name="Broken Authentication",
                    api=api_ctx,
                    correlation_key=corr_key,
                    owasp_api_category="OWASP API2:2023"
                )
                api_issues.append(finding)

    return api_issues
