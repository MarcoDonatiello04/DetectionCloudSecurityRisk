import os
import json
import subprocess
from typing import List
from src.models.finding import Finding, FindingSource, FindingCategory, Severity, APIContext

def extract_object_based_endpoints(target_dir=".") -> List[str]:
    """
    Usa la configurazione Semgrep esistente (route-detect.yaml) per estrarre
    tutte le rotte, filtrando poi solo quelle 'object-based' (che contengono parametri come <id> o {id}).
    """
    semgrep_bin = "semgrep"
    if os.path.exists("./.venv/bin/semgrep"):
        semgrep_bin = "./.venv/bin/semgrep"

    ruleset_path = "config/scanner_configs/route-detect.yaml"
    if not os.path.exists(ruleset_path):
        ruleset_path = os.path.join(os.path.dirname(__file__), "../../../config/scanner_configs/route-detect.yaml")

    # Esegui Semgrep per estrarre le rotte
    cmd = [semgrep_bin, "scan", f"--config={ruleset_path}", "--json", "-o", "semgrep_routes_bola.json", target_dir]
    subprocess.run(cmd, capture_output=True, text=True)

    object_based_routes = []
    
    if os.path.exists("semgrep_routes_bola.json"):
        with open("semgrep_routes_bola.json", "r") as f:
            try:
                data = json.load(f)
                for res in data.get("results", []):
                    msg = res.get("extra", {}).get("message", "")
                    if "Route Detected:" in msg:
                        route = msg.split("Route Detected:")[1].strip().strip("'\"")
                        # Un endpoint è object-based se accetta un parametro nell'URL (es: <id>, {user_id})
                        if "<" in route and ">" in route or "{" in route and "}" in route:
                            if route not in object_based_routes:
                                object_based_routes.append(route)
            except Exception as e:
                print(f"Errore parsing JSON BOLA: {e}")
                
    return object_based_routes

def run_bola_detection(target_dir=".") -> List[Finding]:
    """
    Rileva potenziali vulnerabilità BOLA (Broken Object Level Authorization).
    Estrae gli endpoint object-based e li marca come target ad alto rischio BOLA.
    """
    print("🚀 Esecuzione BOLA Detector...")
    object_endpoints = extract_object_based_endpoints(target_dir)
    
    findings = []
    for route in object_endpoints:
        api_ctx = APIContext(endpoint=route, requires_authentication=True) # Assumiamo Auth richiesta per ora
        finding_id = Finding.generate_deterministic_id(FindingSource.SEMGREP, "bola-target", route)
        
        finding = Finding(
            finding_id=finding_id,
            source=FindingSource.SEMGREP,
            category=FindingCategory.AUTHORIZATION,
            title="Potenziale BOLA (Broken Object Level Authorization)",
            description=f"Endpoint Object-based rilevato: {route}. Gli endpoint che prendono identificatori in input devono implementare controlli di ownership rigorosi, altrimenti sono vulnerabili a BOLA (OWASP API1:2023).",
            severity=Severity.HIGH,
            confidence=0.8,
            rule_id="bola-target-detection",
            rule_name="BOLA/IDOR Endpoint",
            api=api_ctx,
            correlation_key=route,
            owasp_api_category="OWASP API1:2023"
        )
        findings.append(finding)
        
    return findings
