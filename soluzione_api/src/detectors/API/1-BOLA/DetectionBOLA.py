import os
import sys
import json
import subprocess
import yaml
import re
from typing import List

# Fix for direct execution: add project root to PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../..")))

from src.models.finding import Finding, FindingSource, FindingCategory, Severity, APIContext

def extract_object_based_endpoints(target_dir=".") -> List[str]:
    """
    Estrae tutte le rotte 'object-based' (che contengono parametri come <id> o {id})
    combinando l'analisi statica di Semgrep, i file OpenAPI presenti nel target,
    e il parsing euristico dei file sorgente (es. AWS Lambda routes).
    """
    object_based_routes = []

    # 1. Estrazione da OpenAPI Spec
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('venv', '.venv', 'node_modules')]
        for file in files:
            if file.endswith(('.yaml', '.yml', '.json')):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if 'openapi:' in content or 'swagger:' in content:
                            f.seek(0)
                            spec = yaml.safe_load(f)
                            if isinstance(spec, dict):
                                paths = spec.get("paths", {})
                                if isinstance(paths, dict):
                                    for p in paths.keys():
                                        if ("<" in p and ">" in p) or ("{" in p and "}" in p):
                                            if p not in object_based_routes:
                                                object_based_routes.append(p)
                except Exception as e:
                    print(f"⚠️ Errore lettura OpenAPI {filepath}: {e}")

    # 2. Estrazione Euristica da Codice Python (es. AWS Lambda app.py)
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('venv', '.venv', 'node_modules')]
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                # Salta file di framework/detector stessi
                if "DetectionBOLA.py" in filepath or "semgrep" in filepath:
                    continue
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        # Trova pattern come path.startswith('/users/') o path.startswith('/notes/')
                        matches = re.findall(r'path\.startswith\(\s*[\'"]([^\'"]+)[\'"]\s*\)', content)
                        for m in matches:
                            if m.endswith('/') and m != '/':
                                route_param = f"{m}{{id}}"
                                if route_param not in object_based_routes:
                                    object_based_routes.append(route_param)
                except Exception:
                    pass

    # 3. Estrazione via Semgrep (Flask/FastAPI decorators)
    semgrep_bin = "semgrep"
    if os.path.exists("./.venv/bin/semgrep"):
        semgrep_bin = "./.venv/bin/semgrep"

    ruleset_path = "config/scanner_configs/route-detect.yaml"
    if not os.path.exists(ruleset_path):
        ruleset_path = os.path.join(os.path.dirname(__file__), "../../../config/scanner_configs/route-detect.yaml")

    if os.path.exists(ruleset_path):
        cmd = [semgrep_bin, "scan", f"--config={ruleset_path}", "--json", "-o", "semgrep_routes_bola.json", target_dir]
        subprocess.run(cmd, capture_output=True, text=True)

        if os.path.exists("semgrep_routes_bola.json"):
            with open("semgrep_routes_bola.json", "r") as f:
                try:
                    data = json.load(f)
                    for res in data.get("results", []):
                        msg = res.get("extra", {}).get("message", "")
                        if "Route Detected:" in msg:
                            route = msg.split("Route Detected:")[1].strip().strip("'\"")
                            if "<" in route and ">" in route or "{" in route and "}" in route:
                                if route not in object_based_routes:
                                    object_based_routes.append(route)
                except Exception as e:
                    print(f"Errore parsing JSON BOLA da Semgrep: {e}")

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

if __name__ == "__main__":
    import pprint
    # Run from the project root directory
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
    print(f"Eseguendo BOLA detection nella directory: {project_root}")
    results = run_bola_detection(project_root)
    print(f"Trovati {len(results)} potenziali endpoint BOLA:")
    for f in results:
        print(f" - {f.api.endpoint} (ID: {f.finding_id})")
        # pprint.pprint(f.to_dict()) if needed

