import os
import json
import subprocess
import sys
import yaml
import re

def is_openapi_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            if 'openapi:' in content or 'swagger:' in content:
                return True
    except Exception:
        pass
    return False

def run_spectral():
    print("🚀 Esecuzione Spectral API Scanner (OWASP)...")
    openapi_file = None
    for root, dirs, files in os.walk("."):
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        for file in files:
            if file.endswith(('.yaml', '.yml', '.json')):
                filepath = os.path.join(root, file)
                if is_openapi_file(filepath):
                    openapi_file = filepath
                    break
        if openapi_file: break

    if not openapi_file:
        print("ℹ️ Nessun file OpenAPI trovato.")
        return []

    print(f"📄 File OpenAPI trovato: {openapi_file}")
    cmd = ["npx", "@stoplight/spectral-cli", "lint", openapi_file, "--ruleset", "spectral-owasp.yaml", "--format", "json", "-o", "spectral_report.json"]
    try:
        subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        print("⚠️ npx non trovato. Salto la scansione Spectral.")
        return []
    except Exception as e:
        print(f"⚠️ Errore durante l'esecuzione di Spectral: {e}")
        return []
    
    if os.path.exists("spectral_report.json"):
        with open("spectral_report.json", "r") as f:
            try:
                return json.load(f)
            except:
                return []
    return []

def run_checkov():
    print("🚀 Esecuzione Cloud Security Scanner (Checkov)...")
    checkov_bin = "checkov"
    if os.path.exists("./.venv/bin/checkov"):
        checkov_bin = "./.venv/bin/checkov"
    
    cmd = [checkov_bin, "--skip-download", "--no-cert-verify", "-o", "json"]
    if os.path.exists(".checkov.yaml"):
        cmd.extend(["--config-file", ".checkov.yaml"])
    else:
        cmd.extend(["-d", "."])
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    output_str = result.stdout
    try:
        json_start = output_str.find('{')
        json_start_array = output_str.find('[')
        start_idx = -1
        if json_start != -1 and json_start_array != -1:
            start_idx = min(json_start, json_start_array)
        elif json_start != -1:
            start_idx = json_start
        elif json_start_array != -1:
            start_idx = json_start_array
            
        if start_idx != -1:
            data = json.loads(output_str[start_idx:])
            with open("checkov_report.json", "w") as f:
                json.dump(data, f)
            if isinstance(data, dict):
                return [data]
            return data
    except Exception as e:
        print(f"⚠️ Errore parsing Checkov JSON: {e}")
    return []

def run_semgrep():
    print("🚀 Esecuzione Static Analysis (Semgrep)...")
    semgrep_bin = "semgrep"
    if os.path.exists("./.venv/bin/semgrep"):
        semgrep_bin = "./.venv/bin/semgrep"

    cmd = [semgrep_bin, "scan", "--config=p/owasp-top-10", "--config=p/api-security", "--json", "-o", "semgrep_report.json", "."]
    subprocess.run(cmd, capture_output=True, text=True)
    
    if os.path.exists("semgrep_report.json"):
        with open("semgrep_report.json", "r") as f:
            try:
                data = json.load(f)
                return data.get("results", [])
            except:
                return []
    return []

def run_shadow_api_hunter():
    print("🚀 Esecuzione Shadow API Hunter (con Auth Discrepancy Control)...")
    semgrep_bin = "semgrep"
    if os.path.exists("./.venv/bin/semgrep"):
        semgrep_bin = "./.venv/bin/semgrep"

    # Fase A: Estrazione con Semgrep
    cmd = [semgrep_bin, "scan", "--config=route-detect.yaml", "--json", "-o", "semgrep_routes.json", "."]
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
    for root, dirs, files in os.walk("."):
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
                
    # Normalizzazione path: trasformare parametri in VAR
    def normalize_path(path):
        # /users/<int:id> -> /users/VAR
        path = re.sub(r'<[^>]+>', 'VAR', path)
        # /users/{id} -> /users/VAR
        path = re.sub(r'\{[^}]+\}', 'VAR', path)
        return path

    normalized_semgrep = {normalize_path(r): (r, data["is_secured"]) for r, data in code_routes.items()}
    normalized_openapi = {normalize_path(r): (r, data["is_secured"]) for r, data in openapi_routes.items()}

    api_issues = []
    
    # Fase C: Diff Analysis (Shadow API & Auth Discrepancy)
    for norm_route, (orig_route, code_secured) in normalized_semgrep.items():
        if norm_route not in normalized_openapi:
            api_issues.append({
                "Type": "Shadow API",
                "Severity": "High",
                "Category": "OWASP API8:2023 - Improper Inventory Management",
                "Message": f"Shadow API rilevata: {orig_route} (non documentata in OpenAPI)"
            })
        else:
            _, oas_secured = normalized_openapi[norm_route]
            if oas_secured and not code_secured:
                api_issues.append({
                    "Type": "Auth Discrepancy",
                    "Severity": "Critical",
                    "Category": "OWASP API2:2023 - Broken Authentication",
                    "Message": f"Auth Discrepancy su {orig_route}: L'OpenAPI richiede Auth, ma il codice NON implementa difese!"
                })
            elif code_secured and not oas_secured:
                api_issues.append({
                    "Type": "Auth Discrepancy",
                    "Severity": "Medium",
                    "Category": "OWASP API2:2023 - Broken Authentication",
                    "Message": f"Auth Discrepancy su {orig_route}: Il codice implementa Auth, ma non è dichiarata nell'OpenAPI (Contratto Obsoleto)."
                })

    return api_issues

def consolidate_reports(spectral_data, checkov_data, semgrep_data, api_issues):
    print("\n" + "="*80)
    print("📊 REPORT GLOBALE MULTI-LAYER (SEVERITY E OWASP)")
    print("="*80)
    
    vulnerabilities = []
    
    # Checkov
    for report in checkov_data:
        for check in report.get("results", {}).get("failed_checks", []):
            vuln = {
                "Tool": "Checkov",
                "Severity": "Critical" if "s3" in check.get("check_id", "").lower() or "acl" in check.get("check_id", "").lower() else "Medium",
                "Category": "IaC Misconfiguration",
                "Message": f"{check.get('check_name')} in {check.get('file_path')}:{check.get('file_line_range', [0])[0]}"
            }
            vulnerabilities.append(vuln)
            
    # Spectral
    for issue in spectral_data:
        vuln = {
            "Tool": "Spectral",
            "Severity": "High" if issue.get("severity") == 0 else "Medium",
            "Category": "API Contract (OWASP)",
            "Message": f"{issue.get('message')} at {issue.get('source')} line {issue.get('range', {}).get('start', {}).get('line')}"
        }
        vulnerabilities.append(vuln)
        
    # Semgrep
    for issue in semgrep_data:
        vuln = {
            "Tool": "Semgrep",
            "Severity": issue.get("extra", {}).get("severity", "Medium"),
            "Category": "SAST Vulnerability",
            "Message": f"{issue.get('extra', {}).get('message').splitlines()[0]} in {issue.get('path')}:{issue.get('start', {}).get('line')}"
        }
        vulnerabilities.append(vuln)
        
    # Shadow API & Auth Discrepancy
    for issue in api_issues:
        vuln = {
            "Tool": "L'Arbitro (API Hunter)",
            "Severity": issue["Severity"],
            "Category": issue["Category"],
            "Message": issue["Message"]
        }
        vulnerabilities.append(vuln)

    # Sort by Severity priority (Critical, High, Medium, Low)
    severity_rank = {"Critical": 1, "High": 2, "ERROR": 2, "Medium": 3, "WARNING": 3, "Low": 4, "INFO": 4}
    
    vulnerabilities.sort(key=lambda x: severity_rank.get(x["Severity"], 5))

    if not vulnerabilities:
        print("✅ Nessuna vulnerabilità rilevata! Il sistema è sicuro.")
    else:
        for v in vulnerabilities:
            print(f"[{v['Severity'].upper()}] ({v['Tool']}) {v['Category']}")
            print(f"    -> {v['Message']}\n")
        print(f"❌ Trovate {len(vulnerabilities)} vulnerabilità. Risolvi i problemi prima del deploy.")
        sys.exit(1)

def main():
    checkov_data = run_checkov()
    spectral_data = run_spectral()
    semgrep_data = run_semgrep()
    shadow_apis = run_shadow_api_hunter()
    
    consolidate_reports(spectral_data, checkov_data, semgrep_data, shadow_apis)

if __name__ == "__main__":
    main()
