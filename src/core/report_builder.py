import sys

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
