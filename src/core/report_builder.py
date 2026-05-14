import sys
from typing import List
from Finding import Finding, FindingSource

def consolidate_reports(spectral_findings: List[Finding], checkov_findings: List[Finding], semgrep_findings: List[Finding], shadow_api_findings: List[Finding]):
    print("\n" + "="*80)
    print("📊 REPORT GLOBALE MULTI-LAYER (SEVERITY E OWASP)")
    print("="*80)
    
    checkov_vulns: List[Finding] = checkov_findings
    other_vulns: List[Finding] = spectral_findings + semgrep_findings + shadow_api_findings
    
    # Sort by Severity priority (Critical, High, Medium, Low)
    severity_rank = {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 3,
        "LOW": 4,
        "INFO": 5
    }
    
    checkov_vulns.sort(key=lambda f: severity_rank.get(f.severity.value, 6))
    other_vulns.sort(key=lambda f: severity_rank.get(f.severity.value, 6))

    total_vulns = len(checkov_vulns) + len(other_vulns)

    print("\n" + "-"*80)
    print("🛡️  RISULTATI CHECKOV (Infrastructure as Code)")
    print("-"*80)
    if not checkov_vulns:
        print("✅ Nessuna vulnerabilità Checkov rilevata.\n")
    else:
        for f in checkov_vulns:
            loc_path = f.location.file_path if f.location else "N/A"
            loc_line = f":{f.location.start_line}" if f.location and f.location.start_line is not None else ""
            print(f"[{f.severity.value}] {f.category.value}")
            print(f"    -> {f.title} in {loc_path}{loc_line}\n")

    print("-"*80)
    print("🔍 RESTANTI VULNERABILITÀ (SAST, API Contract, Shadow API)")
    print("-"*80)
    if not other_vulns:
        print("✅ Nessuna altra vulnerabilità rilevata.\n")
    else:
        for f in other_vulns:
            loc_str = ""
            if f.location and f.location.file_path:
                loc_str = f" in {f.location.file_path}"
                if f.location.start_line is not None:
                    loc_str += f":{f.location.start_line}"
            elif f.api and f.api.endpoint:
                loc_str = f" su endpoint {f.api.endpoint}"
                
            owasp_str = f" ({f.owasp_api_category})" if f.owasp_api_category else ""
            
            print(f"[{f.severity.value}] ({f.source.value}) {f.category.value}{owasp_str}")
            print(f"    -> {f.description or f.title}{loc_str}\n")

    print("="*80)
    if total_vulns == 0:
        print("✅ Nessuna vulnerabilità rilevata in totale! Il sistema è sicuro.")
    else:
        print(f"❌ Trovate {total_vulns} vulnerabilità totali ({len(checkov_vulns)} Checkov, {len(other_vulns)} altre). Risolvi i problemi prima del deploy.")
        sys.exit(1)
