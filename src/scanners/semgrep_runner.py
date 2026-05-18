import os
import json
import subprocess
from typing import List
from src.models.finding from src.models.finding import Finding, FindingSource, FindingCategory, Severity, CodeLocation

def run_semgrep(target_dir=".") -> List[Finding]:
    print("🚀 Esecuzione Static Analysis (Semgrep)...")
    semgrep_bin = "semgrep"
    if os.path.exists("./.venv/bin/semgrep"):
        semgrep_bin = "./.venv/bin/semgrep"

    cmd = [semgrep_bin, "scan", "--config=p/owasp-top-10", "--config=p/api-security", "--json", "-o", "semgrep_report.json", target_dir]
    subprocess.run(cmd, capture_output=True, text=True)
    
    findings = []
    if os.path.exists("semgrep_report.json"):
        with open("semgrep_report.json", "r") as f:
            try:
                data = json.load(f)
                results = data.get("results", [])
                idx = 0
                for issue in results:
                    check_id = issue.get("check_id", "unknown")
                    extra = issue.get("extra", {})
                    msg = extra.get("message", "Vulnerabilità SAST rilevata")
                    short_desc = msg.splitlines()[0] if msg else "Vulnerabilità SAST"
                    
                    check_lower = check_id.lower()
                    
                    # Mapping Category esteso
                    if "inject" in check_lower or "sql" in check_lower or "cmd" in check_lower:
                        cat = FindingCategory.INJECTION
                    elif "secret" in check_lower or "jwt" in check_lower or "key" in check_lower or "token" in check_lower:
                        cat = FindingCategory.SECRETS
                    elif "auth" in check_lower or "login" in check_lower:
                        cat = FindingCategory.AUTHENTICATION
                    elif "perm" in check_lower or "access" in check_lower or "authz" in check_lower:
                        cat = FindingCategory.AUTHORIZATION
                    else:
                        cat = FindingCategory.MISCONFIGURATION

                    # Mapping Severity intelligente
                    semgrep_sev = extra.get("severity", "").upper()
                    if semgrep_sev == "ERROR":
                        sev = Severity.CRITICAL if cat in (FindingCategory.INJECTION, FindingCategory.AUTHENTICATION) else Severity.HIGH
                    elif semgrep_sev == "WARNING":
                        sev = Severity.MEDIUM
                    elif semgrep_sev == "INFO":
                        sev = Severity.LOW
                    else:
                        sev = Severity.MEDIUM

                    loc = CodeLocation(
                        file_path=issue.get("path", ""),
                        start_line=issue.get("start", {}).get("line")
                    )

                    target_ident = f"{loc.file_path}"
                    finding_id = Finding.generate_deterministic_id(FindingSource.SEMGREP, check_id, target_ident)
                    
                    corr_key = loc.file_path.split("/")[-1] if "/" in loc.file_path else loc.file_path

                    finding = Finding(
                        finding_id=finding_id,
                        source=FindingSource.SEMGREP,
                        category=cat,
                        title=check_id,
                        description=short_desc,
                        severity=sev,
                        confidence=1.0,
                        rule_id=check_id,
                        rule_name=check_id,
                        location=loc,
                        correlation_key=corr_key,
                        raw_data=issue
                    )
                    findings.append(finding)
            except Exception as e:
                print(f"⚠️ Errore parsing Semgrep JSON: {e}")
    return findings
