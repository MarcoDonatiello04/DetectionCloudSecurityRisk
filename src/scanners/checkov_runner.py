import os
import json
import subprocess
from typing import List
from Finding import Finding, FindingSource, FindingCategory, Severity, CodeLocation

def run_checkov(target_dir=".") -> List[Finding]:
    print("🚀 Esecuzione Cloud Security Scanner (Checkov)...")
    checkov_bin = "checkov"
    if os.path.exists("./.venv/bin/checkov"):
        checkov_bin = "./.venv/bin/checkov"
    
    cmd = [checkov_bin, "--skip-download", "--no-cert-verify", "-o", "json"]
    if os.path.exists(".checkov.yaml"):
        cmd.extend(["--config-file", ".checkov.yaml"])
    else:
        cmd.extend(["-d", target_dir])
    
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
            
            findings = []
            reports = [data] if isinstance(data, dict) else data
            idx = 0
            for report in reports:
                for check in report.get("results", {}).get("failed_checks", []):
                    idx += 1
                    check_id = check.get("check_id", "unknown")
                    is_storage = "s3" in check_id.lower() or "acl" in check_id.lower()
                    
                    loc = CodeLocation(
                        file_path=check.get("file_path", ""),
                        start_line=check.get("file_line_range", [None])[0]
                    )
                    
                    finding = Finding(
                        finding_id=f"checkov-{check_id}-{idx}",
                        source=FindingSource.CHECKOV,
                        category=FindingCategory.STORAGE if is_storage else FindingCategory.MISCONFIGURATION,
                        title=check.get("check_name", "IaC Misconfiguration"),
                        description=f"{check.get('check_name')} per la risorsa {check.get('resource', 'N/A')}",
                        severity=Severity.CRITICAL if is_storage else Severity.MEDIUM,
                        confidence=1.0,
                        rule_id=check_id,
                        rule_name=check.get("check_name"),
                        resource_id=check.get("resource"),
                        location=loc,
                        raw_data=check
                    )
                    findings.append(finding)
            return findings
    except Exception as e:
        print(f"⚠️ Errore parsing Checkov JSON: {e}")
    return []

