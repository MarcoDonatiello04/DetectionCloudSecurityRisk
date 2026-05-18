import os
import json
import subprocess
from typing import List
from src.models.finding from src.models.finding import Finding, FindingSource, FindingCategory, Severity, CodeLocation

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
                    check_id = check.get("check_id", "unknown")
                    check_id_lower = check_id.lower()
                    resource_id = check.get("resource", "unknown")
                    
                    # Determinazione Categoria più accurata
                    if "iam" in check_id_lower or "iam" in resource_id.lower():
                        cat = FindingCategory.IAM
                    elif "s3" in check_id_lower or "acl" in check_id_lower or "storage" in resource_id.lower():
                        cat = FindingCategory.STORAGE
                    elif "sg" in check_id_lower or "security_group" in resource_id.lower() or "vpc" in resource_id.lower() or "port" in check_id_lower:
                        cat = FindingCategory.NETWORK
                    elif "encrypt" in check_id_lower or "kms" in resource_id.lower():
                        cat = FindingCategory.ENCRYPTION
                    elif "log" in check_id_lower or "trail" in resource_id.lower():
                        cat = FindingCategory.LOGGING
                    else:
                        cat = FindingCategory.MISCONFIGURATION

                    # Derivazione Severity basata su impatto
                    if cat in (FindingCategory.IAM, FindingCategory.STORAGE) and ("public" in check_id_lower or "star" in check_id_lower or "admin" in check_id_lower):
                        sev = Severity.CRITICAL
                    elif cat in (FindingCategory.NETWORK, FindingCategory.ENCRYPTION) or "public" in check_id_lower:
                        sev = Severity.HIGH
                    else:
                        sev = Severity.MEDIUM

                    loc = CodeLocation(
                        file_path=check.get("file_path", ""),
                        start_line=check.get("file_line_range", [None])[0]
                    )
                    
                    target_ident = f"{resource_id}:{loc.file_path}"
                    finding_id = Finding.generate_deterministic_id(FindingSource.CHECKOV, check_id, target_ident)
                    
                    corr_key = resource_id.split(".")[-1] if "." in resource_id else resource_id
                    
                    finding = Finding(
                        finding_id=finding_id,
                        source=FindingSource.CHECKOV,
                        category=cat,
                        title=check.get("check_name", "IaC Misconfiguration"),
                        description=f"{check.get('check_name')} per la risorsa {resource_id}",
                        severity=sev,
                        confidence=1.0,
                        rule_id=check_id,
                        rule_name=check.get("check_name"),
                        resource_id=resource_id,
                        location=loc,
                        correlation_key=corr_key,
                        raw_data=check
                    )
                    findings.append(finding)
            return findings
    except Exception as e:
        print(f"⚠️ Errore parsing Checkov JSON: {e}")
    return []

