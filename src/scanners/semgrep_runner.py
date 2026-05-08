import os
import json
import subprocess

def run_semgrep(target_dir="."):
    print("🚀 Esecuzione Static Analysis (Semgrep)...")
    semgrep_bin = "semgrep"
    if os.path.exists("./.venv/bin/semgrep"):
        semgrep_bin = "./.venv/bin/semgrep"

    cmd = [semgrep_bin, "scan", "--config=p/owasp-top-10", "--config=p/api-security", "--json", "-o", "semgrep_report.json", target_dir]
    subprocess.run(cmd, capture_output=True, text=True)
    
    if os.path.exists("semgrep_report.json"):
        with open("semgrep_report.json", "r") as f:
            try:
                data = json.load(f)
                return data.get("results", [])
            except:
                return []
    return []
