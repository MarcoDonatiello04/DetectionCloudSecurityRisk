import os
import json
import subprocess

def run_checkov(target_dir="."):
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
            if isinstance(data, dict):
                return [data]
            return data
    except Exception as e:
        print(f"⚠️ Errore parsing Checkov JSON: {e}")
    return []
