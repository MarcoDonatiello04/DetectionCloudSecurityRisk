import os
import json
import subprocess

def is_openapi_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            if 'openapi:' in content or 'swagger:' in content:
                return True
    except Exception:
        pass
    return False

def run_spectral(target_dir="."):
    print("🚀 Esecuzione Spectral API Scanner (OWASP)...")
    openapi_file = None
    for root, dirs, files in os.walk(target_dir):
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
    
    ruleset_path = "rules/spectral-owasp.yaml"
    if not os.path.exists(ruleset_path):
        # Fallback se lo script è eseguito da una dir diversa
        ruleset_path = os.path.join(os.path.dirname(__file__), "../../rules/spectral-owasp.yaml")

    cmd = ["npx", "@stoplight/spectral-cli", "lint", openapi_file, "--ruleset", ruleset_path, "--format", "json", "-o", "spectral_report.json"]
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
