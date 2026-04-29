import os
import subprocess
import sys

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
    print("🚀 Inizializzazione Spectral API Scanner (OWASP)...")
    spectral_found = False
    has_errors = False
    
    for root, dirs, files in os.walk("."):
        # Ignoriamo le cartelle nascoste come .venv, .terraform, .git
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        for file in files:
            if file.endswith(('.yaml', '.yml', '.json')):
                filepath = os.path.join(root, file)
                if is_openapi_file(filepath):
                    print(f"\n📄 Trovato file OpenAPI: {filepath}")
                    print("🔍 Avvio analisi Spectral...")
                    try:
                        # Usiamo npx per lanciare spectral senza doverlo installare globalmente
                        cmd = ["npx", "@stoplight/spectral-cli", "lint", filepath, "--ruleset", "spectral-owasp.yaml"]
                        result = subprocess.run(cmd, capture_output=True, text=True)
                        
                        output = result.stdout + result.stderr
                        print(output)
                        
                        # Catturiamo i risultati: se contiene "error", la configurazione non è sicura
                        if "error" in output.lower():
                            print(f"❌ La configurazione API in {filepath} NON è sicura (rilevati errori OWASP).")
                            has_errors = True
                        else:
                            print(f"✅ La configurazione API in {filepath} è sicura e conforme alle regole OWASP.")
                        
                        spectral_found = True
                        print("-" * 50)
                    except Exception as e:
                        print(f"❌ Errore durante l'esecuzione di Spectral su {filepath}: {e}")
                        has_errors = True
                        
    if not spectral_found:
        print("ℹ️ Nessun file OpenAPI trovato per l'analisi Spectral.\n" + "-" * 50)
        
    return has_errors

def run_checkov():
    print("🚀 Inizializzazione Cloud Security Scanner (Checkov)...")
    
    checkov_bin = "checkov"
    if os.path.exists("./.venv/bin/checkov"):
        checkov_bin = "./.venv/bin/checkov"
        
    print(f"🔍 Avvio analisi di sicurezza sulla directory corrente: {os.path.abspath('.')}")
    print("-" * 50)
    
    try:
        cmd = [checkov_bin, "--skip-download", "--no-cert-verify"]
        if os.path.exists(".checkov.yaml"):
            cmd.extend(["--config-file", ".checkov.yaml"])
        else:
            cmd.extend(["-d", "."])
            
        result = subprocess.run(cmd)
        
        print("-" * 50)
        if result.returncode == 0:
            print("✅ Scansione Checkov completata: Nessuna vulnerabilità rilevata.")
            return False
        else:
            print(f"⚠️ Scansione Checkov completata con codice di uscita {result.returncode}.")
            print("❌ Sono state rilevate possibili vulnerabilità di sicurezza nell'infrastruttura (vedi output sopra).")
            return True
            
    except FileNotFoundError:
        print(f"❌ Errore: l'eseguibile '{checkov_bin}' non è stato trovato.")
        print("Assicurati di aver installato le dipendenze con 'pip install -r requirements.txt'")
        return True
    except Exception as e:
        print(f"❌ Errore imprevisto durante l'esecuzione di checkov: {e}")
        return True

def main():
    spectral_errors = run_spectral()
    checkov_errors = run_checkov()
    
    if spectral_errors or checkov_errors:
        print("\n❌ L'analisi globale ha rilevato problemi di sicurezza. Risolvi gli errori segnalati.")
        sys.exit(1)
    else:
        print("\n✅ L'analisi globale è stata superata. Il sistema è sicuro.")
        sys.exit(0)

if __name__ == "__main__":
    main()
