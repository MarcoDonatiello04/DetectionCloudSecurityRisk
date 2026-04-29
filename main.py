import os
import subprocess
import sys

def main():
    print("🚀 Inizializzazione Cloud Security Scanner (Checkov)...")
    
    # Cerchiamo l'eseguibile checkov
    checkov_bin = "checkov"
    if os.path.exists("./.venv/bin/checkov"):
        checkov_bin = "./.venv/bin/checkov"
        
    print(f"🔍 Avvio analisi di sicurezza sulla directory corrente: {os.path.abspath('.')}")
    print("-" * 50)
    
    try:
        # Costruiamo il comando: usiamo checkov con il file di configurazione se presente
        cmd = [checkov_bin]
        if os.path.exists(".checkov.yaml"):
            cmd.extend(["--config-file", ".checkov.yaml"])
        else:
            cmd.extend(["-d", "."])
            
        # Eseguiamo checkov lasciando che stampi l'output direttamente su stdout
        result = subprocess.run(cmd)
        
        print("-" * 50)
        if result.returncode == 0:
            print("✅ Scansione completata: Nessuna vulnerabilità rilevata.")
        else:
            print(f"⚠️ Scansione completata con codice di uscita {result.returncode}.")
            print("❌ Sono state rilevate possibili vulnerabilità di sicurezza nel codice (vedi output sopra).")
            
        sys.exit(result.returncode)
            
    except FileNotFoundError:
        print(f"❌ Errore: l'eseguibile '{checkov_bin}' non è stato trovato.")
        print("Assicurati di aver installato le dipendenze con 'pip install -r requirements.txt'")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Errore imprevisto durante l'esecuzione di checkov: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
