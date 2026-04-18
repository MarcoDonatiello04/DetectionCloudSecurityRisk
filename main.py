import os
from src.core.terraform_scanner import TerraformScanner

def main():
    print("🚀 Inizializzazione Cloud Security Scanner...")
    
    # Istanziamo il nostro scanner passando dalla nuova interfaccia
    scanner = TerraformScanner()
    
    # Configuriamo la cartella da scansionare (se stesso / root directory del progetto)
    # Ignoriamo le cartelle come ".venv" o "src" se vogliamo analizzare solo le root o test?
    # In questo caso scanner.scan_folder cercherà tutti i .tf
    cartella_target = "."
    
    print(f"🔍 Avvio analisi dei file Terraform (.tf) nella cartella: {os.path.abspath(cartella_target)}")
    
    # Esegui scansione
    risultati = scanner.scan_folder(cartella_target)
    
    # Mostra risultati
    scanner.print_summary(risultati)
    print("\n✅ Scansione completata!")

if __name__ == "__main__":
    main()
