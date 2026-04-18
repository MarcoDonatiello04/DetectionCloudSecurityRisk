import os
import hcl2
from typing import Dict, List, Any, Optional
from src.interfaces.scanner_interface import ICloudScanner

class TerraformScanner(ICloudScanner):
    """
    Implementazione dello scanner per i file IaC di tipo Terraform (.tf).
    """

    def parse_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Legge e analizza un file .tf restituendo un dizionario."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return hcl2.load(f)
        except Exception as e:
            print(f"❌ Errore parsing del file {file_path}: {e}")
            return None

    def extract_resources(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Estrae i dettagli delle risorse (tipo, nome, configurazione) dai dati HCL."""
        resources = []
        
        # Verifichiamo se ci sono risorse definite nel file
        if not parsed_data or "resource" not in parsed_data:
            return resources

        # Il parser HCL2 restituisce le risorse come una lista di dizionari
        for resource_block in parsed_data["resource"]:
            for resource_type, instances in resource_block.items():
                for name, config in instances.items():
                    resources.append({
                        "type": resource_type,
                        "name": name,
                        "config": config
                    })
        return resources

    def scan_folder(self, folder_path: str) -> Dict[str, Dict[str, Any]]:
        """Scansiona la cartella e analizza tutti i file .tf trovati."""
        parsed_files = {}
        for root, _, files in os.walk(folder_path):
            for file in files:
                if file.endswith(".tf"):
                    full_path = os.path.join(root, file)
                    parsed = self.parse_file(full_path)
                    if parsed:
                        parsed_files[full_path] = parsed
        return parsed_files

    def print_summary(self, parsed_files: Dict[str, Dict[str, Any]]) -> None:
        """Stampa a video il riepilogo delle risorse trovate."""
        if not parsed_files:
            print("Nessun file .tf valido trovato.")
            return

        for file_path, data in parsed_files.items():
            print("\n==================================================")
            print(f"📄 FILE: {file_path}")
            print("==================================================")
            
            resources = self.extract_resources(data)
            
            if not resources:
                print("  (Nessuna risorsa trovata in questo file)")
            else:
                for r in resources:
                    print(f"  🔹 Risorsa: {r['type']}")
                    print(f"     Nome:    {r['name']}")
                    # print(f"     Config:  {r['config']}")
                    print("-" * 20)

# --- PUNTO DI AVVIO (Esempio d'uso standalone) ---
if __name__ == "__main__":
    scanner = TerraformScanner()
    
    # Esegue il comando nella radice del progetto
    cartella_attuale = "../.." 
    str_abs = os.path.abspath(cartella_attuale)
    
    print(f"🔍 Avvio analisi Terraform tramite TerraformScanner nella cartella: {str_abs}")
    
    # 1. Scansiona e analizza
    risultati = scanner.scan_folder(cartella_attuale)
    
    # 2. Mostra i risultati a video
    scanner.print_summary(risultati)