import os
import hcl2
from typing import Dict, List, Any, Optional
from src.interfaces.scanner_interface import ICloudScanner
from src.model.BucketEntity import BucketEntity

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

    def _parse_bucket_entity(self, resource_type: str, name: str, config: Dict[str, Any]) -> BucketEntity:
        """Helper per trasformare i dizionari in oggetti BucketEntity a seconda del provider."""
        
        # Una funzione lambda per estrarre valori da config (HCL2 di solito mette in liste)
        def get_val(key, default=None):
            val = config.get(key)
            if isinstance(val, list) and len(val) > 0:
                return val[0]
            return val if val is not None else default

        bucket_name = get_val("bucket", get_val("name", name))
        acl = get_val("acl")
        region = get_val("location", get_val("region"))
        tags = get_val("tags")
        
        # Versioning logica: a volte è un blocco "versioning" [{ "enabled": true }]
        versioning_enabled = False
        versioning_block = get_val("versioning")
        if isinstance(versioning_block, dict):
            versioning_enabled = versioning_block.get("enabled", [False])[0] if isinstance(versioning_block.get("enabled"), list) else versioning_block.get("enabled", False)
        elif str(get_val("versioning")).lower() in ["true", "enabled"]:
             versioning_enabled = True

        # Encryption logica: a volte server_side_encryption_configuration ...
        encryption_enabled = False
        if "server_side_encryption_configuration" in config:
            encryption_enabled = True

        # Logging logica
        logging_enabled = False
        if "logging" in config:
            logging_enabled = True

        # Public Access Block (per AWS, a volte è una risorsa separata, ma per semplicità qui vediamo se c'è un hint)
        public_access_block = False
        
        policy = get_val("policy")
        object_ownership = get_val("object_ownership")
        
        return BucketEntity(
            name=bucket_name,
            provider=resource_type,
            acl=acl,
            policies=policy,
            versioning_enabled=versioning_enabled,
            encryption_enabled=encryption_enabled,
            public_access_block=public_access_block,
            logging_enabled=logging_enabled,
            tags=tags,
            region=region,
            raw_config=config,
            object_ownership=object_ownership
        )

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


    