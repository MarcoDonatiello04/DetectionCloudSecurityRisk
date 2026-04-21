import os
from src.core.terraform_scanner import TerraformScanner

def main():
    print("🚀 Inizializzazione Cloud Security Scanner...")
    
    # Istanziamo il nostro scanner
    scanner = TerraformScanner()
    
    # Configuriamo la cartella da scansionare
    cartella_target = "."
    
    print(f"🔍 Avvio analisi dei file Terraform (.tf) nella cartella: {os.path.abspath(cartella_target)}")
    
    # Esegui scansione
    risultati = scanner.scan_folder(cartella_target)
    
    if not risultati:
        print("❌ Nessun file .tf valido trovato.")
        return
        
    for file_path, data in risultati.items():
        print("\n==================================================")
        print(f"📄 FILE: {file_path}")
        print("==================================================")
        
        resources = scanner.extract_resources(data)
        if not resources:
            print("  (Nessuna risorsa trovata in questo file)")
        else:
            for r in resources:
                resource_type = r['type']
                name = r['name']
                config = r['config']
                
                print(f"  🔹 Risorsa: {resource_type}")
                print(f"     Nome:    {name}")
                
                # Analisi specifica di sicurezza per S3 Bucket
                if resource_type == "aws_s3_bucket":
                    bucket_entity = scanner._parse_bucket_entity(resource_type, name, config)
                    risks = bucket_entity.evaluate_risks()
                    
                    if risks:
                        print("     ⚠️  Rischi rilevati:")
                        for risk in risks:
                            print(f"        - {risk}")
                    else:
                        print("     ✅ Nessun rischio rilevato (policy e object_ownership conformi).")
                
                print("-" * 20)

    print("\n✅ Scansione completata!")

if __name__ == "__main__":
    main()
