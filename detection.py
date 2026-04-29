import boto3
import subprocess
import os
from botocore.exceptions import ClientError, NoCredentialsError

# 1. Configurazione: puntiamo a LocalStack e inseriamo credenziali fittizie
ENDPOINT = "http://localhost:4566"

s3 = boto3.client(
    's3',
    endpoint_url=ENDPOINT,
    aws_access_key_id='test',          # <--- AGGIUNGI QUESTO
    aws_secret_access_key='test',      # <--- AGGIUNGI QUESTO
    region_name='us-east-1'
)

def avvia_audit():
    try:
        print("🛡️  Inizio scansione sicurezza bucket S3...")
        
        # 2. Elenca tutti i bucket presenti
        response = s3.list_buckets()
        buckets = response.get('Buckets', [])

        if not buckets:
            print("❓ Nessun bucket trovato. Hai fatto 'tflocal apply'?")
            return

        for b in buckets:
            nome = b['Name']
            print(f"\n--- Analisi Bucket: {nome} ---")
            
            try:
                # 3. Controllo se il blocco accesso pubblico è attivo
                pab = s3.get_public_access_block(Bucket=nome)
                config = pab['PublicAccessBlockConfiguration']
                
                # Se i parametri sono False (come nel tuo file Terraform), segnaliamo il rischio
                if config['BlockPublicAcls'] == False:
                    print(f"❌ RISCHIO RILEVATO: Il blocco ACL pubbliche è DISATTIVATO!")
                    print(f"👉 Misconfiguration rilevata (OWASP A05:2021)")
                else:
                    print(f"✅ OK: Il bucket è protetto correttamente.")
                    
            except ClientError as e:
                # Se non c'è una configurazione, il bucket è potenzialmente esposto
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    print(f"⚠️  ALLERTA CRITICA: Nessuna configurazione di sicurezza trovata!")
            
            # --- ESECUZIONE S3SCANNER (INGANNO LOCALSTACK) ---
            print(f"🕵️  Avvio s3scanner sul bucket '{nome}'...")
            env = os.environ.copy()
            # Impostiamo le variabili d'ambiente in modo che gli SDK AWS interni a s3scanner 
            # puntino al nostro LocalStack invece che ad AWS reale.
            env["AWS_ACCESS_KEY_ID"] = "test"
            env["AWS_SECRET_ACCESS_KEY"] = "test"
            env["AWS_DEFAULT_REGION"] = "us-east-1"
            
            # Forziamo l'endpoint a localhost:4566 come consigliato per LocalStack
            env["AWS_ENDPOINT_URL"] = ENDPOINT
            env["S3_ENDPOINT_URL"] = ENDPOINT
            
            # Assicuriamoci di forzare l'uso del Path Style per AWS SDK
            env["AWS_S3_USE_PATH_STYLE"] = "true"

            try:
                # S3Scanner richiede che le opzioni globali (--endpoint-url) vengano prima del comando 'scan'
                process = subprocess.run(
                    f"s3scanner --endpoint-url {ENDPOINT} --endpoint-address-style path scan --bucket {nome}",
                    shell=True,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # Stampiamo l'output ripulito
                output = process.stdout.strip()
                if output:
                    print(f"[s3scanner output] {output}")
                
                if process.stderr.strip():
                    print(f"[s3scanner err] {process.stderr.strip()}")
            except Exception as e:
                print(f"❌ Impossibile eseguire s3scanner: {e}")
    
    except NoCredentialsError:
        print("❌ Errore: Credenziali non trovate. Verifica la configurazione di boto3.")
    except Exception as e:
        print(f"❌ Errore imprevisto: {e}")

if __name__ == "__main__":
    avvia_audit()