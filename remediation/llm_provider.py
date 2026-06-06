"""
Gestisce la comunicazione con l'LLM locale tramite Ollama.
Responsabilità:
- Controllare la disponibilità del server Ollama su http://localhost:11434.
- Interrogare dinamicamente i modelli installati localmente (es. qwen3:8b, llama3.1:8b).
- Eseguire prompt engineering per generare remediation in formato JSON strutturato.
- Fornire un simulatore offline ad alta fedeltà se il demone Ollama è offline.
"""

import json
import logging
import requests
from typing import Dict, Any, Optional

logger = logging.getLogger("SecurityPlatform.Remediation.LlmProvider")

class LlmProvider:
    """
    Gestore delle richieste dirette all'istanza locale di Ollama con simulatore locale integrato.
    """

    def __init__(self, base_url: str = "http://localhost:11434"):
        self.base_url = base_url
        self._cached_model = None
        self._checked_online = False

    def get_available_model(self) -> Optional[str]:
        """
        Interroga il server Ollama per trovare il primo modello disponibile.
        Ritorna un modello simulato se il server è offline o non ha modelli.
        Usa la cache per evitare chiamate ripetute.
        """
        if self._checked_online:
            return self._cached_model

        try:
            url = f"{self.base_url}/api/tags"
            response = requests.get(url, timeout=1.0)
            if response.status_code == 200:
                data = response.json()
                models = data.get("models", [])
                if models:
                    self._cached_model = models[0].get("name")
                    logger.info(f"Rilevato modello locale Ollama attivo: {self._cached_model}")
                else:
                    self._cached_model = "llama3.1:8b (Simulato)"
                    logger.warning("Ollama attivo ma nessun modello scaricato trovato. Attivazione Simulatore Locale Llama 3.1.")
            else:
                self._cached_model = "llama3.1:8b (Simulato)"
                logger.warning(f"Risposta Ollama non corretta ({response.status_code}). Attivazione Simulatore Locale Llama 3.1.")
            self._checked_online = True
            return self._cached_model
        except Exception as e:
            logger.warning(f"Ollama server offline in {self.base_url} ({e}). Attivazione Simulatore Locale Llama 3.1.")
            self._cached_model = "llama3.1:8b (Simulato)"
            self._checked_online = True
            return self._cached_model

    def generate_remediation(
        self,
        finding_id: str,
        title: str,
        category: str,
        source: str,
        description: str
    ) -> Optional[Dict[str, Any]]:
        """
        Invia la richiesta a Ollama per generare una remediation strutturata JSON.
        Se Ollama è contrassegnato come simulato, richiama il simulatore offline locale.
        """
        model = self.get_available_model()
        if not model:
            # Fallback di emergenza
            return self._simulate_generation(finding_id, title, category, source, description)

        if "Simulato" in model:
            logger.info("Ollama offline. Generazione della remediation tramite Simulatore Locale Llama 3.1...")
            return self._simulate_generation(finding_id, title, category, source, description)

        # Costruisce il prompt strutturato per Ollama reale
        prompt = f"""
        Sei un esperto Senior di Cybersecurity ed Cloud Security Architect.
        Genera le linee guida di remediation in italiano per la seguente vulnerabilità di sicurezza:

        - ID Regola/Finding: {finding_id}
        - Titolo: {title}
        - Categoria: {category}
        - Sorgente Scanner: {source}
        - Descrizione originale: {description}

        Devi restituire esclusivamente un oggetto JSON valido avente i seguenti campi:
        {{
            "title": "Titolo chiaro e arricchito in italiano",
            "description": "Spiegazione dettagliata della causa della vulnerabilità in italiano",
            "impact": "Impatto di sicurezza e rischi reali se sfruttata in italiano",
            "remediation_steps": [
                "Istruzione o azione correttiva precisa 1 (italiano)",
                "Istruzione o azione correttiva precisa 2 (italiano)"
            ],
            "example": "Esempio di codice corretto (Terraform se IaC, o codice/configurazione API protetta in base al contesto)"
        }}
        """

        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.2
            }
        }

        try:
            url = f"{self.base_url}/api/generate"
            logger.info(f"Invio prompt a Ollama utilizzando modello '{model}'...")
            response = requests.post(url, json=payload, timeout=20.0)
            
            if response.status_code == 200:
                res_data = response.json()
                response_text = res_data.get("response", "").strip()
                parsed_remediation = json.loads(response_text)
                logger.info("Remediation generata con successo da LLM locale.")
                return parsed_remediation
            else:
                logger.error(f"Errore chiamata Ollama API: {response.status_code}. Uso del simulatore locale.")
                return self._simulate_generation(finding_id, title, category, source, description)
        except Exception as e:
            logger.error(f"Eccezione chiamata Ollama: {e}. Uso del simulatore locale.")
            return self._simulate_generation(finding_id, title, category, source, description)

    def _simulate_generation(
        self,
        finding_id: str,
        title: str,
        category: str,
        source: str,
        description: str
    ) -> Dict[str, Any]:
        """
        Simulatore offline ad alta fedeltà Llama 3.1. Ritorna risposte realistiche strutturate in JSON.
        """
        category_upper = category.upper()
        source_upper = source.upper()

        if "AUTHORIZATION" in category_upper or "BOLA" in title.upper() or "IDOR" in title.upper():
            return {
                "title": "Controllo di Autorizzazione Mancante (BOLA / IDOR)",
                "description": f"L'applicazione non verifica i permessi di accesso per la risorsa identificata nell'endpoint. Ciò consente a utenti autenticati di accedere arbitrariamente alle risorse altrui manipolando i parametri identificativi (Broken Object Level Authorization).",
                "impact": "Esposizione e alterazione non autorizzata di dati sensibili appartenenti ad altri utenti, compromissione dell'integrità dei record a database.",
                "remediation_steps": [
                    "Implementare una verifica di ownership lato server estraendo il JWT del client corrente.",
                    "Validare che il proprietario della risorsa coincida con l'identità dell'utente autenticato prima di restituire i dati.",
                    "Sostituire gli ID sequenziali (es. database auto-increment) con UUID v4 non prevedibili."
                ],
                "example": """# Codice Corretto (Python Flask)
@app.route('/api/v1/resources/<resource_id>', methods=['GET'])
@jwt_required()
def get_resource(resource_id):
    current_user = get_jwt_identity()
    resource = db.get_resource(resource_id)
    
    # VERIFICA PROPRIETÀ (BOLA FIX)
    if resource.owner_id != current_user:
        return jsonify({"error": "Forbidden"}), 403
        
    return jsonify(resource.to_dict()), 200"""
            }

        elif "AUTHENTICATION" in category_upper or "AUTHN" in category_upper:
            return {
                "title": "Violazione dei Controlli di Autenticazione",
                "description": "L'endpoint espone funzionalità o dati sensibili senza richiedere una sessione o un token di autenticazione valido, oppure accetta token scaduti/non firmati.",
                "impact": "Accesso non autorizzato ad aree critiche o amministrative, impersonificazione di altri utenti e furto di identità digitale.",
                "remediation_steps": [
                    "Applicare middleware di autenticazione robusti su tutti gli endpoint sensibili.",
                    "Inviare un codice di stato HTTP 401 Unauthorized per le richieste prive di credenziali valide.",
                    "Verificare sempre la firma crittografica del token JWT lato server."
                ],
                "example": """# Codice Corretto (Python Flask JWT)
@app.route('/api/v1/admin/dashboard', methods=['GET'])
@jwt_required() # Protezione con token JWT
def get_admin_dashboard():
    # Verifica il ruolo o claims associati al token
    claims = get_jwt()
    if claims.get("role") != "admin":
        return jsonify({"error": "Role administrator required"}), 403
    return jsonify({"data": "sensitive admin data"}), 200"""
            }

        elif "RATE_LIMITING" in category_upper or "LIMIT" in title.upper() or "DOS" in title.upper():
            return {
                "title": "Assenza di Rate Limiting su Endpoint Sensibile",
                "description": "L'API non limita il numero di richieste consecutive che un client può inviare in un intervallo di tempo limitato. Questo consente brute-force di credenziali o Denial of Service.",
                "impact": "Saturazione delle risorse del server, brute-force di password o token di sblocco con conseguente compromissione degli account utente.",
                "remediation_steps": [
                    "Configurare un middleware di rate limiting (es. token bucket o leaky bucket).",
                    "Limitare a massimo 5 richieste al minuto gli endpoint critici come login, reset password e token generation.",
                    "Ritornare lo stato HTTP 429 Too Many Requests con header Retry-After quando il limite viene superato."
                ],
                "example": """# Codice Corretto (Flask-Limiter)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

# Limite di 5 tentativi di login al minuto per IP client
@app.route("/api/v1/auth/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    # Logica di autenticazione sicura
    return jsonify({"status": "success"}), 200"""
            }

        elif source_upper == "CHECKOV" or "IAC" in category_upper or "MISCONFIGURATION" in category_upper:
            return {
                "title": f"Misconfiguration Infrastrutturale IaC: {finding_id}",
                "description": f"Il codice di configurazione infrastrutturale (Terraform) contiene una definizione non sicura per la regola {finding_id}. La risorsa cloud associata risulta eccessivamente esposta o priva di cifratura/logging.",
                "impact": "Accesso non autorizzato alle risorse cloud, furto di dati riservati, potenziale manomissione dell'infrastruttura di produzione.",
                "remediation_steps": [
                    "Restringere l'accesso specificando regole di rete e IAM minime indispensabili.",
                    "Abilitare la cifratura a riposo (encryption at rest) tramite chiavi gestite (KMS).",
                    "Attivare il log dei flussi di rete e degli accessi amministrativi sulla risorsa."
                ],
                "example": """# Codice Terraform Corretto
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-bucket-cloud-data"
}

# Blocco totale degli accessi pubblici al bucket S3
resource "aws_s3_bucket_public_access_block" "block" {
  bucket                  = aws_s3_bucket.secure_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}"""
            }

        else:
            return {
                "title": f"Vulnerabilità Rilevata: {title}",
                "description": f"L'analisi statica/dinamica ha identificato un potenziale rischio: '{description}'. È necessaria una revisione per allinearsi alle best practice di sicurezza.",
                "impact": "Aumento della superficie d'attacco ed esposizione ad exploit di gravità variabile a seconda dell'ambiente di deployment.",
                "remediation_steps": [
                    "Rivedere la configurazione della risorsa interessata.",
                    "Applicare le patch o gli aggiornamenti di sicurezza raccomandati.",
                    "Isolare la risorsa sensibile limitando l'esposizione sulla rete pubblica."
                ],
                "example": """# Configurazione Sicura Consigliata
{
  "status": "secure_configuration_applied",
  "verification": "required"
}"""
            }
