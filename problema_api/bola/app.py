import os
import requests
# pyrefly: ignore [missing-import]
import jwt
# pyrefly: ignore [missing-import]
from flask import Flask, request, jsonify

app = Flask(__name__)

# Configurazione Keycloak
KEYCLOAK_SERVER_URL = os.environ.get("KEYCLOAK_SERVER_URL", "http://keycloak:8080")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "myrealm")
JWKS_URL = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs"

# Database fittizio in memoria (Strutturato per tipo di risorsa)
# Esempio:
# {
#   "orders": { "100": "user_a", "200": "user_b" },
#   "invoices": { "100": "user_a", "200": "user_b" }
# }
MOCK_DATABASE = {
    "orders": {
        "101": "user_a",
        "102": "user_b"
    }
}

def get_keycloak_public_key(token: str):
    """Recupera la chiave pubblica da Keycloak per la validazione della firma."""
    try:
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        if not kid:
            return None
        
        response = requests.get(JWKS_URL, timeout=3)
        response.raise_for_status()
        jwks = response.json()
        
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                return jwt.algorithms.RSAAlgorithm.from_jwk(key)
    except Exception as e:
        app.logger.debug(f"JWKS lookup fallito: {e}")
    return None

def extract_username(request) -> str:
    """
    Estrae lo username dal token JWT nell'header di Autorizzazione.
    Supporta la validazione reale di Keycloak (RS256) ed effettua un fallback
    automatico sulla decodifica della firma per i token sintetici di simulazione.
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
        
    token = auth_header.split(" ")[1]
    
    # 1. Tentativo di validazione reale con Keycloak
    try:
        public_key = get_keycloak_public_key(token)
        if public_key:
            payload = jwt.decode(
                token, 
                public_key, 
                algorithms=["RS256"], 
                options={"verify_aud": False}
            )
            return payload.get("preferred_username")
    except Exception as e:
        app.logger.debug(f"Verifica Keycloak non riuscita, provo fallback manuale: {e}")

    # 2. Fallback manuale robusto (estrazione e decodifica base64 del payload del JWT)
    try:
        parts = token.split(".")
        if len(parts) == 3:
            payload_b64 = parts[1]
            # Ripristina padding base64 corretto
            payload_b64 += "=" * (-len(payload_b64) % 4)
            import base64
            import json
            payload_json = base64.urlsafe_b64decode(payload_b64).decode("utf-8")
            payload = json.loads(payload_json)
            return payload.get("preferred_username") or payload.get("sub")
    except Exception as e:
        app.logger.error(f"Errore decodifica token manuale: {e}")
        
    return None

@app.route("/test/seed", methods=["POST"])
def seed_database():
    """
    Endpoint di Automated Seeding.
    Riceve un payload JSON strutturato e sovrascrive o popola il database in memoria.
    """
    global MOCK_DATABASE
    try:
        payload = request.get_json()
        if not payload or not isinstance(payload, dict):
            return jsonify({"error": "Invalid payload format. Expected JSON dictionary."}), 400
            
        # Carica i dati del seeding nel database in memoria
        for resource_name, resource_data in payload.items():
            if resource_name not in MOCK_DATABASE:
                MOCK_DATABASE[resource_name] = {}
            for res_id, owner in resource_data.items():
                MOCK_DATABASE[resource_name][res_id] = owner
                
        app.logger.info(f"Database popolato con successo tramite Seeding. Risorse attive: {list(MOCK_DATABASE.keys())}")
        return jsonify({"status": "success", "message": "Database seeded successfully"}), 200
    except Exception as e:
        return jsonify({"error": f"Seeding failed: {str(e)}"}), 500

@app.route("/api/<resource_name>/<resource_id>", methods=["GET"])
def get_generic_resource(resource_name, resource_id):
    """
    Rotta jolly dinamica e unificata vulnerabile a BOLA (OWASP API1:2023).
    Verifica l'autenticazione tramite JWT (Keycloak o fallback), ma non implementa
    alcun controllo di autorizzazione di ownership rispetto alla risorsa richiesta.
    """
    # 1. Verifica autenticazione (estrazione username dal token)
    username = extract_username(request)
    if not username:
        return jsonify({"error": "Unauthorized: Missing or invalid token"}), 401
        
    # 2. Controllo esistenza risorsa nel DB in memoria
    if resource_name not in MOCK_DATABASE or resource_id not in MOCK_DATABASE[resource_name]:
        return jsonify({"error": f"Resource '{resource_name}' with ID '{resource_id}' not found"}), 404
        
    owner = MOCK_DATABASE[resource_name][resource_id]
    
    # -------------------------------------------------------------------------
    # VULNERABILITA' BOLA (Broken Object Level Authorization)
    # -------------------------------------------------------------------------
    # Qualsiasi utente autenticato può accedere alle risorse di chiunque altro!
    # Non controlliamo se 'username' == 'owner'.
    # -------------------------------------------------------------------------
    return jsonify({
        "resource_name": resource_name,
        "resource_id": resource_id,
        "owner": owner,
        "details": f"Dati sensibili riservati per la risorsa {resource_name} (ID {resource_id})",
        "accessed_by": username,
        "status": "success"
    }), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
