import os
import requests
import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)

# Configurazione Keycloak ottenuta dall'ambiente o impostata a valori di default
KEYCLOAK_SERVER_URL = os.environ.get("KEYCLOAK_SERVER_URL", "http://keycloak:8080")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "myrealm")
JWKS_URL = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs"

# Database fittizio in memoria (Order ID -> Proprietario della risorsa)
# L'ordine 102 appartiene a 'user_b', mentre l'ordine 101 appartiene a 'user_a'.
ORDERS_DATABASE = {
    "101": "user_a",
    "102": "user_b",
    "103": "admin_user"
}

def get_keycloak_public_key(token: str):
    """
    Recupera la chiave pubblica (JWK) corretta da Keycloak analizzando l'header del JWT.
    In un'applicazione reale, le chiavi dovrebbero essere memorizzate in cache
    per evitare di fare una richiesta HTTP a Keycloak per ogni chiamata API.
    """
    try:
        # Estrae l'header non verificato per ottenere il Key ID ('kid')
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        if not kid:
            return None
        
        # Recupera il JSON Web Key Set (JWKS) da Keycloak
        response = requests.get(JWKS_URL, timeout=5)
        response.raise_for_status()
        jwks = response.json()
        
        # Cerca la chiave corrispondente al 'kid' nell'elenco delle chiavi certificate
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                # Converte la chiave JWK nel formato PEM pubblico supportato da PyJWT
                return jwt.algorithms.RSAAlgorithm.from_jwk(key)
    except Exception as e:
        app.logger.error(f"Errore nel recupero della chiave pubblica da Keycloak: {e}")
    return None

@app.route("/api/orders/<order_id>", methods=["GET"])
def get_order(order_id):
    """
    Endpoint GET per il recupero di un ordine.
    Vulnerabile a BOLA (Broken Object Level Authorization).
    """
    # 1. Estrazione del token dall'header Authorization
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized: Missing or invalid Bearer token"}), 401
    
    token = auth_header.split(" ")[1]
    
    # 2. Validazione del token JWT tramite Keycloak
    try:
        public_key = get_keycloak_public_key(token)
        if not public_key:
            return jsonify({"error": "Unauthorized: Unable to verify token signature (JWKS lookup failed)"}), 401
        
        # Decodifica e valida il token JWT.
        # Disabilitiamo il controllo dell'audience ('verify_aud': False) per flessibilità nel PoC locale.
        # Keycloak richiede che l'algoritmo sia RS256.
        payload = jwt.decode(
            token, 
            public_key, 
            algorithms=["RS256"], 
            options={"verify_aud": False}
        )
        
        # Estrazione dell'identità dell'utente autenticato (es. claim preferred_username)
        username = payload.get("preferred_username")
        if not username:
            return jsonify({"error": "Unauthorized: Claim 'preferred_username' not found in JWT"}), 401
            
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Unauthorized: Token expired"}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({"error": f"Unauthorized: Invalid token ({str(e)})"}), 401
    
    # 3. Lookup della risorsa nel Database
    if order_id not in ORDERS_DATABASE:
        return jsonify({"error": "Order not found"}), 404
        
    owner = ORDERS_DATABASE[order_id]
    
    # =========================================================================
    # CRITICITA' BOLA (OWASP API1:2023 - Broken Object Level Authorization)
    # -------------------------------------------------------------------------
    # In questa sezione il codice accetta qualsiasi JWT valido emesso da Keycloak,
    # ma NON esegue alcuna verifica di autorizzazione basata sulla risorsa:
    # controlla CHI è l'utente (Autenticazione), ma non controlla se tale utente
    # ha il diritto di accedere all'ordine richiesto (Autorizzazione a livello di oggetto).
    #
    # Di conseguenza, 'user_a' può richiedere e leggere l'ordine '102' (di user_b)
    # semplicemente cambiando l'ID nella richiesta GET, a patto di inviare un JWT valido.
    # =========================================================================
    
    # [CODICE VULNERABILE A BOLA]
    return jsonify({
        "order_id": order_id,
        "owner": owner,
        "details": f"Informazioni riservate per l'ordine {order_id} (Dati sensibili e di spedizione)",
        "status": "In Consegna"
    }), 200

    # =========================================================================
    # COME CORREGGERE (PATCH PER IL BOLA):
    # -------------------------------------------------------------------------
    # Per mitigare questa vulnerabilità, è necessario inserire un controllo di 
    # sbarramento (Authorization check) che metta in relazione l'utente
    # estratto dal token (username) con il proprietario reale della risorsa (owner).
    #
    # Decommenta il blocco sottostante per applicare la patch di sicurezza:
    #
    # if username != owner and username != "admin_user":
    #     # Se l'utente non è il proprietario e non è l'utente amministratore globale, nega l'accesso!
    #     return jsonify({"error": "Forbidden: You do not have permission to access this resource"}), 403
    # =========================================================================

if __name__ == "__main__":
    # Avvia l'applicazione sulla porta 5000
    app.run(host="0.0.0.0", port=5000, debug=True)
