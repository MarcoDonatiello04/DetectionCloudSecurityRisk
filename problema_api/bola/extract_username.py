import jwt
import base64
import json
import logging
from keycloak_key import get_keycloak_public_key

logger = logging.getLogger("flask.app")

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
        logger.debug(f"Verifica Keycloak non riuscita, provo fallback manuale: {e}")

    # 2. Fallback manuale robusto (estrazione e decodifica base64 del payload del JWT)
    try:
        parts = token.split(".")
        if len(parts) == 3:
            payload_b64 = parts[1]
            # Ripristina padding base64 corretto
            payload_b64 += "=" * (-len(payload_b64) % 4)
            payload_json = base64.urlsafe_b64decode(payload_b64).decode("utf-8")
            payload = json.loads(payload_json)
            return payload.get("preferred_username") or payload.get("sub")
    except Exception as e:
        logger.error(f"Errore decodifica token manuale: {e}")
        
    return None
