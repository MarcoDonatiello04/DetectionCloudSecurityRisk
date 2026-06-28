import os
import requests
import jwt
import logging

KEYCLOAK_SERVER_URL = os.environ.get("KEYCLOAK_SERVER_URL", "http://keycloak:8080")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "myrealm")
JWKS_URL = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs"

logger = logging.getLogger("flask.app")

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
        logger.debug(f"JWKS lookup fallito: {e}")
    return None
