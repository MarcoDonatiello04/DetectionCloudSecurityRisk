"""
Estrazione dell'identita dal token JWT del richiedente.

Rispecchia il comportamento di `test_targets/bola/extract_username`: tenta la
validazione reale della firma RS256 tramite le chiavi pubbliche di Keycloak e,
in caso di token sintetici (usati dalle simulazioni), ricade sulla decodifica
del solo payload. Restituisce lo username applicativo e il claim `sub` (UUID
Keycloak), entrambi usati dagli endpoint per decidere l'autorizzazione.
"""

from __future__ import annotations

import base64
import json
import logging
import os

import jwt
from jwt import PyJWKClient

logger = logging.getLogger("repo_target.identity")

KEYCLOAK_SERVER_URL = os.environ.get("KEYCLOAK_SERVER_URL", "http://localhost:8080")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "myrealm")
JWKS_URL = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs"


def _decode_with_keycloak(token: str) -> dict | None:
    try:
        signing_key = PyJWKClient(JWKS_URL).get_signing_key_from_jwt(token)
        return jwt.decode(
            token, signing_key.key, algorithms=["RS256"], options={"verify_aud": False}
        )
    except Exception as exc:  # firma non verificabile o Keycloak irraggiungibile
        logger.debug("Validazione Keycloak non riuscita, uso il fallback: %s", exc)
        return None


def _decode_payload_only(token: str) -> dict | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))
    except Exception as exc:
        logger.debug("Decodifica manuale del token fallita: %s", exc)
        return None


def extract_identity(request) -> tuple[str | None, str | None]:
    """
    Ritorna (username, sub) dal token Bearer, oppure (None, None) se assente/illeggibile.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None, None

    token = auth_header.split(" ", 1)[1]
    claims = _decode_with_keycloak(token) or _decode_payload_only(token)
    if not claims:
        return None, None

    return claims.get("preferred_username") or claims.get("sub"), claims.get("sub")
