"""Fixture TN per la regola S01: decodifica JWT correttamente verificata.

Usa solo `jwt.decode(..., algorithms=[...])` con verifica della firma. Non c'e
alcuna decodifica manuale del payload (nessuno split '.', nessun Base64, nessun
json.loads sul token), quindi la regola S01 non deve produrre finding.
"""

import jwt


def decode_verified(token: str, public_key: str) -> dict:
    # Verifica crittografica della firma: nessun fallback non verificato.
    return jwt.decode(token, public_key, algorithms=["RS256"], options={"verify_aud": False})
