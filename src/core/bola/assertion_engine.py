"""
Motore di Asserzione BOLA per il framework D-AST.
Analizza e confronta semanticamente e strutturalmente le risposte HTTP per tutti i metodi HTTP
(GET, PUT, DELETE, POST), calcolando la legittimità dell'accesso in base alla Privilege Matrix
(BOLA Orizzontale, BOLA Verticale, Safe per ruolo gerarchico).
"""

import logging
import requests
from typing import Dict, Any
from src.core.bola.role_matrix import AccessControlMatrix

logger = logging.getLogger("SecurityPlatform.BOLA.AssertionEngine")


class APIAssertionEngine:
    """
    Motore di Asserzione delle API (Assertion Engine).
    Implementa regole differenziali e gerarchiche per BOLA (OWASP API1:2023).
    """

    ERROR_KEYWORDS = [
        "access denied", "unauthorized", "forbidden", "error_code", 
        "invalid_user", "non autorizzato", "accesso negato", "permission_denied"
    ]

    @classmethod
    def evaluate_bola_assertion(
        cls, 
        method: str, 
        res_alice: requests.Response, 
        res_bob: requests.Response,
        requesting_user_role: str,
        resource_owner_role: str
    ) -> Dict[str, Any]:
        """
        Valuta le asserzioni di sicurezza (status, keyword, strutturali) e controlla
        la Privilege Matrix per determinare se l'accesso costituisce una violazione BOLA
        orizzontale o verticale, o se sia legittimo.
        """
        method = method.upper()
        req_role = (requesting_user_role or "user").lower()
        owner_role = (resource_owner_role or "user").lower()

        # 1. Asserzioni Tecniche
        http_status_assertion = (res_bob.status_code in (401, 403))

        bob_text_lower = res_bob.text.lower() if res_bob.text else ""
        has_error_keyword = any(kw in bob_text_lower for kw in cls.ERROR_KEYWORDS)
        
        if res_bob.status_code in (200, 204):
            content_keyword_assertion = has_error_keyword
        else:
            content_keyword_assertion = True

        # Asserzione strutturale differenziale
        if method == "GET":
            if res_bob.status_code == 200 and res_alice is not None:
                try:
                    json_alice = res_alice.json()
                    json_bob = res_bob.json()
                    
                    def get_structure_keys(obj):
                        if isinstance(obj, dict):
                            keys = set(obj.keys())
                            for k, v in obj.items():
                                if isinstance(v, dict):
                                    keys.update(f"{k}.{sub_k}" for sub_k in get_structure_keys(v))
                            return keys
                        elif isinstance(obj, list):
                            keys = set()
                            for item in obj:
                                if isinstance(item, dict):
                                    keys.update(get_structure_keys(item))
                            return keys
                        return set()

                    keys_alice = get_structure_keys(json_alice)
                    keys_bob = get_structure_keys(json_bob)
                    
                    if keys_alice and keys_bob:
                        common_keys = keys_alice.intersection(keys_bob)
                        similarity = len(common_keys) / max(len(keys_alice), len(keys_bob))
                        # Se condividono almeno l'80% delle chiavi, sono simili (assertion = False)
                        structural_similarity_assertion = (similarity < 0.8)
                    else:
                        structural_similarity_assertion = (type(json_alice) != type(json_bob))
                except Exception:
                    # Fallback non-JSON:
                    len_a = len(res_alice.text) if res_alice.text else 0
                    len_b = len(res_bob.text) if res_bob.text else 0
                    if len_a == 0 or len_b == 0:
                        structural_similarity_assertion = (len_a != len_b)
                    else:
                        # Se la lunghezza differisce di oltre 5 volte, le risposte sono strutturalmente diverse
                        ratio = max(len_a, len_b) / min(len_a, len_b)
                        structural_similarity_assertion = (ratio > 5.0)
            else:
                structural_similarity_assertion = True
        else:
            if res_bob.status_code in (200, 204) and not has_error_keyword:
                structural_similarity_assertion = False
            else:
                structural_similarity_assertion = True

        # L'accesso tecnico ha avuto successo (nessun blocco applicato dal server)
        technical_success = not (http_status_assertion or content_keyword_assertion or structural_similarity_assertion)

        # 2. Asserzione Logica (Role-Aware / Privilege Matrix)
        is_legitimate = AccessControlMatrix.validate_access_legitimacy(req_role, owner_role, method)

        is_vulnerable = False
        verdict = "SAFE"

        if technical_success:
            if is_legitimate:
                # Il server ha risposto 200/204 ma l'accesso è legittimo (es. Admin che accede a risorsa User)
                verdict = "SAFE (Legitimate Privilege Access)"
                is_vulnerable = False
                logger.info(
                    f"🛡️ [SAFE (Legitimate Privilege Access)] Richiesta {method} da parte di "
                    f"ruolo '{req_role}' su risorsa di '{owner_role}' consentita per Privilege Matrix."
                )
            else:
                # Violazione rilevata. Distinguiamo tra orizzontale e verticale
                is_vulnerable = True
                if req_role == "user" and owner_role == "user":
                    verdict = "BOLA ORIZZONTALE"
                    logger.error(
                        f"🚨 [ALERT CRITICAL] BOLA ORIZZONTALE RILEVATO! "
                        f"Utente di livello paritetico '{req_role}' ha eseguito con successo {method} "
                        f"su una risorsa di un altro '{owner_role}'."
                    )
                else:
                    verdict = "BOLA VERTICALE (Privilege Escalation)"
                    logger.error(
                        f"🚨 [ALERT CRITICAL] BOLA VERTICALE (Privilege Escalation) RILEVATO! "
                        f"Utente con privilegi inferiori '{req_role}' ha eseguito con successo {method} "
                        f"su una risorsa di livello superiore '{owner_role}'."
                    )
        else:
            # L'accesso è stato bloccato dal server
            verdict = "SAFE"

        return {
            "http_status_assertion": http_status_assertion,
            "content_keyword_assertion": content_keyword_assertion,
            "structural_similarity_assertion": structural_similarity_assertion,
            "is_vulnerable": is_vulnerable,
            "verdict": verdict,
            "requesting_role": req_role,
            "owner_role": owner_role
        }
