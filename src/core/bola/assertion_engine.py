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
                structural_similarity_assertion = (len(res_bob.text) != len(res_alice.text))
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
