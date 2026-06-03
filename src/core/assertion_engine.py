import logging
import requests
from typing import Dict, Any

logger = logging.getLogger("SecurityPlatform.AssertionEngine")


class APIAssertionEngine:
    """
    Motore di Asserzione delle API (Assertion Engine).
    Analizza e confronta semanticamente e strutturalmente le risposte HTTP della vittima (Alice)
    e dell'attaccante (Bob) per determinare l'esposizione reale a vulnerabilità BOLA (OWASP API1:2023).
    Questo approccio differenziale a livello applicativo riduce drasticamente i falsi positivi
    e i falsi negativi rispetto a una valutazione basata esclusivamente sui codici di stato HTTP.
    """

    ERROR_KEYWORDS = [
        "access denied", "unauthorized", "forbidden", "error_code", 
        "invalid_user", "non autorizzato", "accesso negato", "permission_denied"
    ]

    @classmethod
    def evaluate_bola_assertion(cls, res_alice: requests.Response, res_bob: requests.Response) -> Dict[str, Any]:
        """
        Valuta una matrice di tre asserzioni di sicurezza a runtime:
        1. http_status_assertion: True se Bob riceve 401 o 403. False se risponde 200.
        2. content_keyword_assertion: True se lo status è 200 ma contiene una delle parole chiave di errore mascherate. False altrimenti.
        3. structural_similarity_assertion: True se lo status è 200 ma la risposta di Bob differisce in lunghezza rispetto a quella legittima di Alice. False se la lunghezza è identica al byte.
        
        L'endpoint è marcato come VULNERABLE se tutte e tre le asserzioni falliscono (False).
        In caso di status code 200 OK:
          - Se l'applicazione blocca internamente l'accesso (keyword assertion True) OR
          - Se la risposta ha lunghezza diversa da quella di Alice (structural similarity assertion True)
          allora l'asserzione di sicurezza tiene (SAFE).
          Altrimenti, se tutte falliscono (False), l'endpoint è vulnerabile.
        """
        # A. Status Code Assertion
        http_status_assertion = (res_bob.status_code in (401, 403))

        # B. Content Keyword Inspection
        bob_text_lower = res_bob.text.lower() if res_bob.text else ""
        has_error_keyword = any(kw in bob_text_lower for kw in cls.ERROR_KEYWORDS)
        
        if res_bob.status_code == 200:
            content_keyword_assertion = has_error_keyword
        else:
            content_keyword_assertion = True

        # C. Structural Similarity Assertion
        if res_bob.status_code == 200 and res_alice is not None:
            # Se la lunghezza è identica al byte rispetto a quella legittima di Alice,
            # Bob sta visualizzando esattamente lo stesso payload sensibile. L'asserzione fallisce (False).
            structural_similarity_assertion = (len(res_bob.text) != len(res_alice.text))
        else:
            structural_similarity_assertion = True

        # L'endpoint è vulnerabile se tutte e tre falliscono.
        # Ovvero, se non è bloccato da status code, non è bloccato da keyword e ha lo stesso contenuto di Alice.
        is_vulnerable = not (http_status_assertion or content_keyword_assertion or structural_similarity_assertion)

        return {
            "http_status_assertion": http_status_assertion,
            "content_keyword_assertion": content_keyword_assertion,
            "structural_similarity_assertion": structural_similarity_assertion,
            "is_vulnerable": is_vulnerable
        }
