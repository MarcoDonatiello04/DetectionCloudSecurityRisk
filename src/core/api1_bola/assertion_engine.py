"""
Requirements Analysis Document (RAD) & Object Design Document (ODD) Academic Alignment
Modulo: Assertion Engine / Validatore Semantico BOLA (APIAssertionEngine)
Percorso: src/core/api1_bola/assertion_engine.py

Questo modulo implementa il motore di validazione semantica a runtime per BOLA,
utilizzando il paradigma del Differential Testing. Analizza le risposte HTTP (livello 7 OSI)
verificando lo status code, le parole chiave e la similarità strutturale dei body.
"""

import logging
import re
from typing import Any

import requests

from src.core.api1_bola.role_matrix import AccessControlMatrix

logger = logging.getLogger("SecurityPlatform.BOLA.AssertionEngine")


class APIAssertionEngine:
    """
    Motore di validazione semantica (Assertion Engine) basato su Differential Testing.

    Verifica la presenza di BOLA orizzontale o verticale valutando tre asserzioni
    booleane concorrenti ed incrociando i dati con la Privilege Matrix di controllo degli accessi.

    Pattern Comportamentale: Chain of Responsibility / Rules Engine
    """

    # Parole chiave indicanti blocco applicativo mascherato da 200 OK
    ERROR_KEYWORDS = [
        r"access denied",
        r"unauthorized",
        r"forbidden",
        r"non autorizzato",
        r"accesso negato",
        r"permission denied",
        r"error_code",
        r"invalid_user",
    ]

    @classmethod
    def evaluate_bola_assertion(
        cls,
        method: str,
        res_alice: requests.Response,
        res_bob: requests.Response,
        requesting_user_role: str,
        resource_owner_role: str,
    ) -> dict[str, Any]:
        """
        Valuta le tre asserzioni booleane (status, keyword, strutturale) e coordina
        il verdetto finale incrociando i dati con la Privilege Matrix.

        Args:
            method (str): Metodo HTTP dell'operazione.
            res_alice (requests.Response): Risposta HTTP ottenuta dall'utente legittimo.
            res_bob (requests.Response): Risposta HTTP ottenuta dall'utente attaccante (tampered).
            requesting_user_role (str): Ruolo dell'utente attaccante.
            resource_owner_role (str): Ruolo dell'utente proprietario della risorsa.

        Returns:
            Dict[str, Any]: Mappa contenente i risultati delle asserzioni ed il verdetto finale.
        """
        method = method.upper().strip()
        req_role = (requesting_user_role or "user").lower().strip()
        owner_role = (resource_owner_role or "user").lower().strip()

        # 1. Asserzione 1: HTTP Status Code Assertion
        # True se il server risponde con codici di blocco standard (401/403)
        http_status_assertion = res_bob.status_code in (401, 403)

        # 2. Asserzione 2: Content Keyword Assertion
        # Ispezione regex del body alla ricerca di stringhe di errore custom mascherate dietro un 200 OK.
        # Se risponde con codici di blocco o se il body contiene keyword di errore, l'asserzione di blocco è True.
        bob_text = res_bob.text or ""
        bob_text_lower = bob_text.lower()

        has_error_keyword = False
        for kw_pattern in cls.ERROR_KEYWORDS:
            if re.search(kw_pattern, bob_text_lower):
                has_error_keyword = True
                break

        # Se il server risponde 200/204 ma contiene parole di errore, consideriamo l'asserzione di sicurezza attivata (True)
        if res_bob.status_code in (200, 204):  # noqa: SIM108 - rami commentati per chiarezza
            content_keyword_assertion = has_error_keyword
        else:
            # Se ha risposto con codice diverso da 200/204 (es. 400, 401, 403, 404), la consideriamo bloccata (True)
            content_keyword_assertion = True

        # 3. Asserzione 3: Structural Similarity Assertion
        # Confronto differenziale sulla lunghezza dei body tra Alice (proprietario) e Bob (attaccante).
        # Se la variazione in byte è zero (Delta = 0), significa che l'attaccante ha ricevuto
        # l'esatto contenuto del proprietario: l'isolamento dei dati è violato (structural_similarity_assertion = True).
        # Se c'è una variazione (Delta != 0), l'isolamento ha retto (structural_similarity_assertion = False).
        structural_similarity_assertion = False

        # Effettuiamo il controllo per risposte di successo tecnico (200/204)
        if res_bob.status_code in (200, 204) and res_alice is not None:
            len_alice = len(res_alice.text) if res_alice.text else 0
            len_bob = len(res_bob.text) if res_bob.text else 0

            delta_bytes = abs(len_alice - len_bob)

            # Se delta = 0, l'isolamento dei dati è violato (risposta identica)
            structural_similarity_assertion = delta_bytes == 0
        else:
            # Se la risposta è un errore o se res_alice non è disponibile, assumiamo che non ci sia violazione strutturale
            structural_similarity_assertion = False

        # Verifica di successo tecnico dell'attacco:
        # L'attacco ha avuto successo se NON è stato bloccato dallo status, NON contiene keyword di errore
        # E la similarità strutturale indica violazione dell'isolamento dei dati (structural_similarity_assertion == True).
        technical_success = (
            not http_status_assertion
            and not content_keyword_assertion
            and structural_similarity_assertion
        )

        # 4. Coordinamento con la Privilege Matrix per determinare il verdetto logico finalizzato
        matrix_verdict = AccessControlMatrix.validate_access_legitimacy(
            requesting_role=req_role, owner_role=owner_role, method=method
        )

        is_vulnerable = False
        verdict = "SAFE"

        if technical_success:
            if matrix_verdict == "LEGITTIMO":
                # L'accesso ha avuto successo tecnico ma è legittimo da Privilege Matrix (es. Admin su User)
                verdict = "SAFE (Legitimate Privilege Access)"
                is_vulnerable = False
                logger.info(
                    f"🛡️ [SAFE - ACCESSO LEGITTIMO] Richiesta {method} da ruolo '{req_role}' "
                    f"su risorsa di '{owner_role}' consentita dalle regole di business."
                )
            elif matrix_verdict == "BOLA_ORIZZONTALE":
                verdict = "BOLA ORIZZONTALE"
                is_vulnerable = True
                logger.error(
                    f"🚨 [ALERT CRITICAL] BOLA ORIZZONTALE RILEVATO! Utente paritetico '{req_role}' "
                    f"ha ottenuto l'esatta risorsa (Delta=0) di un altro utente '{owner_role}' tramite {method}."
                )
            elif matrix_verdict == "BOLA_VERTICALE":
                verdict = "BOLA VERTICALE (Privilege Escalation)"
                is_vulnerable = True
                logger.error(
                    f"🚨 [ALERT CRITICAL] BOLA VERTICALE RILEVATO! Utente con minori privilegi '{req_role}' "
                    f"ha ottenuto l'esatta risorsa (Delta=0) dell'admin/ruolo superiore '{owner_role}' tramite {method}."
                )
        else:
            # Se l'attacco è stato bloccato o ha fallito tecnicamente (es. Delta != 0 o status 401/403)
            verdict = "SAFE"
            is_vulnerable = False
            logger.info(
                f"✅ [SAFE - ACCESSO BLOCCATO] Tentativo {method} da '{req_role}' "
                f"su risorsa di '{owner_role}' respinto correttamente (Status={res_bob.status_code}, Delta={abs(len(res_alice.text or '') - len(res_bob.text or '')) if res_alice else 'N/D'})."
            )

        return {
            "http_status_assertion": http_status_assertion,
            "content_keyword_assertion": content_keyword_assertion,
            "structural_similarity_assertion": structural_similarity_assertion,
            "is_vulnerable": is_vulnerable,
            "verdict": verdict,
            "requesting_role": req_role,
            "owner_role": owner_role,
        }
