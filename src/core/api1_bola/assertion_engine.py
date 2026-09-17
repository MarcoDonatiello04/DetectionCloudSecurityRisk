"""
Requirements Analysis Document (RAD) & Object Design Document (ODD) Academic Alignment
Modulo: Assertion Engine / Validatore Semantico BOLA (APIAssertionEngine)
Percorso: src/core/api1_bola/assertion_engine.py

Questo modulo implementa il motore di validazione semantica a runtime per BOLA,
utilizzando il paradigma del Differential Testing. Analizza le risposte HTTP (livello 7 OSI)
verificando lo status code, le parole chiave e la similarità strutturale dei body.

Il confronto strutturale è semantico, non sulla lunghezza in byte: i body vengono
decodificati come JSON e confrontati dopo aver rimosso i campi volatili (chi ha
acceduto, timestamp, ...) dichiarati in ``config/bola.yaml``. Un segnale aggiuntivo
scatta quando la risposta 2xx dell'attaccante contiene l'identificativo della vittima,
anche se i body divergono.
"""

import logging
import re
from typing import Any

import requests

from src.core.api1_bola.bola_config import get_bola_config
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

    @staticmethod
    def _is_success(status_code: int) -> bool:
        """True per qualunque risposta di successo tecnico (2xx)."""
        return 200 <= int(status_code) < 300

    @classmethod
    def _strip_volatile(cls, value: Any, volatile: frozenset[str]) -> Any:
        """
        Rimuove ricorsivamente le chiavi volatili da un valore JSON decodificato.

        Args:
            value (Any): Struttura JSON (dict/list/scalare).
            volatile (frozenset[str]): Nomi delle chiavi da ignorare nel confronto.

        Returns:
            Any: La struttura equivalente senza le chiavi volatili.
        """
        if isinstance(value, dict):
            return {
                k: cls._strip_volatile(v, volatile) for k, v in value.items() if k not in volatile
            }
        if isinstance(value, list):
            return [cls._strip_volatile(v, volatile) for v in value]
        return value

    @classmethod
    def _structural_match(
        cls, res_owner: requests.Response, res_attacker: requests.Response
    ) -> bool:
        """
        Confronto semantico tra la risposta del proprietario e quella dell'attaccante.

        Entrambi i body vengono decodificati come JSON e confrontati dopo aver rimosso
        i campi volatili (``config/bola.yaml``): così ``accessed_by`` diverso non maschera
        lo stesso oggetto, e due body diversi con la stessa lunghezza non collidono.
        Se uno dei due body non è JSON si ricade sull'uguaglianza testuale.

        Args:
            res_owner (requests.Response): Risposta ottenuta dal proprietario legittimo.
            res_attacker (requests.Response): Risposta ottenuta dall'attaccante.

        Returns:
            bool: True se l'attaccante ha ottenuto lo stesso oggetto del proprietario.
        """
        try:
            owner_body, attacker_body = res_owner.json(), res_attacker.json()
        except ValueError:
            return (res_owner.text or "") == (res_attacker.text or "")
        volatile = get_bola_config().volatile_fields
        return cls._strip_volatile(owner_body, volatile) == cls._strip_volatile(
            attacker_body, volatile
        )

    @staticmethod
    def _references_victim(res_attacker: requests.Response, resource_id: str | None) -> bool:
        """
        True se il body dell'attaccante cita l'identificativo della risorsa della vittima.

        Args:
            res_attacker (requests.Response): Risposta ottenuta dall'attaccante.
            resource_id (str | None): Identificativo della risorsa bersaglio (es. sub della vittima).

        Returns:
            bool: True se l'ID compare nel body; False se l'ID non è noto o assente.
        """
        if not resource_id:
            return False
        return str(resource_id) in (res_attacker.text or "")

    @classmethod
    def evaluate_bola_assertion(
        cls,
        method: str,
        res_alice: requests.Response,
        res_bob: requests.Response,
        requesting_user_role: str,
        resource_owner_role: str,
        resource_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Valuta le asserzioni booleane (status, keyword, strutturale, riferimento alla vittima)
        e coordina il verdetto finale incrociando i dati con la Privilege Matrix.

        Args:
            method (str): Metodo HTTP dell'operazione.
            res_alice (requests.Response): Risposta HTTP ottenuta dall'utente legittimo.
            res_bob (requests.Response): Risposta HTTP ottenuta dall'utente attaccante (tampered).
            requesting_user_role (str): Ruolo dell'utente attaccante.
            resource_owner_role (str): Ruolo dell'utente proprietario della risorsa.
            resource_id (str | None): Identificativo della risorsa della vittima usato nel
                tampering; se noto, la sua presenza in un body 2xx dell'attaccante è
                di per sé violazione dell'isolamento.

        Returns:
            Dict[str, Any]: Mappa contenente i risultati delle asserzioni ed il verdetto finale.
        """
        method = method.upper().strip()
        req_role = (requesting_user_role or "user").lower().strip()
        owner_role = (resource_owner_role or "user").lower().strip()
        bob_success = cls._is_success(res_bob.status_code)

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

        # Se il server risponde 2xx ma contiene parole di errore, consideriamo l'asserzione di sicurezza attivata (True)
        if bob_success:  # noqa: SIM108 - rami commentati per chiarezza
            content_keyword_assertion = has_error_keyword
        else:
            # Se ha risposto con codice non 2xx (es. 400, 401, 403, 404), la consideriamo bloccata (True)
            content_keyword_assertion = True

        # 3. Asserzione 3: Structural Similarity Assertion
        # Confronto semantico dei body tra Alice (proprietario) e Bob (attaccante), al netto
        # dei campi volatili. Se l'attaccante ha ricevuto lo stesso oggetto del proprietario,
        # l'isolamento dei dati è violato (structural_similarity_assertion = True).
        # 4. Asserzione 4: Victim Reference Assertion
        # Se il body 2xx dell'attaccante cita l'ID della vittima, l'isolamento è violato anche
        # se i body divergono (es. rappresentazioni diverse dello stesso oggetto).
        structural_similarity_assertion = False
        victim_reference_assertion = False

        # Effettuiamo i controlli solo per risposte di successo tecnico (2xx)
        if bob_success:
            if res_alice is not None:
                structural_similarity_assertion = cls._structural_match(res_alice, res_bob)
            victim_reference_assertion = cls._references_victim(res_bob, resource_id)

        # Verifica di successo tecnico dell'attacco:
        # L'attacco ha avuto successo se NON è stato bloccato dallo status, NON contiene keyword di errore
        # E almeno un segnale indica violazione dell'isolamento dei dati (stesso oggetto o ID vittima).
        technical_success = (
            not http_status_assertion
            and not content_keyword_assertion
            and (structural_similarity_assertion or victim_reference_assertion)
        )
        isolation_signal = (
            "stesso oggetto del proprietario"
            if structural_similarity_assertion
            else "body che cita l'ID della vittima"
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
                    f"ha ottenuto la risorsa di un altro utente '{owner_role}' tramite {method} ({isolation_signal})."
                )
            elif matrix_verdict == "BOLA_VERTICALE":
                verdict = "BOLA VERTICALE (Privilege Escalation)"
                is_vulnerable = True
                logger.error(
                    f"🚨 [ALERT CRITICAL] BOLA VERTICALE RILEVATO! Utente con minori privilegi '{req_role}' "
                    f"ha ottenuto la risorsa del ruolo superiore '{owner_role}' tramite {method} ({isolation_signal})."
                )
        else:
            # Se l'attacco è stato bloccato o ha fallito tecnicamente (es. oggetto diverso o status 401/403)
            verdict = "SAFE"
            is_vulnerable = False
            logger.info(
                f"✅ [SAFE - ACCESSO BLOCCATO] Tentativo {method} da '{req_role}' "
                f"su risorsa di '{owner_role}' respinto correttamente (Status={res_bob.status_code}, "
                f"stesso_oggetto={structural_similarity_assertion}, cita_vittima={victim_reference_assertion})."
            )

        return {
            "http_status_assertion": http_status_assertion,
            "content_keyword_assertion": content_keyword_assertion,
            "structural_similarity_assertion": structural_similarity_assertion,
            "victim_reference_assertion": victim_reference_assertion,
            "is_vulnerable": is_vulnerable,
            "verdict": verdict,
            "requesting_role": req_role,
            "owner_role": owner_role,
        }
