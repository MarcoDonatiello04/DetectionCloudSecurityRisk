"""
Requirements Analysis Document (RAD) & Object Design Document (ODD) Academic Alignment
Modulo: Privilege Matrix / Controllo Accessi BOLA (AccessControlMatrix)
Percorso: src/core/object_level_authorization/role_matrix.py

Questo modulo implementa la Privilege Matrix di controllo degli accessi. Definisce
la logica di business gerarchica per determinare la legittimità o la classificazione
di una violazione BOLA (Orizzontale o Verticale).
"""

import logging
from typing import Optional

logger = logging.getLogger("SecurityPlatform.BOLA.AccessControlMatrix")


class AccessControlMatrix:
    """
    Rappresenta la Privilege Matrix gerarchica del sistema.
    
    Pattern Strutturale: Privilege Matrix / Role-Based Policy
    """

    HIERARCHY = {
        "admin": 3,
        "manager": 2,
        "user": 1
    }

    @classmethod
    def validate_access_legitimacy(
        cls, 
        requesting_role: str, 
        owner_role: str, 
        method: str = "GET",
        # Parametri legacy per retrocompatibilità con keyword arguments
        requesting_user_role: Optional[str] = None,
        resource_owner_role: Optional[str] = None
    ) -> str:
        """
        Valuta se l'operazione richiesta è legittima rispetto alle regole di business.
        
        Regole di Business:
        - Un ruolo 'admin' ha accesso completo e legittimo a qualsiasi risorsa.
        - Un ruolo 'manager' ha accesso alle proprie risorse e a quelle degli utenti 'user', ma non degli 'admin'.
        - Un ruolo 'user' può accedere solo alle proprie risorse. Qualsiasi interazione
          su risorse di un altro 'user' (peer) è marcata come BOLA Orizzontale.
        - Un tentativo di accesso da ruolo inferiore a risorsa di ruolo superiore è marcato come BOLA Verticale.
        
        Args:
            requesting_role (str): Il ruolo dell'utente che avvia la richiesta.
            owner_role (str): Il ruolo dell'utente proprietario della risorsa target.
            method (str): Il metodo HTTP dell'azione.
            
        Returns:
            str: Verdetto formale: "LEGITTIMO", "BOLA_ORIZZONTALE" o "BOLA_VERTICALE".
        """
        # Risolve l'uso di parametri legacy
        req_role_raw = requesting_role if requesting_role is not None else requesting_user_role
        owner_role_raw = owner_role if owner_role is not None else resource_owner_role

        req_role = str(req_role_raw or "user").lower().strip()
        owner_role = str(owner_role_raw or "user").lower().strip()
        method = str(method or "GET").upper().strip()

        # Allineamento con la gerarchia censita
        if req_role not in cls.HIERARCHY:
            req_role = "user"
        if owner_role not in cls.HIERARCHY:
            owner_role = "user"

        logger.debug(f"📐 [ROLE MATRIX] Valutazione: {req_role} su risorsa di {owner_role} tramite {method}")

        # 1. Accesso da parte di un Amministratore
        if req_role == "admin":
            return "LEGITTIMO"

        # 2. Accesso da parte di un Utente ordinario su un altro Utente ordinario (Peer-to-Peer)
        if req_role == "user" and owner_role == "user":
            return "BOLA_ORIZZONTALE"

        # 3. Accesso da ruolo con privilegi inferiori a superiori (Scalata)
        if cls.HIERARCHY[req_role] < cls.HIERARCHY[owner_role]:
            return "BOLA_VERTICALE"

        # 4. Accesso da parte di un Manager su un Utente ordinario (Lecito)
        if req_role == "manager" and owner_role == "user":
            return "LEGITTIMO"

        # 5. Default in caso di ruoli identici non admin (es. manager su manager)
        if req_role == owner_role:
            return "BOLA_ORIZZONTALE"

        return "BOLA_VERTICALE"
