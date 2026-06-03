"""
Modulo della Privilege Matrix (Matrice di Controllo Accessi) per Role-Aware Testing.
Modella le regole di business attese per l'applicazione, determinando se una determinata
operazione effettuata da un utente con un certo ruolo sulla risorsa di un altro utente
sia legittima per design o se rappresenti una violazione BOLA (Orizzontale o Verticale).
"""

import logging

logger = logging.getLogger("SecurityPlatform.BOLA.RoleMatrix")


class AccessControlMatrix:
    """
    Rappresenta la matrice delle autorizzazioni gerarchiche sulle risorse.
    Regole di business attese:
    - Un ruolo 'admin' ha accesso completo (lettura, scrittura, cancellazione) su qualsiasi risorsa.
    - Un ruolo 'manager' ha accesso alle proprie risorse e a quelle degli utenti con ruolo 'user', ma non degli 'admin'.
    - Un ruolo 'user' può accedere solo ed esclusivamente alle proprie risorse.
    """

    HIERARCHY = {
        "admin": 3,
        "manager": 2,
        "user": 1
    }

    @classmethod
    def validate_access_legitimacy(cls, requesting_user_role: str, resource_owner_role: str, method: str) -> bool:
        """
        Valuta se l'accesso alla risorsa è legittimo in base alle regole dei ruoli.
        
        Args:
            requesting_user_role (str): Il ruolo dell'utente che effettua la richiesta (es. 'admin', 'user').
            resource_owner_role (str): Il ruolo del proprietario effettivo della risorsa.
            method (str): Il metodo HTTP dell'operazione (GET, PUT, DELETE, ecc.).

        Returns:
            bool: True se l'accesso è legittimo per design (es. Admin su User), 
                  False se costituisce una violazione di sicurezza.
        """
        req_role = (requesting_user_role or "user").lower()
        owner_role = (resource_owner_role or "user").lower()
        method = method.upper()

        # Sanitarizzazione dei ruoli per evitare disallineamenti
        if req_role not in cls.HIERARCHY:
            req_role = "user"
        if owner_role not in cls.HIERARCHY:
            owner_role = "user"

        logger.debug(f"Valutazione legittimità: Richiedente={req_role}, Proprietario={owner_role}, Metodo={method}")

        # Regola 1: Se l'utente richiedente è 'admin', l'accesso è sempre legittimo per design.
        if req_role == "admin":
            return True

        # Regola 2: Un utente ordinario ('user') non può mai accedere a risorse di altri utenti (paritetici o superiori).
        if req_role == "user" and owner_role == "user":
            # Per scopi di test BOLA, se sono due identità diverse (Alice e Bob), l'accesso non è legittimo.
            # Qui la matrice definisce le regole di ruolo generiche: un 'user' non ha diritti ereditati su altri 'user'.
            return False

        # Regola 3: Privilegio verticale (un ruolo inferiore che accede ad uno superiore)
        if cls.HIERARCHY[req_role] < cls.HIERARCHY[owner_role]:
            return False

        # Regola 4: Un 'manager' può accedere alle risorse degli 'user' per determinati metodi (es. GET o modifiche autorizzate)
        if req_role == "manager" and owner_role == "user":
            return True

        return False
