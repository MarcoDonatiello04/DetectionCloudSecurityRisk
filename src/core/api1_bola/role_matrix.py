"""
Requirements Analysis Document (RAD) & Object Design Document (ODD) Academic Alignment
Modulo: Privilege Matrix / Controllo Accessi BOLA (AccessControlMatrix)
Percorso: src/core/api1_bola/role_matrix.py

Questo modulo implementa la Privilege Matrix di controllo degli accessi. Definisce
la logica di business gerarchica per determinare la legittimità o la classificazione
di una violazione BOLA (Orizzontale o Verticale). La gerarchia dei ruoli è letta da
``config/bola.yaml`` (sezione ``roles``), non cablata nel codice.
"""

import logging

from src.core.api1_bola.bola_config import get_bola_config

logger = logging.getLogger("SecurityPlatform.BOLA.AccessControlMatrix")


class _ConfiguredHierarchy:
    """Descrittore di classe: ``AccessControlMatrix.HIERARCHY`` legge la config attiva."""

    def __get__(self, instance, owner) -> dict[str, int]:
        return get_bola_config().role_hierarchy


class AccessControlMatrix:
    """
    Rappresenta la Privilege Matrix gerarchica del sistema.

    La gerarchia (``HIERARCHY``) è una mappa ruolo -> rango intero: rango maggiore
    equivale a maggiori privilegi. Le regole non dipendono dai nomi dei ruoli ma solo
    dal confronto dei ranghi, così una gerarchia diversa da admin/manager/user
    (es. ``owner > editor > viewer``) viene valutata con la stessa logica.

    Pattern Strutturale: Privilege Matrix / Role-Based Policy
    """

    # Letta ad ogni accesso da config/bola.yaml (sezione roles), mai cablata qui
    HIERARCHY: dict[str, int] = _ConfiguredHierarchy()  # type: ignore[assignment]

    @classmethod
    def hierarchy(cls) -> dict[str, int]:
        """
        Gerarchia attiva dei ruoli, letta dalla configurazione condivisa del modulo BOLA.

        Returns:
            dict[str, int]: Mappa ruolo -> rango.
        """
        return cls.HIERARCHY

    @classmethod
    def default_role(cls) -> str:
        """
        Ruolo di ripiego per i ruoli non censiti: quello con il rango minimo.

        Returns:
            str: Il nome del ruolo meno privilegiato della gerarchia.
        """
        return min(cls.hierarchy(), key=cls.hierarchy().get)

    @classmethod
    def normalize_role(cls, role: str | None, subject: str) -> str:
        """
        Normalizza un ruolo e lo degrada esplicitamente se non è censito nella gerarchia.

        Args:
            role (str | None): Il ruolo così come dichiarato dall'identity provider.
            subject (str): Etichetta del soggetto (richiedente/proprietario) per il log.

        Returns:
            str: Un ruolo presente nella gerarchia.
        """
        normalized = str(role or cls.default_role()).lower().strip()
        if normalized in cls.hierarchy():
            return normalized
        fallback = cls.default_role()
        logger.warning(
            f"⚠️ [ROLE MATRIX] Ruolo '{normalized}' del {subject} non censito nella gerarchia "
            f"{sorted(cls.hierarchy())}: degradato a '{fallback}'. "
            "Aggiungerlo a config/bola.yaml (sezione roles) se legittimo."
        )
        return fallback

    @classmethod
    def validate_access_legitimacy(
        cls,
        requesting_role: str,
        owner_role: str,
        method: str = "GET",
        # Parametri legacy per retrocompatibilità con keyword arguments
        requesting_user_role: str | None = None,
        resource_owner_role: str | None = None,
    ) -> str:
        """
        Valuta se l'operazione richiesta è legittima rispetto alle regole di business.

        Regole di Business (in termini di rango):
        - Il ruolo di rango massimo (es. 'admin') ha accesso completo e legittimo a qualsiasi risorsa.
        - Un ruolo che accede a una risorsa di rango inferiore (es. 'manager' su 'user') è legittimo.
        - Un ruolo che accede a una risorsa di pari rango (es. 'user' su 'user') è BOLA Orizzontale.
        - Un ruolo che accede a una risorsa di rango superiore è BOLA Verticale.

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

        req_role = cls.normalize_role(req_role_raw, "richiedente")
        owner_role = cls.normalize_role(owner_role_raw, "proprietario")
        method = str(method or "GET").upper().strip()

        hierarchy = cls.hierarchy()
        req_rank = hierarchy[req_role]
        owner_rank = hierarchy[owner_role]

        logger.debug(
            f"📐 [ROLE MATRIX] Valutazione: {req_role}({req_rank}) su risorsa di "
            f"{owner_role}({owner_rank}) tramite {method}"
        )

        # 1. Accesso da parte del ruolo di rango massimo (es. Amministratore)
        if req_rank == max(hierarchy.values()):
            return "LEGITTIMO"

        # 2. Accesso da ruolo con privilegi inferiori a superiori (Scalata)
        if req_rank < owner_rank:
            return "BOLA_VERTICALE"

        # 3. Accesso tra pari (Peer-to-Peer)
        if req_rank == owner_rank:
            return "BOLA_ORIZZONTALE"

        # 4. Accesso da ruolo superiore su inferiore (es. Manager su User): lecito
        return "LEGITTIMO"
