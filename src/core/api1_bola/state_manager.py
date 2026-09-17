"""
Requirements Analysis Document (RAD) & Object Design Document (ODD) Academic Alignment
Modulo: State Manager BOLA (APIStateEngine)
Percorso: src/core/api1_bola/state_manager.py

Questo modulo implementa il componente 'APIStateEngine' deputato a garantire
l'idempotenza e la consistenza dello stato dell'applicazione target durante
le sessioni di stimolazione dinamica (D-AST). L'obiettivo è prevenire la
"Test Cross-Contamination" derivante da richieste distruttive (PUT, DELETE).

I path degli endpoint di snapshot/rollback non sono cablati qui: arrivano dal
contratto del bersaglio (``config/bola_target.yaml``, sezione ``harness``).
"""

import logging

import requests

from src.core.api1_bola.target_config import (
    DEFAULT_HARNESS_ROLLBACK_PATH,
    DEFAULT_HARNESS_SNAPSHOT_PATH,
)

logger = logging.getLogger("SecurityPlatform.BOLA.APIStateEngine")


class APIStateEngine:
    """
    Componente di controllo dello stato (State Manager).
    Fornisce servizi sincroni per eseguire il backup transazionale e il
    ripristino dello stato in memoria dell'applicazione target.

    Pattern Strutturale: Singleton / Utility Class
    """

    def __init__(
        self,
        target_base_url: str | None = None,
        snapshot_path: str = DEFAULT_HARNESS_SNAPSHOT_PATH,
        rollback_path: str = DEFAULT_HARNESS_ROLLBACK_PATH,
    ):
        """
        Costruttore della classe. Consente l'inizializzazione con un host predefinito.

        Args:
            target_base_url (str, optional): URL di base dell'host target.
            snapshot_path (str): Path dell'endpoint di snapshot dell'harness cooperante.
            rollback_path (str): Path dell'endpoint di rollback dell'harness cooperante.
        """
        self.target_base_url = target_base_url
        self.snapshot_path = snapshot_path
        self.rollback_path = rollback_path

    @staticmethod
    def take_snapshot(target_host: str, snapshot_path: str = DEFAULT_HARNESS_SNAPSHOT_PATH) -> bool:
        """
        Invia una richiesta sincrona all'endpoint di snapshot dell'applicazione target
        per congelare lo stato attuale del database in memoria.

        Args:
            target_host (str): L'host/URL di base del server target.
            snapshot_path (str): Path dell'endpoint di snapshot (default ``/test/snapshot``).

        Returns:
            bool: True se lo snapshot è stato eseguito correttamente, False altrimenti.
        """
        snapshot_url = f"{target_host.rstrip('/')}/{snapshot_path.lstrip('/')}"
        try:
            logger.info(f"💾 [STATE ENGINE] Esecuzione snapshot dello stato su: {snapshot_url}")
            response = requests.post(snapshot_url, timeout=5)
            if response.status_code == 200:
                logger.info("✅ Snapshot creato con successo sul backend target.")
                return True
            else:
                logger.warning(f"⚠️ Snapshot fallito. Status HTTP target: {response.status_code}")
        except Exception as e:
            logger.error(f"❌ Connessione fallita per snapshot a {snapshot_url}: {e}")
        return False

    @staticmethod
    def trigger_rollback(
        target_host: str, rollback_path: str = DEFAULT_HARNESS_ROLLBACK_PATH
    ) -> bool:
        """
        Invia una richiesta POST sincrona all'endpoint di rollback dell'applicazione target
        per ripristinare il DB allo stato originario congelato dallo snapshot (Fase di Teardown).

        Args:
            target_host (str): L'host/URL di base del server target.
            rollback_path (str): Path dell'endpoint di rollback (default ``/test/rollback``).

        Returns:
            bool: True se il rollback ha avuto successo, False altrimenti.
        """
        rollback_url = f"{target_host.rstrip('/')}/{rollback_path.lstrip('/')}"
        try:
            logger.info(f"🔄 [STATE ENGINE] Richiesta rollback dello stato su: {rollback_url}")
            response = requests.post(rollback_url, timeout=5)
            if response.status_code == 200:
                logger.info("✅ Rollback dello stato completato con successo sul backend target.")
                return True
            else:
                logger.warning(f"⚠️ Rollback fallito. Status HTTP target: {response.status_code}")
        except Exception as e:
            logger.error(f"❌ Connessione fallita per rollback a {rollback_url}: {e}")
        return False

    # Wrapper di istanza: usano host e path configurati nel costruttore
    def take_instance_snapshot(self) -> bool:
        if not self.target_base_url:
            raise ValueError("target_base_url non configurato per questa istanza.")
        return self.take_snapshot(self.target_base_url, self.snapshot_path)

    def trigger_instance_rollback(self) -> bool:
        if not self.target_base_url:
            raise ValueError("target_base_url non configurato per questa istanza.")
        return self.trigger_rollback(self.target_base_url, self.rollback_path)


# Classe Alias per retrocompatibilità immediata con altri moduli
class BOLAStateManager(APIStateEngine):
    """
    Classe adattatrice per mantenere compatibilità con il codice legacy.
    Mappa i vecchi metodi di istanza sui nuovi servizi di APIStateEngine.
    """

    def take_snapshot(self) -> bool:  # type: ignore[override]
        return self.take_instance_snapshot()

    def trigger_rollback(self) -> bool:  # type: ignore[override]
        return self.trigger_instance_rollback()
