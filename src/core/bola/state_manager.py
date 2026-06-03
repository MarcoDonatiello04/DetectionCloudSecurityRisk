"""
Manager di Stato BOLA per il framework D-AST.
Fornisce la logica di coordinamento per congelare (Snapshot) e ripristinare (Rollback)
lo stato del database in memoria dell'applicazione target Flask.
Questo garantisce che i test di scrittura e distruttivi (PUT, DELETE) non sporchino
o compromettano lo stato del sistema e rimangano isolati per ciascun test-case.
"""

import logging
import requests

logger = logging.getLogger("SecurityPlatform.BOLA.StateManager")


class BOLAStateManager:
    """
    Gestisce l'orchestrazione delle chiamate HTTP al backend target
    per catturare snapshot e innescare rollback.
    """

    def __init__(self, target_base_url: str):
        """
        Inizializza lo state manager con gli endpoint dell'API target.
        """
        self.target_base_url = target_base_url
        self.snapshot_url = f"{target_base_url.rstrip('/')}/test/snapshot"
        self.rollback_url = f"{target_base_url.rstrip('/')}/test/rollback"

    def take_snapshot(self) -> bool:
        """
        Invia una richiesta HTTP POST all'endpoint di snapshot per congelare lo stato attuale.
        """
        try:
            logger.info("Innesco della richiesta di snapshot dello stato target...")
            # Effettua la chiamata di snapshot (supporta sia GET che POST)
            response = requests.post(self.snapshot_url, timeout=5)
            if response.status_code == 200:
                logger.info("✅ Snapshot dello stato target completato con successo.")
                return True
            else:
                logger.warning(f"⚠️ Impossibile eseguire lo snapshot dello stato. Status HTTP: {response.status_code}")
        except Exception as e:
            logger.error(f"❌ Errore di rete durante la chiamata di snapshot a {self.snapshot_url}: {e}")
        return False

    def trigger_rollback(self) -> bool:
        """
        Invia una richiesta HTTP POST all'endpoint di rollback per ripristinare lo stato salvato.
        """
        try:
            logger.info("Innesco della richiesta di rollback dello stato target...")
            response = requests.post(self.rollback_url, timeout=5)
            if response.status_code == 200:
                logger.info("✅ Rollback dello stato target eseguito con successo.")
                return True
            else:
                logger.warning(f"⚠️ Impossibile eseguire il rollback dello stato. Status HTTP: {response.status_code}")
        except Exception as e:
            logger.error(f"❌ Errore di rete durante la chiamata di rollback a {self.rollback_url}: {e}")
        return False
