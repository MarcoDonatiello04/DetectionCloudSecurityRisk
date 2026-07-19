import json
import logging
import os
from typing import Any

logger = logging.getLogger("SecurityPlatform.MitmproxyAdapter")


class MitmproxyClientAdapter:
    """
    Adapter per Mitmproxy.
    Carica i log del traffico di rete intercettati a runtime
    e salvati su file JSON per l'elaborazione dinamica.
    """

    def __init__(self, traffic_file_path: str):
        """
        Inizializza l'adattatore MitmproxyClientAdapter impostando il percorso del file dei log.

        Args:
            traffic_file_path (str): Il percorso del file contenente i log del traffico di rete.
        """
        self.traffic_file_path = os.path.abspath(traffic_file_path)

    def load_captured_traffic(self) -> list[dict[str, Any]]:
        """
        Carica il traffico salvato da mitmproxy. Ritorna una lista di dizionari di richieste.

        Returns:
            List[Dict[str, Any]]: La lista di dizionari che rappresentano il traffico di rete catturato.
        """
        if not os.path.exists(self.traffic_file_path):
            logger.warning(f"File di traffico Mitmproxy non trovato a: {self.traffic_file_path}")
            return []

        try:
            with open(self.traffic_file_path, encoding="utf-8") as f:
                traffic = json.load(f)
            logger.info(f"Caricate con successo {len(traffic)} richieste catturate da Mitmproxy.")
            return traffic
        except (json.JSONDecodeError, OSError) as e:
            logger.error(f"Errore durante il caricamento del file di traffico: {e}", exc_info=True)
            return []
