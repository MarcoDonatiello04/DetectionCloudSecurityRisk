import os
import json
import logging
from typing import List, Dict, Any
from src.domain.entities import Finding

logger = logging.getLogger("SecurityPlatform.ReportRepository")


class ReportRepository:
    """
    Gestore di persistenza per i report e gli inventari della piattaforma.
    Salva i findings in formato standardizzato JSON per l'integrazione CI/CD.
    """

    def __init__(self, output_dir: str):
        self.output_dir = os.path.abspath(output_dir)
        os.makedirs(self.output_dir, exist_ok=True)

    def save_findings(self, findings: List[Finding], filename: str = "findings_report.json") -> str:
        """Salva una lista di Finding in un file JSON. Ritorna il path assoluto."""
        filepath = os.path.join(self.output_dir, filename)
        try:
            data = [f.to_dict() for f in findings]
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.info(f"💾 Report dei Findings salvato con successo in: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Errore durante il salvataggio dei findings in {filepath}: {e}", exc_info=True)
            return ""

    def save_inventory(self, inventory: List[Dict[str, Any]], filename: str = "unified_api_inventory.json") -> str:
        """Salva l'inventario API unificato in formato JSON."""
        filepath = os.path.join(self.output_dir, filename)
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(inventory, f, indent=2, ensure_ascii=False)
            logger.info(f"💾 Inventario API salvato con successo in: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Errore durante il salvataggio dell'inventario in {filepath}: {e}", exc_info=True)
            return ""
