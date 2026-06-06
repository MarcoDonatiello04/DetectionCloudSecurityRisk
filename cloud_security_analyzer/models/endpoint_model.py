"""
Rappresenta un endpoint API nel catalogo rilevato e analizzato.
Responsabilità:
- Incapsulare le informazioni di route dell'API (metodo, path, documentazione).
- Mantenere lo stato di sicurezza dinamico dell'endpoint (BOLA, violazioni OpenAPI).
"""

from typing import List, Dict, Any

class EndpointModel:
    """
    Rappresenta un elemento del Catalogo API esposto per la GUI.
    """

    def __init__(self, data: Dict[str, Any]):
        """
        Inizializza il modello a partire dal dizionario serializzato.
        """
        self.data = data

    @property
    def method(self) -> str:
        return self.data.get("method", "GET").upper()

    @property
    def path(self) -> str:
        return self.data.get("path", "")

    @property
    def summary(self) -> str:
        return self.data.get("summary", "")

    @property
    def description(self) -> str:
        return self.data.get("description", "")

    @property
    def documented(self) -> bool:
        return bool(self.data.get("documented", True))

    @property
    def shadow(self) -> bool:
        return bool(self.data.get("shadow", False))

    @property
    def violations(self) -> List[Dict[str, Any]]:
        return self.data.get("violations", [])

    @property
    def violation_count(self) -> int:
        return len(self.violations)

    @property
    def bola_status(self) -> str:
        return self.data.get("bola_status", "UNTESTED").upper()

    @property
    def bola_findings(self) -> List[Dict[str, Any]]:
        return self.data.get("bola_findings", [])

    @property
    def is_dynamic(self) -> bool:
        return bool(self.data.get("is_dynamic", False))

    @property
    def security_label(self) -> str:
        """
        Ritorna una descrizione leggibile dello stato BOLA dell'endpoint.
        """
        status_map = {
            "VULNERABLE": "VULNERABILE (BOLA/Auth)",
            "POTENTIAL": "SOSPETTO (Non Confermato)",
            "SAFE": "SICURO (Convalidato)",
            "UNTESTED": "NON TESTATO"
        }
        return status_map.get(self.bola_status, "NON TESTATO")
