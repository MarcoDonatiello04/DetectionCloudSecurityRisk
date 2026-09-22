from abc import ABC, abstractmethod
from typing import Any

from src.domain.entities import Finding, ScanTarget


class IScanner(ABC):
    """
    Interfaccia astratta per gli scanner statici (es: Semgrep, Checkov, Spectral).
    """

    @abstractmethod
    def scan(self, target_dir: str) -> list[Finding]:
        """
        Esegue la scansione statica della directory target e restituisce la lista di findings rilevati.

        Args:
            target_dir (str): Percorso della directory da scansionare.

        Returns:
            List[Finding]: Lista di Finding di sicurezza individuati.
        """
        pass


class IVulnerabilityDetector(ABC):
    """
    Interfaccia astratta standardizzata per tutti i detector di vulnerabilità del sistema.
    """

    @property
    @abstractmethod
    def detector_id(self) -> str:
        """
        Restituisce l'identificatore unico del detector (es: 'API1_BOLA', 'API2_BROKEN_AUTH').
        """
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Restituisce un nome sintetico e leggibile del detector.
        """
        pass

    @abstractmethod
    def analyze(self, target: ScanTarget) -> list[Finding]:
        """
        Esegue l'analisi sul bersaglio specificato e restituisce la lista di findings individuate.

        Args:
            target (ScanTarget): Il bersaglio della scansione.

        Returns:
            list[Finding]: Lista di Finding generati dall'analisi.
        """
        pass


class ILlmProvider(ABC):
    """
    Porta verso un modello linguistico che genera indicazioni correttive.
    Il livello applicativo dipende solo da questo contratto; la realizzazione
    (es. Ollama locale) vive nell'infrastruttura e viene iniettata dal
    composition root.
    """

    @abstractmethod
    def get_available_model(self) -> str | None:
        """
        Restituisce il nome del modello utilizzabile, o None se nessun modello
        è disponibile.
        """
        pass

    @abstractmethod
    def generate_remediation(
        self, finding_id: str, title: str, category: str, source: str, description: str
    ) -> dict[str, Any] | None:
        """
        Genera una remediation strutturata per il finding descritto.

        Returns:
            dict | None: dizionario con chiavi title, description, impact,
            remediation_steps, example; None se la generazione fallisce.
        """
        pass
