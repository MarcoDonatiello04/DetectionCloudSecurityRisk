from abc import ABC, abstractmethod
from collections.abc import Callable
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


class IDetector(ABC):
    """
    Interfaccia astratta legacy per i detector dinamici o logici.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Nome identificativo del detector.

        Returns:
            str: Il nome del detector.
        """
        pass

    @abstractmethod
    def analyze(self, context: Any) -> list[Finding]:
        """
        Esegue l'analisi logica basata sul contesto (es: traffico catturato o config) e ritorna i findings.

        Args:
            context (Any): Oggetto contenente le informazioni contestuali per l'analisi.

        Returns:
            List[Finding]: Lista di Finding generati dall'analisi.
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



class IRemediation(ABC):
    """
    Interfaccia astratta per i moduli di remediation automatica.
    """

    @property
    @abstractmethod
    def target_category(self) -> str:
        """
        La categoria di finding per cui questa remediation è applicabile.

        Returns:
            str: La categoria associata.
        """
        pass

    @abstractmethod
    def execute(self, finding: Finding) -> bool:
        """
        Esegue l'azione correttiva per mitigare il finding.

        Args:
            finding (Finding): Il Finding su cui applicare la mitigazione.

        Returns:
            bool: True se l'azione correttiva è stata eseguita con successo, altrimenti False.
        """
        pass


class IEventBus(ABC):
    """
    Interfaccia per il bus degli eventi asincroni o sincroni per la comunicazione decoupled.
    """

    @abstractmethod
    def publish(self, event_type: str, event_data: Any) -> None:
        """
        Invia un evento sul bus, notificando tutti i sottoscrittori associati.

        Args:
            event_type (str): Il tipo di evento da pubblicare.
            event_data (Any): Il payload dell'evento.
        """
        pass

    @abstractmethod
    def subscribe(self, event_type: str, handler: Callable[[Any], None]) -> None:
        """
        Registra un handler/callback per un determinato tipo di evento.

        Args:
            event_type (str): Il tipo di evento al quale iscriversi.
            handler (Callable[[Any], None]): La callback da invocare quando l'evento viene emesso.
        """
        pass
