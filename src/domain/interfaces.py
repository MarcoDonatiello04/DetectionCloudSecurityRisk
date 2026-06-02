from abc import ABC, abstractmethod
from typing import List, Callable, Any
from src.domain.entities import Finding


class IScanner(ABC):
    """
    Interfaccia astratta per gli scanner statici (es: Semgrep, Checkov, Spectral).
    """
    
    @abstractmethod
    def scan(self, target_dir: str) -> List[Finding]:
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
    Interfaccia astratta per i detector dinamici o logici (es: BOLA Analyzer, Shadow API Hunter).
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
    def analyze(self, context: Any) -> List[Finding]:
        """
        Esegue l'analisi logica basata sul contesto (es: traffico catturato o config) e ritorna i findings.

        Args:
            context (Any): Oggetto contenente le informazioni contestuali per l'analisi.

        Returns:
            List[Finding]: Lista di Finding generati dall'analisi.
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
