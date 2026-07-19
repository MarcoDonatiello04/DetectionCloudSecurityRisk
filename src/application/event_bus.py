import logging
import threading
from collections.abc import Callable
from typing import Any

from src.domain.events import DomainEvent
from src.domain.interfaces import IEventBus

logger = logging.getLogger("SecurityPlatform.EventBus")


class EventBus(IEventBus):
    """
    Bus degli eventi in-memory e thread-safe.
    Gestisce la registrazione e il dispatch dei DomainEvent.
    """

    def __init__(self):
        """
        Inizializza l'EventBus istanziando la struttura dei sottoscrittori e il lock.
        """
        self._subscribers: dict[str, list[Callable[[DomainEvent], None]]] = {}
        self._lock = threading.RLock()

    def subscribe(self, event_type: str, handler: Callable[[DomainEvent], None]) -> None:
        """
        Sottoscrive un handler per ricevere eventi del tipo specificato.

        Args:
            event_type (str): Il nome del tipo di evento al quale iscriversi.
            handler (Callable[[DomainEvent], None]): La callback da registrare.
        """
        with self._lock:
            if event_type not in self._subscribers:
                self._subscribers[event_type] = []
            if handler not in self._subscribers[event_type]:
                self._subscribers[event_type].append(handler)
                logger.debug(
                    f"Handler {handler.__name__ if hasattr(handler, '__name__') else str(handler)} registrato per '{event_type}'"
                )

    def publish(self, event_type: str, event_data: Any) -> None:
        """
        Pubblica un evento sul bus. Il payload viene racchiuso in un DomainEvent
        e inviato in modo sincrono a tutti gli handler registrati.

        Args:
            event_type (str): Il nome del tipo di evento da pubblicare.
            event_data (Any): Il payload o i dati associati all'evento.
        """
        event = DomainEvent(name=event_type, payload=event_data)
        handlers = []

        with self._lock:
            if event_type in self._subscribers:
                # Creiamo una copia della lista per evitare problemi di mutazione concorrente durante l'esecuzione delle callback
                handlers = list(self._subscribers[event_type])

        if not handlers:
            logger.debug(f"Nessun handler registrato per l'evento '{event_type}'")
            return

        logger.debug(f"Pubblicazione evento '{event_type}' a {len(handlers)} handler(s)")
        for handler in handlers:
            try:
                handler(event)
            except Exception as e:
                logger.error(
                    f"Errore durante l'esecuzione dell'handler {handler} per l'evento '{event_type}': {e}",
                    exc_info=True,
                )
