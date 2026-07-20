from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class DomainEvent:
    """
    Rappresenta un evento immutabile emesso all'interno del dominio event-driven.

    Attributes:
        name (str): Il nome identificativo del tipo di evento.
        payload (Dict[str, Any]): I dati associati all'evento.
        timestamp (datetime): La data e ora di creazione dell'evento.
    """

    name: str
    payload: dict[str, Any]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# Tipi di eventi standardizzati per la pipeline di sicurezza
EVENT_STATIC_SCAN_COMPLETED = "event.static_scan.completed"
EVENT_TRAFFIC_CAPTURED = "event.traffic.captured"
EVENT_FINDING_DETECTED = "event.finding.detected"
EVENT_PIPELINE_COMPLETED = "event.pipeline.completed"
