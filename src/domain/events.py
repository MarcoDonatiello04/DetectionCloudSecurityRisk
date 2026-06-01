from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict


@dataclass(frozen=True)
class DomainEvent:
    """Evento base del dominio."""
    name: str
    payload: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.utcnow)


# Tipi di eventi standardizzati
EVENT_STATIC_SCAN_COMPLETED = "event.static_scan.completed"
EVENT_TRAFFIC_CAPTURED = "event.traffic.captured"
EVENT_FINDING_DETECTED = "event.finding.detected"
EVENT_PIPELINE_COMPLETED = "event.pipeline.completed"
