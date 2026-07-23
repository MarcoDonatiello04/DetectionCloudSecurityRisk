"""
Domain Layer Package (Clean / Hexagonal Architecture).
Espone le entità immutabili del dominio, gli enumeratori, le eccezioni e le interfacce primarie (Porte).
"""

from src.domain.entities import (
    APIContext,
    CodeLocation,
    Finding,
    FindingCategory,
    FindingSource,
    RiskContext,
    RuntimeEvidence,
    ScanTarget,
    Severity,
    ValidationStatus,
)
from src.domain.events import (
    EVENT_FINDING_DETECTED,
    EVENT_PIPELINE_COMPLETED,
    EVENT_STATIC_SCAN_COMPLETED,
    EVENT_TRAFFIC_CAPTURED,
    DomainEvent,
)
from src.domain.exceptions import (
    InvalidFindingException,
    PluginLoadException,
    SecurityPlatformException,
)
from src.domain.interfaces import (
    IDetector,
    IEventBus,
    IRemediation,
    IScanner,
    IVulnerabilityDetector,
)

__all__ = [
    "EVENT_FINDING_DETECTED",
    "EVENT_PIPELINE_COMPLETED",
    "EVENT_STATIC_SCAN_COMPLETED",
    "EVENT_TRAFFIC_CAPTURED",
    "APIContext",
    "CodeLocation",
    "DomainEvent",
    "Finding",
    "FindingCategory",
    "FindingSource",
    "IDetector",
    "IEventBus",
    "IRemediation",
    "IScanner",
    "IVulnerabilityDetector",
    "InvalidFindingException",
    "PluginLoadException",
    "RiskContext",
    "RuntimeEvidence",
    "ScanTarget",
    "SecurityPlatformException",
    "Severity",
    "ValidationStatus",
]
