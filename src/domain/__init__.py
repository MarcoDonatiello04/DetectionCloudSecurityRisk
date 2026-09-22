"""
Domain Layer Package (Clean / Hexagonal Architecture).
Espone le entità immutabili del dominio, gli enumeratori, le eccezioni e le interfacce primarie (Porte).
"""

from src.domain.entities import (
    APIContext,
    CodeLocation,
    Finding,
    FindingCategory,
    FindingNature,
    FindingSource,
    RiskContext,
    RuntimeEvidence,
    ScanTarget,
    Severity,
)
from src.domain.exceptions import (
    InvalidFindingException,
    SecurityPlatformException,
)
from src.domain.interfaces import (
    ILlmProvider,
    IScanner,
    IVulnerabilityDetector,
)
from src.domain.remediation_model import RemediationModel

__all__ = [
    "APIContext",
    "CodeLocation",
    "Finding",
    "FindingCategory",
    "FindingNature",
    "FindingSource",
    "ILlmProvider",
    "IScanner",
    "IVulnerabilityDetector",
    "InvalidFindingException",
    "RemediationModel",
    "RiskContext",
    "RuntimeEvidence",
    "ScanTarget",
    "SecurityPlatformException",
    "Severity",
]
