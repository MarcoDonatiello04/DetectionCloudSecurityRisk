from src.core.api3_bopla.orchestrator import BOPLAOrchestrator
from src.domain.entities import Finding, ScanTarget
from src.domain.interfaces import IVulnerabilityDetector


class Api3BoplaDetector(IVulnerabilityDetector):
    """
    Rilevatore di vulnerabilità OWASP API3: Broken Object Property Level Access (BOPLA).
    """

    def __init__(self, orchestrator: BOPLAOrchestrator | None = None):
        self.orchestrator = orchestrator

    @property
    def detector_id(self) -> str:
        return "API3_BOPLA"

    @property
    def name(self) -> str:
        return "Broken Object Property Level Access Detector"

    def analyze(self, target: ScanTarget) -> list[Finding]:
        target_path = target.target_path or "."
        if self.orchestrator:
            res = self.orchestrator.run_assessment(target_path, openapi_spec=target.openapi_spec)
            return res.get("findings", [])
        return []


BOPLADetector = Api3BoplaDetector
