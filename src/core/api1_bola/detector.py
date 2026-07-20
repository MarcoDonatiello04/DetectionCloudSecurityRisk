from typing import Any

from src.core.api1_bola.dynamic_orchestrator import DynamicOrchestrator
from src.domain.entities import Finding, ScanTarget
from src.domain.interfaces import IVulnerabilityDetector


class Api1BolaDetector(IVulnerabilityDetector):
    """
    Rilevatore di vulnerabilità OWASP API1: Broken Object Level Authorization (BOLA / IDOR).
    """

    def __init__(self, orchestrator: DynamicOrchestrator | None = None):
        self.orchestrator = orchestrator or DynamicOrchestrator()

    @property
    def detector_id(self) -> str:
        return "API1_BOLA"

    @property
    def name(self) -> str:
        return "Broken Object Level Authorization Detector"

    def analyze(self, target: ScanTarget) -> list[Finding]:
        target_path = target.target_path or "."
        return self.orchestrator.run_scan(target_path)

    def run_scan(self, target_dir: str) -> list[Finding]:
        return self.orchestrator.run_scan(target_dir)


BOLAAnalyzer = Api1BolaDetector
