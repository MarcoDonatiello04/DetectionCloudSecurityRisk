from src.core.api2_broken_auth.dynamic_tester import DynamicTester
from src.domain.entities import Finding, ScanTarget
from src.domain.interfaces import IVulnerabilityDetector


class Api2BrokenAuthDetector(IVulnerabilityDetector):
    """
    Rilevatore di vulnerabilità OWASP API2: Broken Authentication.
    """

    def __init__(self, tester: DynamicTester | None = None):
        self.tester = tester

    @property
    def detector_id(self) -> str:
        return "API2_BROKEN_AUTH"

    @property
    def name(self) -> str:
        return "Broken Authentication Detector"

    def analyze(self, target: ScanTarget) -> list[Finding]:
        target_path = target.target_path or "."
        tester = self.tester or DynamicTester(target_path)
        return tester.run_scan() if hasattr(tester, "run_scan") else []


AuthDynamicTester = Api2BrokenAuthDetector
