import logging
from pathlib import Path

from src.core.api8_ssrf import normalizer, semgrep_runner
from src.core.api8_ssrf.layers import layer3_openapi
from src.core.api8_ssrf.models import SsrfFinding, SsrfReport
from src.domain.entities import Finding, ScanTarget
from src.domain.interfaces import IVulnerabilityDetector

logger = logging.getLogger(__name__)

RULES_PATH = Path(__file__).parent / "rules" / "semgrep_rules.yml"


def analyze(
    target_path: str,
    openapi_spec: dict | None = None,
    enrich_spec: bool = False,
    semgrep_timeout: int = 60,
) -> SsrfReport:
    """
    Entry point for the API7:2023 Server-Side Request Forgery (SSRF) module.

    Args:
        target_path: Root path of the codebase to analyze.
        openapi_spec: Optional parsed OpenAPI specification dictionary.
        enrich_spec: If True and openapi_spec is provided, mutates the spec dict in-place.
        semgrep_timeout: Timeout in seconds for Semgrep execution.

    Returns:
        SsrfReport containing normalized findings and analysis metadata.
    """
    # Verifica Semgrep disponibile
    semgrep_version = semgrep_runner.check_semgrep_available()

    findings: list[SsrfFinding] = []

    # Layer principale: Semgrep
    try:
        raw_output = semgrep_runner.run_semgrep(
            target_path=target_path, rules_path=str(RULES_PATH), timeout=semgrep_timeout
        )
        semgrep_findings = normalizer.normalize_semgrep_output(raw_output, target_path)
        findings.extend(semgrep_findings)
    except semgrep_runner.SemgrepTimeoutError as e:
        # Non crashare — ritorna findings parziali con warning
        logging.warning(f"API7: {e} — findings potrebbero essere incompleti")

    # Layer 3: OpenAPI (opzionale)
    if openapi_spec is not None:
        openapi_findings = layer3_openapi.analyze_openapi(openapi_spec, enrich_spec=enrich_spec)
        findings.extend(openapi_findings)

    return SsrfReport(
        target_path=target_path,
        semgrep_version=semgrep_version,
        findings=findings,
        coverage_signals=_build_coverage_signals(findings),
        summary=_build_summary(findings),
    )


def _build_coverage_signals(findings: list[SsrfFinding]) -> dict:
    return {
        rule_id: any(f.rule_id == rule_id for f in findings)
        for rule_id in ["SS-001", "SS-002", "SS-003", "SS-004", "SS-005", "SS-006"]
    }


def _build_summary(findings: list[SsrfFinding]) -> dict:
    return {
        "total": len(findings),
        "by_severity": {
            sev: len([f for f in findings if f.severity == sev])
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        },
        "by_category": {
            cat: len([f for f in findings if f.category == cat])
            for cat in {f.category for f in findings}
        },
        "semgrep_findings": len([f for f in findings if f.layer == "semgrep"]),
        "openapi_findings": len([f for f in findings if f.layer == "openapi"]),
    }


class Api8SsrfDetector(IVulnerabilityDetector):
    """
    Rilevatore di vulnerabilità OWASP API8: Server-Side Request Forgery (SSRF).
    """

    @property
    def detector_id(self) -> str:
        return "API8_SSRF"

    @property
    def name(self) -> str:
        return "Server-Side Request Forgery Detector"

    def analyze(self, target: ScanTarget) -> list[Finding]:
        target_path = target.target_path or "."
        report = analyze(target_path, openapi_spec=target.openapi_spec)
        return report.findings
