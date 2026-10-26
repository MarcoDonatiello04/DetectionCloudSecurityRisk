from typing import Any

from src.core.api2_broken_auth.discovery import Config, OutputConfig
from src.core.api3_bopla.orchestrator import KIND_LABELS, STATUS_LABELS, BOPLAOrchestrator
from src.domain.entities import (
    APIContext,
    CodeLocation,
    Finding,
    FindingCategory,
    FindingSource,
    RuntimeEvidence,
    ScanTarget,
    Severity,
)
from src.domain.interfaces import IVulnerabilityDetector
from src.normalization.normalizer import APIEndpointNormalizer

OWASP_CATEGORY = "API3:2023"
READ_TESTS = {"T01", "T06"}
# Excessive data exposure (read) and mass assignment (write)
CWE_EXPOSURE = "CWE-213"
CWE_MASS_ASSIGNMENT = "CWE-915"
KIND_CWE = {
    "mass_assignment": CWE_MASS_ASSIGNMENT,
    "readonly_writable": CWE_MASS_ASSIGNMENT,
    "excessive_exposure": CWE_EXPOSURE,
    "writeonly_readable": CWE_EXPOSURE,
    "undocumented_property": CWE_EXPOSURE,
}


def _correlation_key(method: str | None, endpoint: str | None) -> str | None:
    if not endpoint or not method or "|" in method:
        return None
    return f"api:{method.upper()}:{APIEndpointNormalizer.normalize_path(endpoint)}"


def _dynamic_finding(f: dict[str, Any]) -> Finding:
    read = f["test_id"] in READ_TESTS
    return Finding.create(
        source=FindingSource.RUNTIME_VALIDATOR,
        category=FindingCategory.DATA_EXPOSURE if read else FindingCategory.AUTHORIZATION,
        title=f"BOPLA {f['test_id']} confermata a runtime su {f['property_name']}",
        description="\n".join(f.get("evidence") or []),
        severity=Severity.HIGH,
        confidence=float(f.get("confidence") or 1.0),
        rule_id=f"BOPLA-{f['test_id']}",
        target_identifier=f"{f['method']} {f['endpoint']}#{f['property_name']}",
        api=APIContext(endpoint=f["endpoint"], method=f["method"]),
        runtime_evidence=RuntimeEvidence(
            tested_url=f["endpoint"],
            http_status=f.get("response_code"),
            response_snippet=str(f.get("response"))[:500],
        ),
        correlation_key=_correlation_key(f["method"], f["endpoint"]),
        owasp_api_category=OWASP_CATEGORY,
        cwe_id=CWE_EXPOSURE if read else CWE_MASS_ASSIGNMENT,
        tags=["bopla", "dynamic"],
        raw_data=f,
    )


def _static_finding(f: dict[str, Any]) -> Finding:
    method, _, path = (f.get("endpoint") or "").partition(" ")
    read = f["kind"] in {"excessive_exposure", "writeonly_readable"}
    return Finding.create(
        # A static finding confirmed by a dynamic test carries the runtime evidence of that test
        source=FindingSource.STATIC_ANALYZER,
        category=FindingCategory.DATA_EXPOSURE if read else FindingCategory.AUTHORIZATION,
        title=f"{f['rule_id']} {KIND_LABELS.get(f['kind'], f['kind'])} ({f.get('entity') or '?'})",
        description="\n".join(f["evidence"]),
        severity=Severity(f["severity"]),
        confidence=float(f["confidence"]),
        rule_id=f["rule_id"],
        target_identifier=f"{f['file_path']}:{f['line']}:{f['sink']}",
        location=CodeLocation(
            file_path=f["file_path"], start_line=f["line"] or None, code_snippet=f["sink"]
        ),
        api=APIContext(endpoint=path or None, method=method or None) if path else None,
        correlation_key=_correlation_key(method, path),
        owasp_api_category=OWASP_CATEGORY,
        cwe_id=KIND_CWE.get(f["kind"]),
        tags=["bopla", "static", STATUS_LABELS.get(f["status"], f["status"])],
        raw_data=f,
    )


class Api3BoplaDetector(IVulnerabilityDetector):
    """
    Rilevatore di vulnerabilità OWASP API3: Broken Object Property Level Access (BOPLA).

    Traduce il report dell'orchestratore nel modello di dominio: le prove dinamiche confermate
    e tutte le segnalazioni statiche (BOPLA-S01..S04, con il loro stato di verifica).
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
        orchestrator = self.orchestrator or BOPLAOrchestrator(
            Config(output=OutputConfig(path=str(target.options.get("output_path", "output"))))
        )
        report = orchestrator.run_assessment(
            target_path,
            openapi_spec=target.openapi_spec or None,
            runtime_traffic=target.options.get("runtime_traffic"),
            headers_matrix=target.options.get("headers_matrix"),
        )
        findings = [_dynamic_finding(f) for f in report.get("findings", []) if f.get("verified")]
        findings += [_static_finding(f) for f in report.get("static_findings", [])]
        return findings


BOPLADetector = Api3BoplaDetector
