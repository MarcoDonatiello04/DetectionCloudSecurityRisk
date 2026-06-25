from typing import Optional, Dict, Any, List
from src.core.api4_unrestricted_resource_consumption.models import ResourceConsumptionReport, ResourceConsumptionFinding
from src.core.api4_unrestricted_resource_consumption.layers.layer1_ast import analyze_ast
from src.core.api4_unrestricted_resource_consumption.layers.layer2_config import analyze_configs as analyze_config
from src.core.api4_unrestricted_resource_consumption.layers.layer3_openapi import analyze_openapi


def _build_coverage_signals(
    findings: List[ResourceConsumptionFinding],
) -> Dict[str, List[str]]:
    signals: Dict[str, List[str]] = {}
    for f in findings:
        signals.setdefault(f.category, [])
        if f.rule_id not in signals[f.category]:
            signals[f.category].append(f.rule_id)
    return signals


def _build_summary(
    findings: List[ResourceConsumptionFinding],
) -> Dict[str, Dict[str, int]]:
    summary: Dict[str, Dict[str, int]] = {
        "severity": {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        "category": {},
        "layer": {"ast": 0, "config": 0, "openapi": 0},
    }
    for f in findings:
        sev = f.severity.upper()
        summary["severity"][sev] = summary["severity"].get(sev, 0) + 1
        summary["category"][f.category] = summary["category"].get(f.category, 0) + 1
        summary["layer"][f.layer] = summary["layer"].get(f.layer, 0) + 1
    return summary


def analyze(
    target_path: str,
    openapi_spec: Optional[Dict[str, Any]] = None,
    enrich_spec: bool = False,
) -> ResourceConsumptionReport:
    """
    Entry point of the API4:2023 Unrestricted Resource Consumption module.

    Args:
        target_path:  Root path of the codebase to analyze.
        openapi_spec: Optional pre-parsed OpenAPI specification dictionary.
                      If None, Layer 3 is silently skipped.
        enrich_spec:  If True and openapi_spec is provided, adds
                      x-security-analysis extension fields to the spec in-place.

    Returns:
        ResourceConsumptionReport containing aggregated findings from all layers.
    """
    findings: List[ResourceConsumptionFinding] = []

    # Layer 1 — AST analysis (always executed)
    ast_findings = analyze_ast(target_path)
    findings.extend(ast_findings)

    # Layer 2 — Configuration file analysis (always executed)
    config_findings = analyze_config(target_path)
    findings.extend(config_findings)

    # Layer 3 — OpenAPI spec analysis (only if spec available)
    if openapi_spec is not None:
        openapi_findings = analyze_openapi(openapi_spec, enrich_spec=enrich_spec)
        findings.extend(openapi_findings)

    return ResourceConsumptionReport(
        target_path=target_path,
        findings=findings,
        coverage_signals=_build_coverage_signals(findings),
        summary=_build_summary(findings),
    )
