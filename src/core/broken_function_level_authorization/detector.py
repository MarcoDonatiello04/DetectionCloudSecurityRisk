from typing import Any

from src.core.broken_function_level_authorization.layers.layer1_ast import (
    analyze_ast_with_endpoints,
)
from src.core.broken_function_level_authorization.layers.layer2_config import (
    analyze_configs as analyze_config,
)
from src.core.broken_function_level_authorization.layers.layer3_openapi import analyze_openapi
from src.core.broken_function_level_authorization.models import (
    FunctionAuthzFinding,
    FunctionAuthzReport,
)


def _build_coverage_signals(
    findings: list[FunctionAuthzFinding],
) -> dict[str, list[str]]:
    signals: dict[str, list[str]] = {}
    for f in findings:
        signals.setdefault(f.category, [])
        if f.rule_id not in signals[f.category]:
            signals[f.category].append(f.rule_id)
    return signals


def _build_summary(
    findings: list[FunctionAuthzFinding],
) -> dict[str, dict[str, int]]:
    summary: dict[str, dict[str, int]] = {
        "severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        "category": {},
        "layer": {"ast": 0, "config": 0, "openapi": 0, "ast+openapi": 0},
    }
    for f in findings:
        sev = f.severity.upper()
        summary["severity"][sev] = summary["severity"].get(sev, 0) + 1
        summary["category"][f.category] = summary["category"].get(f.category, 0) + 1
        summary["layer"][f.layer] = summary["layer"].get(f.layer, 0) + 1
    return summary


RULE_PRIORITY = {
    "BF-006": 6,
    "BF-004": 5,
    "BF-003": 4,
    "BF-002": 3,
    "BF-001": 2,
    "BF-005": 1,
}


def deduplicate_findings(findings: list[FunctionAuthzFinding]) -> list[FunctionAuthzFinding]:
    """
    Per ogni coppia (file_path, endpoint), mantiene solo il finding
    con la rule di priorità più alta.
    """
    config_findings = [f for f in findings if f.rule_id == "BF-005" or not f.endpoint]
    endpoint_findings = [f for f in findings if f.rule_id != "BF-005" and f.endpoint]

    seen: dict[tuple, FunctionAuthzFinding] = {}
    for finding in endpoint_findings:
        endpoint_val = finding.endpoint
        path = ""
        if endpoint_val:
            parts = endpoint_val.strip().split()
            path = parts[-1] if parts else ""

        key = (finding.file_path, path)
        if key not in seen:
            seen[key] = finding
        else:
            existing_priority = RULE_PRIORITY.get(seen[key].rule_id, 0)
            new_priority = RULE_PRIORITY.get(finding.rule_id, 0)
            if new_priority > existing_priority:
                seen[key] = finding

    return list(seen.values()) + config_findings


def analyze(
    target_path: str,
    openapi_spec: dict[str, Any] | None = None,
    enrich_spec: bool = False,
) -> FunctionAuthzReport:
    """
    Entry point of the API5:2023 Broken Function Level Authorization module.

    Args:
        target_path:  Root path of the codebase to analyze.
        openapi_spec: Optional pre-parsed OpenAPI specification dictionary.
                      If None, Layer 3 is silently skipped.
        enrich_spec:  If True and openapi_spec is provided, adds
                      x-security-analysis extension fields to the spec in-place.

    Returns:
        FunctionAuthzReport containing aggregated findings from all layers.
    """
    findings: list[FunctionAuthzFinding] = []

    # Layer 1 — AST analysis (always executed)
    ast_findings, discovered_endpoints = analyze_ast_with_endpoints(target_path)
    findings.extend(ast_findings)

    # Layer 2 — Configuration file analysis (always executed)
    config_findings = analyze_config(target_path)
    findings.extend(config_findings)

    # Layer 3 — OpenAPI spec analysis (only if spec available)
    if openapi_spec is not None:
        openapi_findings = analyze_openapi(
            spec=openapi_spec,
            ast_findings=ast_findings,
            discovered_endpoints=discovered_endpoints,
            enrich_spec=enrich_spec,
        )
        findings.extend(openapi_findings)

    # Deduplicate findings so each endpoint has a single rule owner
    findings = deduplicate_findings(findings)

    return FunctionAuthzReport(
        target_path=target_path,
        findings=findings,
        coverage_signals=_build_coverage_signals(findings),
        summary=_build_summary(findings),
    )


def analyze_content(content: str, filename: str = "app.py") -> FunctionAuthzReport:
    """
    Helper for testing inline content analysis.
    Writes content to a temporary file and runs analyze().
    """
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmpdir:
        file_path = Path(tmpdir) / filename
        file_path.write_text(content, encoding="utf-8")
        return analyze(str(tmpdir))
