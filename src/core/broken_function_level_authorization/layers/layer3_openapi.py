from __future__ import annotations

import logging

from src.core.broken_function_level_authorization.models import FunctionAuthzFinding
from src.core.broken_function_level_authorization.rules.admin_path_exposure import (
    AdminPathExposureRule,
)
from src.core.broken_function_level_authorization.rules.shadow_admin_function import (
    ShadowAdminFunctionRule,
)

logger = logging.getLogger(__name__)


def detect_spec_version(spec: dict) -> str:
    if "openapi" in spec:
        return spec["openapi"]
    if "swagger" in spec:
        return spec["swagger"]
    raise ValueError("Unrecognized spec format — missing 'openapi' or 'swagger' key")


def _get_paths(spec: dict) -> dict:
    return spec.get("paths") or {}


def _enrich_spec(
    spec: dict,
    paths: dict,
    findings: list[FunctionAuthzFinding],
) -> None:
    endpoint_findings: dict[str, list[FunctionAuthzFinding]] = {}
    for f in findings:
        if f.endpoint:
            endpoint_findings.setdefault(f.endpoint, []).append(f)

    for endpoint_key, ep_findings in endpoint_findings.items():
        parts = endpoint_key.split(" ", 1)
        if len(parts) != 2:
            continue
        method, path_str = parts[0].lower(), parts[1]

        path_item = paths.get(path_str)
        if not isinstance(path_item, dict):
            continue
        operation = path_item.get(method)
        if not isinstance(operation, dict):
            continue

        analysis_entries = []
        seen_sigs = set()
        for f in ep_findings:
            sig = (f.rule_id, f.severity, f.missing_guard, f.layer)
            if sig in seen_sigs:
                continue
            seen_sigs.add(sig)

            entry = {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "missing_guard": f.missing_guard,
                "layer": f.layer,
            }
            if f.layer == "ast+openapi":
                entry["correlation"] = "confirmed_by_ast"
            analysis_entries.append(entry)

        if not analysis_entries:
            continue

        if "x-security-analysis" not in operation:
            operation["x-security-analysis"] = {"api5_findings": analysis_entries}
        else:
            existing = operation["x-security-analysis"]
            if isinstance(existing, dict) and "api5_findings" in existing:
                # Add only new entries
                for entry in analysis_entries:
                    if entry not in existing["api5_findings"]:
                        existing["api5_findings"].append(entry)
            else:
                operation["x-security-analysis"] = {"api5_findings": analysis_entries}


def analyze_openapi(
    spec: dict,
    ast_findings: list[FunctionAuthzFinding] | None = None,
    discovered_endpoints: list[str] | None = None,
    enrich_spec: bool = False,
) -> list[FunctionAuthzFinding]:
    if not isinstance(spec, dict) or not spec:
        return []

    try:
        version = detect_spec_version(spec)
        logger.debug("Analyzing OpenAPI spec version: %s", version)
    except ValueError as exc:
        logger.warning("OpenAPI spec version detection failed: %s", exc)

    paths = _get_paths(spec)
    if not paths:
        return []

    all_findings: list[FunctionAuthzFinding] = []

    try:
        all_findings.extend(AdminPathExposureRule.analyze_openapi(spec))
    except Exception as exc:
        logger.warning("BF-004 OpenAPI analysis failed: %s", exc)

    try:
        all_findings.extend(ShadowAdminFunctionRule.analyze_openapi(spec))
    except Exception as exc:
        logger.warning("BF-006 OpenAPI analysis failed: %s", exc)

    from src.core.broken_function_level_authorization.rules.privileged_endpoint_no_role_check import (
        is_privileged_path,
        normalize_path,
    )
    from src.core.broken_function_level_authorization.rules.shadow_admin_function import (
        is_shadow_path,
    )

    global_security = spec.get("security") or []

    # Signal 1: Privileged endpoint without security scheme (BF-001)
    for path_str, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method in path_item:
            if method.lower() not in (
                "get",
                "post",
                "put",
                "delete",
                "patch",
                "options",
                "head",
                "trace",
            ):
                continue

            if is_privileged_path(path_str, method.upper()):
                op = path_item[method]
                if not isinstance(op, dict):
                    continue
                op_security = op.get("security")
                has_security = False
                if op_security is not None:
                    if isinstance(op_security, list) and len(op_security) > 0:
                        has_security = True
                elif global_security:
                    if isinstance(global_security, list) and len(global_security) > 0:
                        has_security = True

                if not has_security:
                    all_findings.append(
                        FunctionAuthzFinding(
                            rule_id="BF-001",
                            cwe_id="CWE-285",
                            category="privileged_endpoint_no_role_check",
                            severity="CRITICAL",
                            file_path="openapi_spec",
                            line_number=None,
                            endpoint=f"{method.upper()} {path_str}",
                            http_methods=[method.upper()],
                            required_role="admin",
                            found_guard=None,
                            missing_guard="No security scheme on privileged endpoint",
                            evidence=f"{method.upper()} {path_str}",
                            confidence=0.95,
                            layer="openapi",
                        )
                    )

    # Signal 2: HTTP methods not restricted in code (BF-003 correlation)
    if ast_findings is not None:
        bf003_ast_findings = [f for f in ast_findings if f.rule_id == "BF-003"]
        for path_str, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method in path_item:
                if method.lower() not in (
                    "get",
                    "post",
                    "put",
                    "delete",
                    "patch",
                    "options",
                    "head",
                    "trace",
                ):
                    continue

                matched_ast_finding = None
                for ast_f in bf003_ast_findings:
                    ast_path = ast_f.endpoint.split(" ")[-1] if ast_f.endpoint else ""
                    if normalize_path(path_str) == normalize_path(ast_path):
                        matched_ast_finding = ast_f
                        break

                if matched_ast_finding is not None:
                    all_findings.append(
                        FunctionAuthzFinding(
                            rule_id="BF-003",
                            cwe_id="CWE-650",
                            category="http_method_override",
                            severity="HIGH",
                            file_path="openapi_spec",
                            line_number=None,
                            endpoint=f"{method.upper()} {path_str}",
                            http_methods=[method.upper()],
                            required_role="admin",
                            found_guard=None,
                            missing_guard="HTTP methods not restricted in code",
                            evidence=f"Spec defines {method.upper()} {path_str} but code does not restrict methods (confirmed by AST finding)",
                            confidence=0.90,
                            layer="ast+openapi",
                        )
                    )

    # Signal 3: Shadow endpoint detection (BF-006)
    if discovered_endpoints is not None:
        spec_paths_normalized = {normalize_path(p) for p in paths}
        for discovered_path in discovered_endpoints:
            norm_discovered = normalize_path(discovered_path)
            if norm_discovered not in spec_paths_normalized:
                if is_shadow_path(discovered_path):
                    all_findings.append(
                        FunctionAuthzFinding(
                            rule_id="BF-006",
                            cwe_id="CWE-285",
                            category="shadow_admin_function",
                            severity="HIGH",
                            file_path="openapi_spec",
                            line_number=None,
                            endpoint=f"GET {discovered_path}",
                            http_methods=["GET"],
                            required_role="admin",
                            found_guard=None,
                            missing_guard="Shadow admin / debug endpoint exposed in production without role check",
                            evidence=f"endpoint presente nel codice ma assente dalla spec: {discovered_path}",
                            confidence=0.95,
                            layer="openapi",
                        )
                    )

    if enrich_spec:
        try:
            _enrich_spec(spec, paths, all_findings)
        except Exception as exc:
            logger.warning("Spec enrichment failed: %s", exc)

    return all_findings
