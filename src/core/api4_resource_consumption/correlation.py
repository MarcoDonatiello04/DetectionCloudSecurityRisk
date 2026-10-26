"""
Cross-layer correlation for API4:2023 Unrestricted Resource Consumption.

The three layers look at the same missing defense from different places: the
code that should enforce it, the configuration that may enforce it in front of
the code, and the contract that should declare it. This module turns their
side-by-side findings into judgements:

  corroborated — code and contract show the same defect on the same endpoint
                 (RC-001↔RC-010, RC-002↔RC-011, RC-005↔RC-013, RC-006↔RC-012):
                 the findings are linked and their confidence is raised.
  compensated  — the defense missing in code or contract is enforced by the
                 configuration (an upload without size check behind a request
                 body limit): the finding is kept for traceability but lowered
                 to INFO, citing the defense.
  derived      — the code proves what the contract can only guess: a route
                 whose handler calls a paid SDK (RC-006) is expensive whatever
                 its name, so an unprotected contract operation gets RC-012.

Code findings are tied to endpoints by locating the route that encloses them
(Flask/FastAPI decorators, Express-style calls) and normalizing both paths
with APIEndpointNormalizer.

Entry point: correlate(findings, target_path, openapi_spec) -> list[dict]
"""

from __future__ import annotations

import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from src.core.api4_resource_consumption.layers.layer2_config import (
    collect_body_size_defenses,
)
from src.core.api4_resource_consumption.layers.layer3_openapi import (
    _get_global_security,
    _has_documented_protection,
    _iter_operations,
    _make_finding,
)
from src.core.api4_resource_consumption.models import ResourceConsumptionFinding
from src.normalization.normalizer import APIEndpointNormalizer

logger = logging.getLogger(__name__)

# Code rule -> contract rule describing the same missing defense
CORRESPONDING_RULES: dict[str, str] = {
    "RC-001": "RC-010",  # pagination without cap
    "RC-002": "RC-011",  # upload without size limit
    "RC-005": "RC-013",  # unbounded user-supplied collection
    "RC-006": "RC-012",  # costly call without throttling
}

# Rules whose missing defense is a request size limit, enforceable by the config
BODY_SIZE_RULES = {"RC-002", "RC-011"}

CORROBORATION_CONFIDENCE_BONUS = 0.1
DERIVED_CONFIDENCE = 0.9

_PY_DEF = re.compile(r"^(\s*)(?:async\s+)?def\s+\w+")
_PY_ROUTE = re.compile(
    r"^\s*@\w+(?:\.\w+)*\.(route|get|post|put|patch|delete)\(\s*[rf]?[\"']([^\"']+)[\"']"
    r"(?:.*methods\s*=\s*[\[(]([^\])]*)[\])])?"
)
_JS_ROUTE = re.compile(
    r"\b\w+\.(get|post|put|patch|delete|all)\(\s*[\"'`]([^\"'`]+)[\"'`]", re.IGNORECASE
)
_ALL_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})


# ---------------------------------------------------------------------------
# Route resolution for code findings
# ---------------------------------------------------------------------------


@lru_cache(maxsize=256)
def _read_lines(file_path: str) -> tuple[str, ...]:
    try:
        return tuple(Path(file_path).read_text(encoding="utf-8", errors="replace").splitlines())
    except OSError:
        return ()


def _python_route(lines: tuple[str, ...], index: int) -> tuple[frozenset[str], str] | None:
    """
    Route of the handler enclosing lines[index]: walks outwards through the
    enclosing functions (nested helpers included) and reads their decorators.
    """
    line = lines[index]
    indent = len(line) - len(line.lstrip())
    for i in range(index, -1, -1):
        m = _PY_DEF.match(lines[i])
        if not m or (i != index and len(m.group(1)) >= indent):
            continue
        indent = len(m.group(1))
        j = i - 1
        while j >= 0 and lines[j].strip().startswith(("@", ")")):
            route = _PY_ROUTE.match(lines[j])
            if route:
                kind, path, methods = route.group(1).upper(), route.group(2), route.group(3)
                if kind != "ROUTE":
                    return frozenset({kind}), path
                declared = re.findall(r"[\"'](\w+)[\"']", methods or "")
                return frozenset(x.upper() for x in declared) or frozenset({"GET"}), path
            j -= 1
        if indent == 0:
            return None
    return None


def _js_route(lines: tuple[str, ...], index: int) -> tuple[frozenset[str], str] | None:
    """Nearest Express-style route declaration at or above lines[index]."""
    for i in range(index, -1, -1):
        m = _JS_ROUTE.search(lines[i])
        if m:
            method = m.group(1).upper()
            return (_ALL_METHODS if method == "ALL" else frozenset({method})), m.group(2)
    return None


def resolve_route(file_path: str, line_number: int | None) -> tuple[frozenset[str], str] | None:
    """(methods, path) of the route handler containing file_path:line_number, if any."""
    if not line_number:
        return None
    lines = _read_lines(file_path)
    if not lines or line_number > len(lines):
        return None
    index = line_number - 1
    if file_path.endswith(".py"):
        return _python_route(lines, index)
    if file_path.endswith((".js", ".ts", ".mjs", ".cjs")):
        return _js_route(lines, index)
    return None


def _norm(path: str) -> str:
    return APIEndpointNormalizer.normalize_path(path)


def _same_path(code_path: str, contract_path: str) -> bool:
    """Equal after normalization, or one is the other plus a mount prefix."""
    a, b = _norm(code_path), _norm(contract_path)
    return a == b or a.endswith(b) or b.endswith(a)


def _split_endpoint(endpoint: str) -> tuple[str, str]:
    method, _, path = endpoint.partition(" ")
    return method.upper(), path


# ---------------------------------------------------------------------------
# Correlation steps
# ---------------------------------------------------------------------------


def _link(a: ResourceConsumptionFinding, b: ResourceConsumptionFinding) -> None:
    for x, y in ((a, b), (b, a)):
        x.correlation = x.correlation or "corroborated"
        if y.key not in x.correlated_with:
            x.correlated_with.append(y.key)
    boosted = min(1.0, max(a.confidence, b.confidence) + CORROBORATION_CONFIDENCE_BONUS)
    a.confidence = b.confidence = round(boosted, 2)


def _parameters_match(code: ResourceConsumptionFinding, contract: ResourceConsumptionFinding):
    if code.rule_id != "RC-001" or not code.parameter or not contract.parameter:
        return True
    return code.parameter.lower() == contract.parameter.lower()


def _corroborate(
    code_findings: list[tuple[ResourceConsumptionFinding, frozenset[str], str]],
    contract_findings: list[ResourceConsumptionFinding],
) -> list[dict]:
    links: list[dict] = []
    for code, methods, route_path in code_findings:
        expected = CORRESPONDING_RULES.get(code.rule_id)
        for contract in contract_findings:
            if contract.rule_id != expected or not contract.endpoint:
                continue
            method, path = _split_endpoint(contract.endpoint)
            if method not in methods or not _same_path(route_path, path):
                continue
            if not _parameters_match(code, contract):
                continue
            _link(code, contract)
            links.append(
                {
                    "type": "corroborated",
                    "endpoint": contract.endpoint,
                    "findings": [code.key, contract.key],
                    "note": (
                        f"{code.rule_id} (code) and {contract.rule_id} (contract) report the "
                        f"same missing defense on {contract.endpoint}"
                    ),
                }
            )
    return links


def _compensate(findings: list[ResourceConsumptionFinding], defenses: list[str]) -> list[dict]:
    if not defenses:
        return []
    links: list[dict] = []
    for f in findings:
        if f.rule_id not in BODY_SIZE_RULES or f.correlation == "compensated":
            continue
        f.original_severity = f.severity
        f.severity = "INFO"
        f.correlation = "compensated"
        f.compensated_by = defenses[0]
        links.append(
            {
                "type": "compensated",
                "endpoint": f.endpoint,
                "findings": [f.key],
                "note": f"request body size enforced by configuration: {'; '.join(defenses)}",
            }
        )
    return links


def _derive_expensive_endpoints(
    code_findings: list[tuple[ResourceConsumptionFinding, frozenset[str], str]],
    contract_findings: list[ResourceConsumptionFinding],
    openapi_spec: dict[str, Any],
) -> tuple[list[ResourceConsumptionFinding], list[dict]]:
    """RC-006 in code proves the cost: flag the matching unprotected contract operation."""
    already = {f.endpoint for f in contract_findings if f.rule_id == "RC-012"}
    global_security = _get_global_security(openapi_spec)
    derived: list[ResourceConsumptionFinding] = []
    links: list[dict] = []

    for code, methods, route_path in code_findings:
        if code.rule_id != "RC-006":
            continue
        for path, method, operation in _iter_operations(openapi_spec.get("paths") or {}):
            endpoint = f"{method} {path}"
            if method not in methods or not _same_path(route_path, path) or endpoint in already:
                continue
            if _has_documented_protection(operation, global_security):
                continue
            finding = _make_finding(
                rule_id="RC-012",
                cwe_id="CWE-770",
                category="openapi_expensive_endpoint_unprotected",
                severity="HIGH",
                file_path="openapi_spec",
                line_number=None,
                endpoint=endpoint,
                parameter=None,
                evidence=(
                    f"{endpoint} — handler calls a paid service ({code.file_path}:"
                    f"{code.line_number}) without security or rate-limit documentation"
                ),
                missing_guard=(
                    "Add security: [{scheme: []}] or x-rate-limit extension "
                    "or document throttling in description"
                ),
                confidence=DERIVED_CONFIDENCE,
            )
            finding.correlation = "derived"
            finding.correlated_with.append(code.key)
            code.correlation = code.correlation or "corroborated"
            code.correlated_with.append(finding.key)
            already.add(endpoint)
            derived.append(finding)
            links.append(
                {
                    "type": "derived",
                    "endpoint": endpoint,
                    "findings": [code.key, finding.key],
                    "note": f"cost proven by code ({code.rule_id}), not inferred from the name",
                }
            )
    return derived, links


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def correlate(
    findings: list[ResourceConsumptionFinding],
    target_path: str,
    openapi_spec: dict[str, Any] | None = None,
) -> list[dict]:
    """
    Correlates the findings of the three layers in place and returns the list of
    cross-layer links. May append derived findings to `findings`.
    """
    code_findings: list[tuple[ResourceConsumptionFinding, frozenset[str], str]] = []
    for f in findings:
        if f.layer != "ast":
            continue
        route = resolve_route(f.file_path, f.line_number)
        if route is None:
            continue
        methods, path = route
        if f.endpoint is None:
            f.endpoint = f"{'|'.join(sorted(methods))} {path}"
        code_findings.append((f, methods, path))

    contract_findings = [f for f in findings if f.layer == "openapi"]
    links = _corroborate(code_findings, contract_findings)

    if openapi_spec:
        derived, derived_links = _derive_expensive_endpoints(
            code_findings, contract_findings, openapi_spec
        )
        findings.extend(derived)
        links.extend(derived_links)

    try:
        defenses = collect_body_size_defenses(target_path)
    except Exception as exc:  # correlation must never break the scan
        logger.warning("Body size defense collection failed: %s", exc)
        defenses = []
    links.extend(_compensate(findings, defenses))
    return links
