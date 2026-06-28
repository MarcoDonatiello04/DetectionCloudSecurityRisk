from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from tree_sitter import Language, Parser

import tree_sitter_python as tspython
import tree_sitter_javascript as tsjavascript

from src.core.broken_function_level_authorization.models import FunctionAuthzFinding
from src.core.broken_function_level_authorization.rules.privileged_endpoint_no_role_check import PrivilegedEndpointNoRoleCheckRule
from src.core.broken_function_level_authorization.rules.auth_without_authz import AuthWithoutAuthzRule
from src.core.broken_function_level_authorization.rules.http_method_override import HTTPMethodOverrideRule
from src.core.broken_function_level_authorization.rules.admin_path_exposure import AdminPathExposureRule
from src.core.broken_function_level_authorization.rules.shadow_admin_function import ShadowAdminFunctionRule

logger = logging.getLogger(__name__)

_PY_LANGUAGE: Optional[Language] = None
_JS_LANGUAGE: Optional[Language] = None


def _get_python_language() -> Optional[Language]:
    global _PY_LANGUAGE
    if _PY_LANGUAGE is None:
        try:
            _PY_LANGUAGE = Language(tspython.language())
        except Exception as exc:
            logger.warning("tree-sitter Python grammar unavailable: %s", exc)
    return _PY_LANGUAGE


def _get_javascript_language() -> Optional[Language]:
    global _JS_LANGUAGE
    if _JS_LANGUAGE is None:
        try:
            _JS_LANGUAGE = Language(tsjavascript.language())
        except Exception as exc:
            logger.warning("tree-sitter JavaScript grammar unavailable: %s", exc)
    return _JS_LANGUAGE


PYTHON_EXTENSIONS = {".py"}
JS_EXTENSIONS = {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}
SUPPORTED_EXTENSIONS = PYTHON_EXTENSIONS | JS_EXTENSIONS

MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB

SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__",
    ".pytest_cache", "dist", "build", ".mypy_cache", ".tox",
    "site-packages", "egg-info",
}

_PYTHON_RULES = [
    PrivilegedEndpointNoRoleCheckRule.analyze_python,
    AuthWithoutAuthzRule.analyze_python,
    HTTPMethodOverrideRule.analyze_python,
    AdminPathExposureRule.analyze_python,
    ShadowAdminFunctionRule.analyze_python,
]

_JS_RULES = [
    PrivilegedEndpointNoRoleCheckRule.analyze_javascript,
    AuthWithoutAuthzRule.analyze_javascript,
    HTTPMethodOverrideRule.analyze_javascript,
    AdminPathExposureRule.analyze_javascript,
    ShadowAdminFunctionRule.analyze_javascript,
]


def _analyze_file_with_endpoints(file_path: Path) -> tuple[list[FunctionAuthzFinding], list[str]]:
    ext = file_path.suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        return [], []

    try:
        size = file_path.stat().st_size
    except OSError:
        return [], []

    if size > MAX_FILE_SIZE or size == 0:
        return [], []

    try:
        content = file_path.read_bytes()
    except OSError as exc:
        logger.warning("Cannot read %s: %s", file_path, exc)
        return [], []

    if b"\x00" in content[:8192]:
        return [], []

    if ext in PYTHON_EXTENSIONS:
        language = _get_python_language()
        rules = _PYTHON_RULES
    else:
        language = _get_javascript_language()
        rules = _JS_RULES

    if language is None:
        return [], []

    try:
        parser = Parser(language)
        tree = parser.parse(content)
    except Exception as exc:
        logger.warning("Parse error in %s: %s", file_path, exc)
        return [], []

    root = tree.root_node
    findings: list[FunctionAuthzFinding] = []
    str_path = str(file_path)
    for rule_fn in rules:
        try:
            findings.extend(rule_fn(root, str_path))
        except Exception as exc:
            logger.warning("Rule %s failed on %s: %s", rule_fn.__qualname__, file_path, exc)

    endpoints: list[str] = []
    try:
        if ext in PYTHON_EXTENSIONS:
            endpoints = _extract_endpoints_python(root)
        else:
            endpoints = _extract_endpoints_javascript(root)
    except Exception as exc:
        logger.warning("Endpoint extraction failed on %s: %s", file_path, exc)

    return findings, endpoints


def _extract_endpoints_python(root: Node) -> list[str]:
    from src.core.broken_function_level_authorization.rules.admin_path_exposure import _get_blueprint_info
    from src.core.broken_function_level_authorization.rules.privileged_endpoint_no_role_check import (
        _collect_nodes, _parse_python_decorator
    )

    blueprints = _get_blueprint_info(root)
    paths = []
    
    dec_defs = _collect_nodes(root, "decorated_definition")
    for dec_def in dec_defs:
        decorators = [c for c in dec_def.children if c.type == "decorator"]
        func_node = next((c for c in dec_def.children if c.type == "function_definition"), None)
        if not func_node:
            continue
            
        is_route = False
        bp_var_used = None
        route_path = ""
        
        for dec in decorators:
            dec_name, dec_args = _parse_python_decorator(dec)
            dec_name_lower = dec_name.lower()
            
            # Check blueprint or app level
            for bp_var in blueprints:
                if dec_name.startswith(f"{bp_var}."):
                    is_route = True
                    bp_var_used = bp_var
                    if dec_args:
                        route_path = dec_args[0]
                    break
                    
            if not is_route:
                if any(x in dec_name_lower for x in (".route", ".get", ".post", ".put", ".delete", ".patch")):
                    is_route = True
                    if dec_args:
                        route_path = dec_args[0]
                        
        if is_route:
            full_path = ""
            if bp_var_used:
                prefix = blueprints[bp_var_used]
                full_path = prefix + route_path
            else:
                full_path = route_path
            if full_path:
                paths.append(full_path)
                
    return paths


def _extract_endpoints_javascript(root: Node) -> list[str]:
    from src.core.broken_function_level_authorization.rules.privileged_endpoint_no_role_check import (
        _collect_nodes, _node_text
    )
    paths = []
    calls = _collect_nodes(root, "call_expression")
    for call in calls:
        func = call.child_by_field_name("function")
        if not func:
            continue
        func_text = _node_text(func)
        
        is_js_route = any(prefix in func_text for prefix in [
            "app.get", "app.post", "app.put", "app.delete", "app.patch", "app.all",
            "router.get", "router.post", "router.put", "router.delete", "router.patch", "router.all"
        ])
        if not is_js_route:
            continue
            
        args_node = call.child_by_field_name("arguments")
        if not args_node or len(args_node.children) < 3:
            continue
            
        path_node = args_node.children[1]
        if path_node.type != "string":
            continue
        route_path = _node_text(path_node).strip("\"'")
        paths.append(route_path)
    return paths


def _analyze_file(file_path: Path) -> list[FunctionAuthzFinding]:
    findings, _ = _analyze_file_with_endpoints(file_path)
    return findings


def _walk_files(target_path: Path):
    if target_path.is_file():
        yield target_path
        return

    for entry in target_path.rglob("*"):
        if not entry.is_file():
            continue
        if any(part in SKIP_DIRS for part in entry.parts):
            continue
        if entry.suffix.lower() in SUPPORTED_EXTENSIONS:
            yield entry


def _dedup(findings: list[FunctionAuthzFinding]) -> list[FunctionAuthzFinding]:
    seen: dict[tuple, FunctionAuthzFinding] = {}
    for f in findings:
        key = (f.rule_id, f.file_path, f.line_number)
        if key not in seen or f.confidence > seen[key].confidence:
            seen[key] = f
    return list(seen.values())


_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _sort_findings(findings: list[FunctionAuthzFinding]) -> list[FunctionAuthzFinding]:
    return sorted(
        findings,
        key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), -f.confidence, f.file_path, f.line_number or 0),
    )


def analyze_ast(target_path: str) -> list[FunctionAuthzFinding]:
    findings, _ = analyze_ast_with_endpoints(target_path)
    return findings


def analyze_ast_with_endpoints(target_path: str) -> tuple[list[FunctionAuthzFinding], list[str]]:
    root_path = Path(target_path)
    if not root_path.exists():
        logger.error("Target path does not exist: %s", target_path)
        return [], []

    all_findings: list[FunctionAuthzFinding] = []
    discovered_endpoints: list[str] = []

    for file_path in _walk_files(root_path):
        findings, endpoints = _analyze_file_with_endpoints(file_path)
        if findings:
            all_findings.extend(findings)
        if endpoints:
            discovered_endpoints.extend(endpoints)

    deduped = _dedup(all_findings)
    sorted_findings = _sort_findings(deduped)
    
    unique_endpoints = list(dict.fromkeys(discovered_endpoints))
    
    return sorted_findings, unique_endpoints
