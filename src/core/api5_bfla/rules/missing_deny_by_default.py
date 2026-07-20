import ast
import re
from pathlib import Path

from src.core.api5_bfla.models import FunctionAuthzFinding


# Helper to check if a Django settings file has DEFAULT_PERMISSION_CLASSES
def _parse_django_settings(file_path: Path, content: str) -> list[FunctionAuthzFinding]:
    findings = []
    try:
        tree = ast.parse(content, filename=str(file_path))
    except SyntaxError:
        return findings

    # Look for REST_FRAMEWORK assignment
    rf_dict = None
    rf_line = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "REST_FRAMEWORK":
                    if isinstance(node.value, ast.Dict):
                        rf_dict = node.value
                        rf_line = node.lineno
                        break

    if rf_dict:
        # Check keys inside REST_FRAMEWORK dict
        has_default_perms = False
        is_allow_any = False
        for k, v in zip(rf_dict.keys, rf_dict.values, strict=False):
            if isinstance(k, ast.Constant) and k.value == "DEFAULT_PERMISSION_CLASSES":
                has_default_perms = True
                # Check if it has AllowAny
                val_repr = ast.unparse(v) if hasattr(ast, "unparse") else ""
                if "AllowAny" in val_repr or (
                    isinstance(v, (ast.List, ast.Tuple, ast.Set)) and not v.elts
                ):
                    is_allow_any = True

        if not has_default_perms or is_allow_any:
            present_keys = []
            for k in rf_dict.keys:
                if isinstance(k, ast.Constant):
                    present_keys.append(k.value)
                elif isinstance(k, ast.Str):
                    present_keys.append(k.s)
            keys_str = ", ".join(f"'{pk}'" for pk in present_keys) if present_keys else "empty"
            evidence_str = f"REST_FRAMEWORK has {{{keys_str}}} but is missing 'DEFAULT_PERMISSION_CLASSES' — defaults to AllowAny"

            findings.append(
                FunctionAuthzFinding(
                    rule_id=MissingDenyByDefaultRule.rule_id,
                    cwe_id=MissingDenyByDefaultRule.cwe_id,
                    category=MissingDenyByDefaultRule.category,
                    severity=MissingDenyByDefaultRule.severity,
                    file_path=str(file_path),
                    line_number=rf_line,
                    endpoint=None,
                    http_methods=[],
                    required_role=None,
                    found_guard="REST_FRAMEWORK configuration",
                    missing_guard="Add DEFAULT_PERMISSION_CLASSES: ['rest_framework.permissions.IsAuthenticated']",
                    evidence=evidence_str,
                    confidence=0.95,
                    layer="config",
                )
            )

    return findings


# Helper to check FastAPI instantiation for global dependencies
def _parse_fastapi_app(file_path: Path, content: str) -> list[FunctionAuthzFinding]:
    findings = []
    if "FastAPI(" not in content:
        return findings

    try:
        tree = ast.parse(content, filename=str(file_path))
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = ast.unparse(node.func) if hasattr(ast, "unparse") else ""
            if "FastAPI" in func_name:
                has_deps = False
                for kw in node.keywords:
                    if kw.arg == "dependencies":
                        has_deps = True
                        break
                if not has_deps:
                    findings.append(
                        FunctionAuthzFinding(
                            rule_id=MissingDenyByDefaultRule.rule_id,
                            cwe_id=MissingDenyByDefaultRule.cwe_id,
                            category=MissingDenyByDefaultRule.category,
                            severity="MEDIUM",
                            file_path=str(file_path),
                            line_number=node.lineno,
                            endpoint=None,
                            http_methods=[],
                            required_role=None,
                            found_guard=None,
                            missing_guard="Add dependencies=[Depends(get_current_user)] to FastAPI() constructor",
                            evidence=f"FastAPI() initialized at line {node.lineno} without global dependencies= — all endpoints unprotected by default",
                            confidence=0.65,
                            layer="config",
                        )
                    )
    return findings


# Helper to check Express files for global auth middleware
def _parse_express_app(file_path: Path, content: str) -> list[FunctionAuthzFinding]:
    findings = []
    if "express(" not in content.lower():
        return findings

    # Check if app.use(authMiddleware) is called
    # We can perform a regex-based sequential check or line parsing
    lines = content.splitlines()
    has_auth_mw = False
    first_router_line = None

    use_pattern = re.compile(r"\bapp\.use\s*\(([^)]+)\)")
    auth_kw = {"auth", "jwt", "passport", "login", "session", "secure"}

    for idx, line in enumerate(lines, start=1):
        if "app.use" in line:
            m = use_pattern.search(line)
            if m:
                arg_text = m.group(1).lower()
                if any(kw in arg_text for kw in auth_kw):
                    has_auth_mw = True
                if "router" in arg_text or "routes" in arg_text:
                    if first_router_line is None:
                        first_router_line = idx

    use_line_content = "app.use()"
    use_line_num = 1
    for idx, line in enumerate(lines, start=1):
        if "app.use" in line:
            use_line_content = line.strip()
            use_line_num = idx
            break

    if not has_auth_mw:
        findings.append(
            FunctionAuthzFinding(
                rule_id=MissingDenyByDefaultRule.rule_id,
                cwe_id=MissingDenyByDefaultRule.cwe_id,
                category=MissingDenyByDefaultRule.category,
                severity="MEDIUM",
                file_path=str(file_path),
                line_number=first_router_line or use_line_num or 1,
                endpoint=None,
                http_methods=[],
                required_role=None,
                found_guard=None,
                missing_guard="Add app.use(authMiddleware) before app.use(router)",
                evidence=f"{use_line_content} at line {use_line_num} — no auth middleware registered before route mounting",
                confidence=0.75,
                layer="config",
            )
        )
    return findings


class MissingDenyByDefaultRule:
    rule_id = "BF-005"
    cwe_id = "CWE-276"
    category = "missing_deny_by_default"
    severity = "MEDIUM"

    @staticmethod
    def analyze_config(file_path: Path) -> list[FunctionAuthzFinding]:
        findings = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings

        name = file_path.name.lower()
        if name == "settings.py":
            findings.extend(_parse_django_settings(file_path, content))
        elif name in ("app.py", "main.py"):
            findings.extend(_parse_fastapi_app(file_path, content))
        elif name in ("app.js", "server.js", "index.js"):
            findings.extend(_parse_express_app(file_path, content))

        return findings
