import ast
import re
from pathlib import Path

from src.core.api8_security_misconfig.models import MisconfigFinding

SENSITIVE_ROUTE_KEYWORDS = {
    "user",
    "users",
    "profile",
    "me",
    "account",
    "message",
    "messages",
    "dm",
    "conversation",
    "chat",
    "order",
    "orders",
    "billing",
    "payment",
    "payments",
    "invoice",
    "token",
    "auth",
    "secret",
    "private",
}


def _has_global_cache_control(target_path: Path) -> bool:
    """Verifica se l'applicazione imposta un middleware o hook globale di no-cache nel codice attivo (non nei commenti)."""
    skip_dirs = {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        "dist",
        "build",
    }
    for p in target_path.rglob("*"):
        if any(part in skip_dirs for part in p.parts):
            continue
        if p.is_file() and p.suffix in (".py", ".js", ".ts"):
            if "test/" in p.as_posix() or "tests/" in p.as_posix():
                continue
            try:
                content = p.read_text(errors="replace")
                for line in content.splitlines():
                    clean_line = line.split("#")[0].strip()
                    if not clean_line:
                        continue
                    if "no-store" in clean_line.lower() and (
                        "cache-control" in clean_line.lower() or "headers" in clean_line.lower()
                    ):
                        return True
            except Exception:
                continue
    return False


def analyze(
    tree: ast.AST | None, file_path: Path, content: str, target_dir: Path | None = None
) -> list[MisconfigFinding]:
    """
    Regola SC-009 (CWE-525 / CWE-524):
    Rileva endpoint che gestiscono dati privati o sensibili (es. messaggi privati,
    profili, ordini, token) ma non impostano l'header di risposta 'Cache-Control: no-store'.
    Risponde direttamente allo Scenario #2 di OWASP API8:2023.
    """
    path_parts = {p.lower() for p in file_path.parts}
    if path_parts & {"test", "tests", "testing", "fixtures", "mock"}:
        if not ("vulnerable_app" in path_parts or "secure_app" in path_parts):
            return []

    if tree is None:
        return []

    # Se la directory target ha un hook globale di no-cache nel codice, nessun finding
    if target_dir and target_dir.is_dir() and _has_global_cache_control(target_dir):
        return []

    findings: list[MisconfigFinding] = []

    class SensitiveRouteVisitor(ast.NodeVisitor):
        def __init__(self):
            self.findings = []

        def visit_FunctionDef(self, node: ast.FunctionDef):
            route_decorator = None
            route_path = ""

            for dec in node.decorator_list:
                if isinstance(dec, ast.Call):
                    is_route = False
                    if (
                        isinstance(dec.func, ast.Attribute)
                        and dec.func.attr in ("route", "get", "post", "api_route")
                    ) or (
                        isinstance(dec.func, ast.Name) and dec.func.id in ("route", "get", "post")
                    ):
                        is_route = True

                    if is_route:
                        route_decorator = dec
                        if (
                            dec.args
                            and isinstance(dec.args[0], ast.Constant)
                            and isinstance(dec.args[0].value, str)
                        ):
                            route_path = dec.args[0].value.lower()
                        break

            if route_decorator and route_path:
                path_words = set(re.findall(r"[a-z0-9]+", route_path))
                func_words = set(re.findall(r"[a-z0-9]+", node.name.lower()))
                all_words = path_words | func_words

                matched_sensitive = all_words & SENSITIVE_ROUTE_KEYWORDS
                if matched_sensitive:
                    # Controlla se il corpo della funzione imposta Cache-Control nel codice attivo (escludendo commenti)
                    func_source = ast.get_source_segment(content, node) or ""
                    code_lines = [
                        line_item.split("#")[0].strip() for line_item in func_source.splitlines()
                    ]
                    code_clean = "\n".join(code_lines).lower()

                    has_cache_control = "no-store" in code_clean or (
                        "cache-control" in code_clean and "no-cache" in code_clean
                    )

                    if not has_cache_control:
                        keyword = next(iter(matched_sensitive))
                        evidence = f"Sensitive route '{route_path}' (sensitive keyword '{keyword}') does not set Cache-Control: no-store"
                        self.findings.append(
                            MisconfigFinding(
                                rule_id="SC-009",
                                cwe_id="CWE-525",
                                category="missing_cache_control",
                                severity="HIGH",
                                file_path=str(file_path),
                                line_number=route_decorator.lineno,
                                evidence=evidence,
                                missing_guard=(
                                    "Set response header 'Cache-Control': 'no-store, no-cache, must-revalidate, private' "
                                    "or configure a global @app.after_request hook to prevent caching of private data (OWASP API8 Scenario #2)"
                                ),
                                confidence=0.85,
                                layer="ast",
                            )
                        )

            self.generic_visit(node)

    visitor = SensitiveRouteVisitor()
    visitor.visit(tree)
    findings.extend(visitor.findings)
    return findings
