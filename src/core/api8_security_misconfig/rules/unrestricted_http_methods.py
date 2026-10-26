import ast
import re
from pathlib import Path

from src.core.api8_security_misconfig.models import MisconfigFinding

MUTATING_KEYWORDS = {
    "delete",
    "remove",
    "destroy",
    "update",
    "modify",
    "create",
    "add",
    "insert",
    "transfer",
    "upload",
    "reset",
    "change",
}

ALL_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}


def analyze(tree: ast.AST | None, file_path: Path, content: str) -> list[MisconfigFinding]:
    """
    Regola SC-008 (CWE-650 / CWE-749):
    Rileva endpoint e route API con restrizioni insufficienti sui metodi HTTP ammessi:
    - Route mutanti (delete, create, update, transfer) accessibili tramite GET implicito senza restrizione methods=['POST'|'DELETE'|'PUT']
    - Handler configurati con tutti i verbi HTTP contemporaneamente (catch-all o lista eccessiva >= 5 verbi)
    - Express.js app.all() su percorsi specifici
    """
    path_parts = {p.lower() for p in file_path.parts}
    if path_parts & {"test", "tests", "testing", "fixtures", "mock"}:
        if not ("vulnerable_app" in path_parts or "secure_app" in path_parts):
            return []

    findings: list[MisconfigFinding] = []

    # Controllo JS/TS per Express app.all / router.all
    if file_path.suffix in (".js", ".ts"):
        lines = content.splitlines()
        for idx, line in enumerate(lines, 1):
            if re.search(r"\b(app|router)\.all\s*\(", line):
                findings.append(
                    MisconfigFinding(
                        rule_id="SC-008",
                        cwe_id="CWE-650",
                        category="unrestricted_http_methods",
                        severity="MEDIUM",
                        file_path=str(file_path),
                        line_number=idx,
                        evidence=line.strip(),
                        missing_guard="Replace .all() with specific HTTP method handlers (e.g. .get(), .post())",
                        confidence=0.85,
                        layer="ast",
                    )
                )
        return findings

    if tree is None:
        return findings

    class MethodVisitor(ast.NodeVisitor):
        def __init__(self):
            self.findings = []

        def visit_FunctionDef(self, node: ast.FunctionDef):
            for decorator in node.decorator_list:
                # Verifica decoratori tipo @app.route(...) o @bp.route(...)
                if isinstance(decorator, ast.Call):
                    is_route = False
                    if (
                        isinstance(decorator.func, ast.Attribute) and decorator.func.attr == "route"
                    ) or (isinstance(decorator.func, ast.Name) and decorator.func.id == "route"):
                        is_route = True

                    is_api_route = False
                    if (
                        isinstance(decorator.func, ast.Attribute)
                        and decorator.func.attr == "api_route"
                    ):
                        is_api_route = True

                    if is_route or is_api_route:
                        self._check_route(node, decorator)

            self.generic_visit(node)

        def _check_route(self, func_node: ast.FunctionDef, dec_call: ast.Call):
            route_path = ""
            if (
                dec_call.args
                and isinstance(dec_call.args[0], ast.Constant)
                and isinstance(dec_call.args[0].value, str)
            ):
                route_path = dec_call.args[0].value.lower()

            methods_arg = None
            for kw in dec_call.keywords:
                if kw.arg == "methods":
                    methods_arg = kw.value

            # Caso 1: methods non specificato -> default GET su operazione mutante
            if methods_arg is None:
                path_words = set(re.findall(r"[a-z0-9]+", route_path))
                func_words = set(re.findall(r"[a-z0-9]+", func_node.name.lower()))
                all_words = path_words | func_words

                matched_mutating = all_words & MUTATING_KEYWORDS
                if matched_mutating:
                    keyword_found = next(iter(matched_mutating))
                    evidence = (
                        ast.get_source_segment(content, dec_call) or f"@app.route('{route_path}')"
                    )
                    self.findings.append(
                        MisconfigFinding(
                            rule_id="SC-008",
                            cwe_id="CWE-650",
                            category="unrestricted_http_methods",
                            severity="HIGH",
                            file_path=str(file_path),
                            line_number=dec_call.lineno,
                            evidence=f"State-changing route '{route_path}' (keyword '{keyword_found}') lacks explicit methods parameter, defaulting to GET",
                            missing_guard="Add explicit methods=['POST'] or methods=['DELETE'] to prevent state changes via GET",
                            confidence=0.85,
                            layer="ast",
                        )
                    )

            # Caso 2: methods contiene troppi verbi (catch-all >= 5 verbi contemporaneamente)
            elif isinstance(methods_arg, (ast.List, ast.Tuple, ast.Set)):
                specified_methods = []
                for elt in methods_arg.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        specified_methods.append(elt.value.upper())

                if len(specified_methods) >= 5 or set(specified_methods) == ALL_METHODS:
                    evidence = (
                        ast.get_source_segment(content, dec_call) or f"methods={specified_methods}"
                    )
                    self.findings.append(
                        MisconfigFinding(
                            rule_id="SC-008",
                            cwe_id="CWE-650",
                            category="unrestricted_http_methods",
                            severity="MEDIUM",
                            file_path=str(file_path),
                            line_number=dec_call.lineno,
                            evidence=f"Overly permissive HTTP methods allowed on route '{route_path}': {specified_methods} ({evidence})",
                            missing_guard="Restrict allowed methods to only the specific verbs required by functional specifications",
                            confidence=0.90,
                            layer="ast",
                        )
                    )

    visitor = MethodVisitor()
    visitor.visit(tree)
    findings.extend(visitor.findings)
    return findings
