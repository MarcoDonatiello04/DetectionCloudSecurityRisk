import ast
from pathlib import Path

from src.core.api7_security_misconfig.models import MisconfigFinding


def analyze(tree: ast.AST | None, file_path: Path, content: str) -> list[MisconfigFinding]:
    findings = []
    if tree is None:
        return findings

    class ErrorHandlerVisitor(ast.NodeVisitor):
        def __init__(self):
            self.findings = []

        def visit_FunctionDef(self, node: ast.FunctionDef):
            is_errorhandler = False
            for dec in node.decorator_list:
                if isinstance(dec, ast.Call):
                    if isinstance(dec.func, ast.Attribute) and dec.func.attr == "errorhandler":
                        is_errorhandler = True
                elif isinstance(dec, ast.Attribute) and dec.attr == "errorhandler":
                    is_errorhandler = True

            if is_errorhandler and node.args.args:
                exc_var_name = node.args.args[0].arg

                body_visitor = VerboseBodyVisitor(exc_var_name)
                body_visitor.visit(node)

                if body_visitor.leaks:
                    body_visitor.leaks.sort(key=lambda x: x[0])
                    _priority, leak_line, _leak_node = body_visitor.leaks[0]

                    content_lines = content.splitlines()
                    if 1 <= leak_line <= len(content_lines):
                        evidence = content_lines[leak_line - 1].strip()
                    else:
                        evidence = f"def {node.name}({exc_var_name}):"

                    self.findings.append(
                        MisconfigFinding(
                            rule_id="SC-003",
                            cwe_id="CWE-209",
                            category="verbose_error_handler",
                            severity="HIGH",
                            file_path=str(file_path),
                            line_number=leak_line,
                            evidence=evidence,
                            missing_guard="Sanitize error messages before returning to user",
                            confidence=0.90,
                            layer="ast",
                        )
                    )
            self.generic_visit(node)

    class VerboseBodyVisitor(ast.NodeVisitor):
        def __init__(self, exc_var: str):
            self.exc_var = exc_var
            self.leaks = []

        def visit_Call(self, node: ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in ("format_exc", "print_exc"):
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == "traceback":
                        self.leaks.append((1, node.lineno, node))

            if (
                isinstance(node.func, ast.Name)
                and node.func.id == "repr"
                and (
                    node.args
                    and isinstance(node.args[0], ast.Name)
                    and node.args[0].id == self.exc_var
                )
            ):
                self.leaks.append((2, node.lineno, node))

            if (
                isinstance(node.func, ast.Name)
                and node.func.id == "str"
                and (
                    node.args
                    and isinstance(node.args[0], ast.Name)
                    and node.args[0].id == self.exc_var
                )
            ):
                self.leaks.append((3, node.lineno, node))

            self.generic_visit(node)

        def visit_JoinedStr(self, node: ast.JoinedStr):
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    if isinstance(val.value, ast.Name) and val.value.id == self.exc_var:
                        self.leaks.append((3, node.lineno, node))
            self.generic_visit(node)

    visitor = ErrorHandlerVisitor()
    visitor.visit(tree)
    findings.extend(visitor.findings)
    return findings
