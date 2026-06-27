import ast
from pathlib import Path
from typing import List
from src.core.api8_security_misconfiguration.models import MisconfigFinding

def analyze(tree: ast.AST | None, file_path: Path, content: str) -> List[MisconfigFinding]:
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
                
                if body_visitor.is_verbose:
                    evidence_line = ast.get_source_segment(content, node) or f"def {node.name}({exc_var_name}):"
                    evidence = evidence_line.strip().splitlines()[0]
                    self.findings.append(MisconfigFinding(
                        rule_id="SC-003",
                        cwe_id="CWE-209",
                        category="verbose_error_handler",
                        severity="HIGH",
                        file_path=str(file_path),
                        line_number=node.lineno,
                        evidence=evidence,
                        missing_guard="Sanitize error messages before returning to user",
                        confidence=0.90,
                        layer="ast"
                    ))
            self.generic_visit(node)

    class VerboseBodyVisitor(ast.NodeVisitor):
        def __init__(self, exc_var: str):
            self.exc_var = exc_var
            self.is_verbose = False

        def visit_Call(self, node: ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in ("format_exc", "print_exc"):
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == "traceback":
                        self.is_verbose = True
            
            if isinstance(node.func, ast.Name) and node.func.id == "repr":
                if node.args and isinstance(node.args[0], ast.Name) and node.args[0].id == self.exc_var:
                    self.is_verbose = True

            if isinstance(node.func, ast.Name) and node.func.id == "str":
                if node.args and isinstance(node.args[0], ast.Name) and node.args[0].id == self.exc_var:
                    self.is_verbose = True

            self.generic_visit(node)

        def visit_JoinedStr(self, node: ast.JoinedStr):
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    if isinstance(val.value, ast.Name) and val.value.id == self.exc_var:
                        self.is_verbose = True
            self.generic_visit(node)

    visitor = ErrorHandlerVisitor()
    visitor.visit(tree)
    findings.extend(visitor.findings)
    return findings
