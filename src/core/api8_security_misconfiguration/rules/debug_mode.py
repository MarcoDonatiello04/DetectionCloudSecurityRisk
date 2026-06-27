import ast
from pathlib import Path
from typing import List
from src.core.api8_security_misconfiguration.models import MisconfigFinding

def analyze(tree: ast.AST | None, file_path: Path, content: str) -> List[MisconfigFinding]:
    findings = []
    if tree is None:
        return findings

    class DebugModeVisitor(ast.NodeVisitor):
        def __init__(self):
            self.findings = []

        def visit_Call(self, node: ast.Call):
            is_app_run = False
            if isinstance(node.func, ast.Attribute) and node.func.attr == "run":
                is_app_run = True
            
            is_uvicorn_run = False
            if isinstance(node.func, ast.Attribute) and node.func.attr == "run":
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "uvicorn":
                    is_uvicorn_run = True
            elif isinstance(node.func, ast.Name) and node.func.id == "run":
                is_uvicorn_run = True

            if is_app_run:
                for keyword in node.keywords:
                    if keyword.arg == "debug":
                        if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                            evidence_line = ast.get_source_segment(content, node) or "app.run(debug=True)"
                            self.findings.append(MisconfigFinding(
                                rule_id="SC-002",
                                cwe_id="CWE-94",
                                category="debug_mode_enabled",
                                severity="HIGH",
                                file_path=str(file_path),
                                line_number=node.lineno,
                                evidence=evidence_line.strip().splitlines()[0],
                                missing_guard="Disable debug mode in production",
                                confidence=0.95,
                                layer="ast"
                            ))

            if is_uvicorn_run:
                for keyword in node.keywords:
                    if keyword.arg in ("debug", "reload"):
                        if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                            evidence_line = ast.get_source_segment(content, node) or f"uvicorn.run(..., {keyword.arg}=True)"
                            self.findings.append(MisconfigFinding(
                                rule_id="SC-002",
                                cwe_id="CWE-94",
                                category="debug_mode_enabled",
                                severity="HIGH",
                                file_path=str(file_path),
                                line_number=node.lineno,
                                evidence=evidence_line.strip().splitlines()[0],
                                missing_guard="Disable reload/debug mode in production",
                                confidence=0.95,
                                layer="ast"
                            ))
            self.generic_visit(node)

        def visit_Assign(self, node: ast.Assign):
            if file_path.name in ("settings.py", "config.py", "app.py"):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "DEBUG":
                        if isinstance(node.value, ast.Constant) and node.value.value is True:
                            evidence_line = ast.get_source_segment(content, node) or "DEBUG = True"
                            self.findings.append(MisconfigFinding(
                                rule_id="SC-002",
                                cwe_id="CWE-94",
                                category="debug_mode_enabled",
                                severity="HIGH",
                                file_path=str(file_path),
                                line_number=node.lineno,
                                evidence=evidence_line.strip(),
                                missing_guard="Disable debug mode in production",
                                confidence=0.95,
                                layer="ast"
                            ))
            self.generic_visit(node)

    visitor = DebugModeVisitor()
    visitor.visit(tree)
    findings.extend(visitor.findings)
    return findings
