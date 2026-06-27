import ast
import re
from pathlib import Path
from typing import List
from src.core.api8_security_misconfiguration.models import MisconfigFinding

def analyze(tree: ast.AST | None, file_path: Path, content: str) -> List[MisconfigFinding]:
    findings = []
    
    # Check if JS/TS
    if file_path.suffix in (".js", ".ts"):
        lines = content.splitlines()
        for idx, line in enumerate(lines, 1):
            if "cors(" in line:
                match_empty = re.search(r'cors\(\s*\)', line)
                match_wildcard = re.search(r'origin\s*:\s*[\'"]\*[\'"]', line)
                if match_empty or match_wildcard:
                    findings.append(MisconfigFinding(
                        rule_id="SC-001",
                        cwe_id="CWE-942",
                        category="cors_wildcard",
                        severity="HIGH",
                        file_path=str(file_path),
                        line_number=idx,
                        evidence=line.strip(),
                        missing_guard="CORS restrict allowlist",
                        confidence=0.95 if match_wildcard else 0.75,
                        layer="ast"
                    ))
        return findings

    if tree is None:
        return findings

    # Python AST Check
    class CORSVisitor(ast.NodeVisitor):
        def __init__(self):
            self.findings = []

        def visit_Call(self, node: ast.Call):
            # Check for Flask CORS(app, ...)
            if isinstance(node.func, ast.Name) and node.func.id == "CORS":
                origins_val = None
                for keyword in node.keywords:
                    if keyword.arg == "origins":
                        origins_val = keyword.value
                        
                is_wildcard = False
                confidence = 0.75
                evidence_line = ast.get_source_segment(content, node) or "CORS(app)"
                
                if origins_val is None:
                    is_wildcard = True
                    confidence = 0.75
                elif isinstance(origins_val, ast.Constant) and origins_val.value == "*":
                    is_wildcard = True
                    confidence = 0.95
                elif isinstance(origins_val, ast.List):
                    for elt in origins_val.elts:
                        if isinstance(elt, ast.Constant) and elt.value == "*":
                            is_wildcard = True
                            confidence = 0.95
                            
                if is_wildcard:
                    self.findings.append(MisconfigFinding(
                        rule_id="SC-001",
                        cwe_id="CWE-942",
                        category="cors_wildcard",
                        severity="HIGH",
                        file_path=str(file_path),
                        line_number=node.lineno,
                        evidence=evidence_line.strip(),
                        missing_guard="CORS restrict allowlist",
                        confidence=confidence,
                        layer="ast"
                    ))

            # Check for FastAPI add_middleware(CORSMiddleware, ...)
            elif isinstance(node.func, ast.Attribute) and node.func.attr == "add_middleware":
                if node.args and isinstance(node.args[0], ast.Name) and node.args[0].id == "CORSMiddleware":
                    allow_origins = None
                    allow_credentials = False
                    for keyword in node.keywords:
                        if keyword.arg == "allow_origins":
                            allow_origins = keyword.value
                        elif keyword.arg == "allow_credentials":
                            if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                                allow_credentials = True
                                
                    is_wildcard = False
                    if allow_origins:
                        if isinstance(allow_origins, ast.List):
                            for elt in allow_origins.elts:
                                if isinstance(elt, ast.Constant) and elt.value == "*":
                                    is_wildcard = True
                        elif isinstance(allow_origins, ast.Constant) and allow_origins.value == "*":
                            is_wildcard = True
                            
                    if is_wildcard:
                        severity = "CRITICAL" if allow_credentials else "HIGH"
                        evidence_line = ast.get_source_segment(content, node) or "add_middleware(CORSMiddleware)"
                        self.findings.append(MisconfigFinding(
                            rule_id="SC-001",
                            cwe_id="CWE-942",
                            category="cors_wildcard",
                            severity=severity,
                            file_path=str(file_path),
                            line_number=node.lineno,
                            evidence=evidence_line.strip(),
                            missing_guard="CORS restrict allowlist",
                            confidence=0.95,
                            layer="ast"
                        ))
            self.generic_visit(node)

        def visit_Assign(self, node: ast.Assign):
            # Check for Django setting CORS_ALLOW_ALL_ORIGINS = True
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "CORS_ALLOW_ALL_ORIGINS":
                    if isinstance(node.value, ast.Constant) and node.value.value is True:
                        evidence_line = ast.get_source_segment(content, node) or "CORS_ALLOW_ALL_ORIGINS = True"
                        self.findings.append(MisconfigFinding(
                            rule_id="SC-001",
                            cwe_id="CWE-942",
                            category="cors_wildcard",
                            severity="HIGH",
                            file_path=str(file_path),
                            line_number=node.lineno,
                            evidence=evidence_line.strip(),
                            missing_guard="CORS restrict allowlist",
                            confidence=0.95,
                            layer="ast"
                        ))
            self.generic_visit(node)

    visitor = CORSVisitor()
    visitor.visit(tree)
    findings.extend(visitor.findings)
    return findings
