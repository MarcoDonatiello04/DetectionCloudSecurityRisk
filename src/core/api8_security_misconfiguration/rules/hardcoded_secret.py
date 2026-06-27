import ast
import math
from pathlib import Path
from typing import List
from src.core.api8_security_misconfiguration.models import MisconfigFinding

SENSITIVE_VAR_NAMES = {
    "secret", "password", "passwd", "pwd", "token", "api_key", "apikey",
    "auth_token", "private_key", "access_key", "secret_key", "jwt_secret",
    "client_secret", "app_secret", "signing_key", "stripe_key", "stripe_secret"
}

PLACEHOLDERS = {"changeme", "example", "test", "placeholder", "dummy", "null", "none", "admin", "password"}

def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    entropy = 0.0
    for x in set(s):
        p_x = float(s.count(x)) / len(s)
        entropy += - p_x * math.log(p_x, 2)
    return entropy

def is_sensitive_name(name: str) -> bool:
    name_lower = name.lower()
    for sensitive in SENSITIVE_VAR_NAMES:
        if sensitive in name_lower:
            return True
    return False

def analyze(tree: ast.AST | None, file_path: Path, content: str) -> List[MisconfigFinding]:
    findings = []
    if tree is None:
        return findings

    # Skip files inside tests
    if "test/" in file_path.as_posix() or "tests/" in file_path.as_posix():
        return findings

    class SecretVisitor(ast.NodeVisitor):
        def __init__(self):
            self.findings = []

        def visit_Assign(self, node: ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and is_sensitive_name(target.id):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        val = node.value.value
                        if not val:
                            continue
                            
                        val_lower = val.lower()
                        if any(pl in val_lower for pl in PLACEHOLDERS):
                            continue
                            
                        entropy = calculate_entropy(val)
                        confidence = 0.90 if entropy > 3.5 else 0.60
                        
                        evidence_line = ast.get_source_segment(content, node) or f"{target.id} = ..."
                        self.findings.append(MisconfigFinding(
                            rule_id="SC-005",
                            cwe_id="CWE-798",
                            category="hardcoded_secret",
                            severity="CRITICAL",
                            file_path=str(file_path),
                            line_number=node.lineno,
                            evidence=evidence_line.strip(),
                            missing_guard="Load secrets from environment variables or a secure vault",
                            confidence=confidence,
                            layer="ast"
                        ))
            self.generic_visit(node)

    visitor = SecretVisitor()
    visitor.visit(tree)
    findings.extend(visitor.findings)
    return findings
