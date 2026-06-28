import ast
import math
from pathlib import Path
from typing import List
from src.core.security_misconfiguration.models import MisconfigFinding

SENSITIVE_VAR_NAMES = {
    "secret", "password", "passwd", "pwd", "token", "api_key", "apikey",
    "auth_token", "private_key", "access_key", "secret_key", "jwt_secret",
    "client_secret", "app_secret", "signing_key", "stripe_key", "stripe_secret"
}

PLACEHOLDER_VALUES = {
    "changeme", "change_me", "example", "test", "placeholder",
    "secret", "password", "your_secret_here", "insert_key_here",
    "xxx", "yyy", "todo", "fixme"
}

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    entropy = 0.0
    for x in set(s):
        p_x = float(s.count(x)) / len(s)
        entropy += - p_x * math.log(p_x, 2)
    return entropy

def _compute_confidence(var_name: str, value: str) -> float:
    entropy = _shannon_entropy(value)
    
    if len(value) < 8:
        return 0.50
    if value.lower() in PLACEHOLDER_VALUES:
        return 0.40
    
    if ' ' in value:
        return 0.45
        
    if entropy > 3.5:
        return 0.90
    if entropy > 2.5:
        return 0.70
    
    return 0.60

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

    # Skip files inside tests but allow our validation fixtures
    path_parts = {p.lower() for p in file_path.parts}
    if path_parts & {"test", "tests", "testing", "fixtures", "mock"}:
        if not ("vulnerable_app" in path_parts or "secure_app" in path_parts):
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
                        if val_lower in {"", "todo", "fixme"}:
                            continue
                            
                        confidence = _compute_confidence(target.id, val)
                        
                        evidence_str = f"{target.id} = \"{val[:40]}{'...' if len(val) > 40 else ''}\""
                        self.findings.append(MisconfigFinding(
                            rule_id="SC-005",
                            cwe_id="CWE-798",
                            category="hardcoded_secret",
                            severity="CRITICAL",
                            file_path=str(file_path),
                            line_number=node.lineno,
                            evidence=evidence_str,
                            missing_guard=f"Move {target.id} to environment variable: os.environ.get('{target.id}')",
                            confidence=confidence,
                            layer="ast"
                        ))
            self.generic_visit(node)

    visitor = SecretVisitor()
    visitor.visit(tree)
    findings.extend(visitor.findings)
    return findings
