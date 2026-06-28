import ast
from pathlib import Path
from typing import List
from src.core.api10_unsafe_consumption.models import UnsafeConsumptionFinding

SENSITIVE_BODY_KEYWORDS = {
    "user", "patient", "medical", "personal", "private", "passwd",
    "password", "ssn", "email", "token", "credential", "data", "info"
}

def is_external_url(url: str) -> bool:
    if not (url.startswith("http://") or url.startswith("https://")):
        return False
    host = url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
    if host.lower() in ("localhost", "127.0.0.1", "0.0.0.0"):
        return False
    return True

def analyze(tree: ast.AST | None, file_path: Path, content: str) -> List[UnsafeConsumptionFinding]:
    findings = []
    if tree is None:
        return findings

    path_parts = {p.lower() for p in file_path.parts}
    if path_parts & {"test", "tests", "testing", "fixtures", "mock"}:
        if not ("vulnerable_app" in path_parts or "secure_app" in path_parts):
            return findings

    class UC003Visitor(ast.NodeVisitor):
        def __init__(self):
            self.findings = []
            self.api_vars = {}

        def visit_Assign(self, node: ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        val = node.value.value
                        if is_external_url(val):
                            self.api_vars[target.id] = val
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call):
            is_requests_call = False
            method = None
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "requests":
                if node.func.attr in ("get", "post", "put", "patch", "delete", "request"):
                    is_requests_call = True
                    method = node.func.attr

            if is_requests_call:
                url_val = None
                if node.args:
                    arg0 = node.args[0]
                    if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                        if is_external_url(arg0.value):
                            url_val = arg0.value
                    elif isinstance(arg0, ast.Name) and arg0.id in self.api_vars:
                        url_val = self.api_vars[arg0.id]
                    elif isinstance(arg0, ast.JoinedStr):
                        for val in arg0.values:
                            if isinstance(val, ast.FormattedValue):
                                if isinstance(val.value, ast.Name) and val.value.id in self.api_vars:
                                    url_val = self.api_vars[val.value.id]

                allow_redirects_node = None
                for kw in node.keywords:
                    if kw.arg == "allow_redirects":
                        allow_redirects_node = kw.value

                is_secure = False
                is_explicit_true = False
                if allow_redirects_node:
                    if isinstance(allow_redirects_node, ast.Constant):
                        if allow_redirects_node.value is False:
                            is_secure = True
                        elif allow_redirects_node.value is True:
                            is_explicit_true = True

                has_data_payload = False
                payload_var_name = ""
                for kw in node.keywords:
                    if kw.arg in ("json", "data"):
                        has_data_payload = True
                        if isinstance(kw.value, ast.Name):
                            payload_var_name = kw.value.id
                        elif isinstance(kw.value, ast.Dict):
                            for val in kw.value.values:
                                if isinstance(val, ast.Name):
                                    payload_var_name = val.id

                is_sensitive = False
                if has_data_payload:
                    if payload_var_name:
                        name_lower = payload_var_name.lower()
                        if any(k in name_lower for k in SENSITIVE_BODY_KEYWORDS):
                            is_sensitive = True
                    else:
                        is_sensitive = True

                if url_val and not is_secure:
                    if method in ("post", "put", "patch") and is_sensitive:
                        severity = "HIGH"
                    elif method == "get" and is_explicit_true:
                        severity = "MEDIUM"
                    else:
                        severity = None

                    if severity:
                        evidence_line = ast.get_source_segment(content, node) or f"requests.{method}(...)"
                        self.findings.append(UnsafeConsumptionFinding(
                            rule_id="UC-003",
                            cwe_id="CWE-601",
                            category="blind_redirect_following",
                            severity=severity,
                            file_path=str(file_path),
                            line_number=node.lineno,
                            third_party_url=url_val,
                            evidence=evidence_line.strip().splitlines()[0],
                            missing_guard="Add allow_redirects=False and handle redirects manually",
                            confidence=0.80,
                            layer="ast"
                        ))
            self.generic_visit(node)

    visitor = UC003Visitor()
    visitor.visit(tree)
    findings.extend(visitor.findings)
    return findings
