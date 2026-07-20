import ast
from pathlib import Path

from src.core.api10_unsafe_consumption.models import UnsafeConsumptionFinding

EXCLUDED_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0"}
EXCLUDED_VAR_KEYWORDS = {"test", "mock", "fake", "stub"}


def is_vulnerable_http_url(url: str) -> bool:
    if not url.startswith("http://"):
        return False
    host = url[7:].split("/", 1)[0].split(":", 1)[0]
    return host.lower() not in EXCLUDED_HOSTS


def analyze(tree: ast.AST | None, file_path: Path, content: str) -> list[UnsafeConsumptionFinding]:
    findings = []
    if tree is None:
        return findings

    path_parts = {p.lower() for p in file_path.parts}
    if path_parts & {"test", "tests", "testing", "fixtures", "mock"}:
        if not ("vulnerable_app" in path_parts or "secure_app" in path_parts):
            return findings

    class UC002Visitor(ast.NodeVisitor):
        def __init__(self):
            self.findings = []
            self.http_vars = {}

        def visit_Assign(self, node: ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    name_lower = target.id.lower()
                    if any(kw in name_lower for kw in EXCLUDED_VAR_KEYWORDS):
                        continue
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        val = node.value.value
                        if is_vulnerable_http_url(val):
                            self.http_vars[target.id] = {"url": val, "lineno": node.lineno}
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call):
            is_http_client_call = False
            url_val = None

            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr
                in ("get", "post", "put", "patch", "delete", "request", "urlopen", "urlretrieve")
            ) or (
                isinstance(node.func, ast.Name)
                and node.func.id in ("fetch", "urlopen", "urlretrieve")
            ):
                is_http_client_call = True

            if is_http_client_call and node.args:
                arg0 = node.args[0]
                if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                    if is_vulnerable_http_url(arg0.value):
                        url_val = arg0.value
                elif isinstance(arg0, ast.Name) and arg0.id in self.http_vars:
                    url_val = self.http_vars[arg0.id]["url"]
                elif isinstance(arg0, ast.JoinedStr):
                    for val in arg0.values:
                        if isinstance(val, ast.FormattedValue):
                            if isinstance(val.value, ast.Name) and val.value.id in self.http_vars:
                                url_val = self.http_vars[val.value.id]["url"]

            if url_val:
                evidence_line = (
                    ast.get_source_segment(content, node) or f"requests.get('{url_val}')"
                )
                self.findings.append(
                    UnsafeConsumptionFinding(
                        rule_id="UC-002",
                        cwe_id="CWE-319",
                        category="http_instead_of_https",
                        severity="HIGH",
                        file_path=str(file_path),
                        line_number=node.lineno,
                        third_party_url=url_val,
                        evidence=evidence_line.strip().splitlines()[0],
                        missing_guard="Use HTTPS: replace http:// with https://",
                        confidence=0.95,
                        layer="ast",
                    )
                )
            self.generic_visit(node)

    visitor = UC002Visitor()
    visitor.visit(tree)
    findings.extend(visitor.findings)
    return findings
