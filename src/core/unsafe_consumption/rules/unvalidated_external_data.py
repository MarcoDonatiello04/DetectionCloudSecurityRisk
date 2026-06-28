import ast
from pathlib import Path
from typing import List
from src.core.unsafe_consumption.models import UnsafeConsumptionFinding

def analyze(tree: ast.AST | None, file_path: Path, content: str) -> List[UnsafeConsumptionFinding]:
    findings = []
    if tree is None:
        return findings

    class UC001Visitor(ast.NodeVisitor):
        def __init__(self):
            self.findings = []
            self.json_vars = {}
            self.validated_vars = set()

        def visit_Assign(self, node: ast.Assign):
            is_json_call = False
            url_str = None
            
            if isinstance(node.value, ast.Call):
                if isinstance(node.value.func, ast.Attribute) and node.value.func.attr == "json":
                    is_json_call = True
                    # Try to trace the URL parameter from the value attribute
                    if isinstance(node.value.func.value, ast.Call):
                        subcall = node.value.func.value
                        if isinstance(subcall.func, ast.Attribute) and subcall.func.attr in ("get", "post", "put", "patch"):
                            if isinstance(subcall.func.value, ast.Name) and subcall.func.value.id in ("requests", "httpx"):
                                if subcall.args:
                                    if isinstance(subcall.args[0], ast.Constant):
                                        url_str = str(subcall.args[0].value)
                elif isinstance(node.value.func, ast.Attribute) and isinstance(node.value.func.value, ast.Call):
                    subcall = node.value.func.value
                    if isinstance(subcall.func, ast.Attribute) and subcall.func.attr in ("get", "post", "put", "patch"):
                        if isinstance(subcall.func.value, ast.Name) and subcall.func.value.id in ("requests", "httpx"):
                            is_json_call = True
                            if subcall.args:
                                if isinstance(subcall.args[0], ast.Constant):
                                    url_str = str(subcall.args[0].value)

            if is_json_call:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.json_vars[target.id] = {
                            "url": url_str,
                            "lineno": node.lineno
                        }

            if isinstance(node.value, ast.Call):
                for arg in node.value.args:
                    if isinstance(arg, ast.Name) and arg.id in self.json_vars:
                        self.validated_vars.add(arg.id)
                if node.value.keywords:
                    for kw in node.value.keywords:
                        if isinstance(kw.value, ast.Name) and kw.value.id in self.json_vars:
                            self.validated_vars.add(kw.value.id)
                        elif kw.arg is None and isinstance(kw.value, ast.Name) and kw.value.id in self.json_vars:
                            self.validated_vars.add(kw.value.id)

            self.generic_visit(node)

        def visit_Call(self, node: ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr in ("validate", "load"):
                for arg in node.args:
                    if isinstance(arg, ast.Name) and arg.id in self.json_vars:
                        self.validated_vars.add(arg.id)

            is_db_execute = False
            if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
                if isinstance(node.func.value, ast.Name) and node.func.value.id in ("db", "cursor", "conn"):
                    is_db_execute = True

            if is_db_execute and node.args:
                arg0 = node.args[0]
                contains_unvalidated = False
                target_var = None
                
                if isinstance(arg0, ast.JoinedStr):
                    for val in arg0.values:
                        if isinstance(val, ast.FormattedValue):
                            for subnode in ast.walk(val.value):
                                if isinstance(subnode, ast.Name) and subnode.id in self.json_vars:
                                    if subnode.id not in self.validated_vars:
                                        contains_unvalidated = True
                                        target_var = subnode.id
                
                if contains_unvalidated:
                    evidence_line = ast.get_source_segment(content, node) or "db.execute(...)"
                    url_val = self.json_vars[target_var]["url"] if target_var in self.json_vars else None
                    self.findings.append(UnsafeConsumptionFinding(
                        rule_id="UC-001",
                        cwe_id="CWE-20",
                        category="unvalidated_external_data",
                        severity="HIGH",
                        file_path=str(file_path),
                        line_number=node.lineno,
                        third_party_url=url_val,
                        evidence=evidence_line.strip(),
                        missing_guard="Validate schema using Pydantic, Marshmallow, or JSON Schema before SQL execution",
                        confidence=0.85,
                        layer="ast"
                    ))

            is_orm_create = False
            if isinstance(node.func, ast.Attribute) and node.func.attr == "create":
                if isinstance(node.func.value, ast.Attribute) and node.func.value.attr == "objects":
                    is_orm_create = True
            elif isinstance(node.func, ast.Name) and node.func.id.istitle():
                is_orm_create = True

            if is_orm_create and node.keywords:
                for kw in node.keywords:
                    if kw.arg is None and isinstance(kw.value, ast.Name) and kw.value.id in self.json_vars:
                        if kw.value.id not in self.validated_vars:
                            evidence_line = ast.get_source_segment(content, node) or "Model.objects.create(**data)"
                            url_val = self.json_vars[kw.value.id]["url"] if kw.value.id in self.json_vars else None
                            self.findings.append(UnsafeConsumptionFinding(
                                rule_id="UC-001",
                                cwe_id="CWE-20",
                                category="unvalidated_external_data",
                                severity="HIGH",
                                file_path=str(file_path),
                                line_number=node.lineno,
                                third_party_url=url_val,
                                evidence=evidence_line.strip(),
                                missing_guard="Filter or validate dictionary keys (Pydantic / explicit whitelist) before passing to ORM",
                                confidence=0.85,
                                layer="ast"
                            ))
            self.generic_visit(node)

    visitor = UC001Visitor()
    visitor.visit(tree)
    findings.extend(visitor.findings)
    return findings
