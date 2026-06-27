import re
from tree_sitter import Node
from src.core.api5_broken_function_level_authorization.models import FunctionAuthzFinding
from src.core.api5_broken_function_level_authorization.rules.privileged_endpoint_no_role_check import (
    is_privileged_path, _node_text, _collect_nodes
)

def _parse_python_decorator(dec_node: Node) -> tuple[str, list[str]]:
    call_nodes = _collect_nodes(dec_node, "call")
    if call_nodes:
        call_node = call_nodes[0]
        func = call_node.child_by_field_name("function")
        func_name = _node_text(func) if func else ""
        paths = []
        args_node = call_node.child_by_field_name("arguments")
        if args_node:
            for child in args_node.children:
                if child.type == "string":
                    paths.append(_node_text(child).strip("\"'"))
        return func_name, paths
    dec_text = _node_text(dec_node)
    if dec_text.startswith("@"):
        dec_text = dec_text[1:]
    return dec_text, []


class HTTPMethodOverrideRule:
    rule_id = "BF-003"
    cwe_id = "CWE-650"
    category = "http_method_override"
    severity = "HIGH"

    @staticmethod
    def analyze_python(root: Node, file_path: str) -> list[FunctionAuthzFinding]:
        findings = []
        
        # 1. Check Flask route method override (@app.route without methods)
        dec_defs = _collect_nodes(root, "decorated_definition")
        for dec_def in dec_defs:
            decorators = [c for c in dec_def.children if c.type == "decorator"]
            func_node = next((cNode for cNode in dec_def.children if cNode.type == "function_definition"), None)
            if not func_node:
                continue
                
            for dec in decorators:
                dec_name, dec_args = _parse_python_decorator(dec)
                dec_name_lower = dec_name.lower()
                
                # Check for @app.route / @bp.route
                if any(x in dec_name_lower for x in ("app.route", "bp.route", "blueprint.route", "router.route")):
                    route_path = dec_args[0] if dec_args else ""
                    if not route_path:
                        continue
                        
                    # Check if privileged path
                    if is_privileged_path(route_path):
                        # Verify if 'methods' argument is present
                        call_nodes = _collect_nodes(dec, "call")
                        if call_nodes:
                            args = call_nodes[0].child_by_field_name("arguments")
                            has_methods = False
                            if args:
                                for kw in args.children:
                                    if kw.type == "keyword_argument":
                                        name_node = kw.child_by_field_name("name")
                                        if name_node and _node_text(name_node) == "methods":
                                            has_methods = True
                                            break
                            if not has_methods:
                                findings.append(FunctionAuthzFinding(
                                    rule_id=HTTPMethodOverrideRule.rule_id,
                                    cwe_id=HTTPMethodOverrideRule.cwe_id,
                                    category=HTTPMethodOverrideRule.category,
                                    severity=HTTPMethodOverrideRule.severity,
                                    file_path=file_path,
                                    line_number=func_node.start_point[0] + 1,
                                    endpoint=f"ANY {route_path}",
                                    http_methods=[],
                                    required_role="admin",
                                    found_guard=None,
                                    missing_guard="Route registered on a privileged path without explicit methods restriction",
                                    evidence=_node_text(dec)[:120],
                                    confidence=0.90,
                                    layer="ast"
                                ))
                                
        # 2. Check for X-HTTP-Method-Override header usage in Python files
        root_text = _node_text(root)
        if "x-http-method-override" in root_text.lower():
            # Find the line containing the header string
            lines = root_text.splitlines()
            for i, line in enumerate(lines, start=1):
                if "x-http-method-override" in line.lower():
                    findings.append(FunctionAuthzFinding(
                        rule_id=HTTPMethodOverrideRule.rule_id,
                        cwe_id=HTTPMethodOverrideRule.cwe_id,
                        category=HTTPMethodOverrideRule.category,
                        severity=HTTPMethodOverrideRule.severity,
                        file_path=file_path,
                        line_number=i,
                        endpoint=None,
                        http_methods=[],
                        required_role=None,
                        found_guard=None,
                        missing_guard="Detected use of X-HTTP-Method-Override without validation whitelist",
                        evidence=line.strip()[:120],
                        confidence=0.85,
                        layer="ast"
                    ))
                    
        return findings

    @staticmethod
    def analyze_javascript(root: Node, file_path: str) -> list[FunctionAuthzFinding]:
        findings = []
        
        # 1. Check Express route method override (app.all or router.all)
        calls = _collect_nodes(root, "call_expression")
        for call in calls:
            func = call.child_by_field_name("function")
            if not func:
                continue
            func_text = _node_text(func)
            
            # app.all or router.all
            is_all_route = any(prefix in func_text for prefix in ["app.all", "router.all"])
            if not is_all_route:
                continue
                
            args_node = call.child_by_field_name("arguments")
            if not args_node or len(args_node.children) < 3:
                continue
                
            path_node = args_node.children[1]
            if path_node.type != "string":
                continue
            route_path = _node_text(path_node).strip("\"'")
            
            if is_privileged_path(route_path):
                findings.append(FunctionAuthzFinding(
                    rule_id=HTTPMethodOverrideRule.rule_id,
                    cwe_id=HTTPMethodOverrideRule.cwe_id,
                    category=HTTPMethodOverrideRule.category,
                    severity=HTTPMethodOverrideRule.severity,
                    file_path=file_path,
                    line_number=call.start_point[0] + 1,
                    endpoint=f"ALL {route_path}",
                    http_methods=[],
                    required_role="admin",
                    found_guard=None,
                    missing_guard="Express route configured with .all() on a privileged path, accepting all HTTP methods",
                    evidence=_node_text(call)[:120],
                    confidence=0.90,
                    layer="ast"
                ))
                
        # 2. Check for X-HTTP-Method-Override header usage in JavaScript files
        root_text = _node_text(root)
        if "x-http-method-override" in root_text.lower():
            lines = root_text.splitlines()
            for i, line in enumerate(lines, start=1):
                if "x-http-method-override" in line.lower():
                    findings.append(FunctionAuthzFinding(
                        rule_id=HTTPMethodOverrideRule.rule_id,
                        cwe_id=HTTPMethodOverrideRule.cwe_id,
                        category=HTTPMethodOverrideRule.category,
                        severity=HTTPMethodOverrideRule.severity,
                        file_path=file_path,
                        line_number=i,
                        endpoint=None,
                        http_methods=[],
                        required_role=None,
                        found_guard=None,
                        missing_guard="Detected use of X-HTTP-Method-Override without validation whitelist",
                        evidence=line.strip()[:120],
                        confidence=0.85,
                        layer="ast"
                    ))
                    
        return findings
