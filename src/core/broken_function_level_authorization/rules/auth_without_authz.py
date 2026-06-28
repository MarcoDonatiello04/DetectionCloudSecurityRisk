import re
from tree_sitter import Node
from src.core.broken_function_level_authorization.models import FunctionAuthzFinding
from src.core.broken_function_level_authorization.rules.privileged_endpoint_no_role_check import (
    has_inline_role_check, _node_text, _collect_nodes, _parse_python_decorator
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

AUTH_ONLY_DECORATORS = {
    "login_required", "IsAuthenticated", "jwt_required",
    "token_required", "require_auth", "authenticated"
}

ROLE_CHECK_DECORATORS = {
    "roles_required", "require_role", "admin_required",
    "permission_required", "get_current_admin", "check_permission",
    "permission_classes", "IsAdminUser", "require_admin",
    "admin_only", "staff_required"
}

DESTRUCTIVE_OPERATIONS = {
    "delete(", "session.delete", "db.session.delete", "db.delete", "delete_user", "remove(", "rmtree",
    "promote(", "set_role", "update_role", "role =", "stripe.Charge", "payment", "refund"
}


class AuthWithoutAuthzRule:
    rule_id = "BF-002"
    cwe_id = "CWE-862"
    category = "auth_without_authz"
    severity = "HIGH"

    @staticmethod
    def analyze_python(root: Node, file_path: str) -> list[FunctionAuthzFinding]:
        findings = []
        
        dec_defs = _collect_nodes(root, "decorated_definition")
        for dec_def in dec_defs:
            decorators = [c for c in dec_def.children if c.type == "decorator"]
            func_node = next((c for c in dec_def.children if c.type == "function_definition"), None)
            if not func_node:
                continue
                
            body = func_node.child_by_field_name("body")
            body_text = _node_text(body) if body else ""
            
            # Check for destructive/sensitive operations
            has_destructive = any(op in body_text for op in DESTRUCTIVE_OPERATIONS)
            if not has_destructive:
                continue
                
            # Check decorators
            has_auth = False
            has_role_check = False
            
            # Reconstruct route methods/path to include in finding
            route_methods = []
            route_path = ""
            
            for dec in decorators:
                dec_name, dec_args = _parse_python_decorator(dec)
                dec_name_lower = dec_name.lower()
                
                # Check auth-only
                if any(ao in dec_name for ao in AUTH_ONLY_DECORATORS):
                    has_auth = True
                    
                # Check role check
                if any(rc in dec_name for rc in ROLE_CHECK_DECORATORS):
                    has_role_check = True
                    
                # Extract route method/path for context
                if any(x in dec_name_lower for x in ("app.route", "bp.route", "router.route")):
                    if dec_args:
                        route_path = dec_args[0]
                    # Try to extract Flask methods
                    call_nodes = _collect_nodes(dec, "call")
                    if call_nodes:
                        args = call_nodes[0].child_by_field_name("arguments")
                        if args:
                            for kw in args.children:
                                if kw.type == "keyword_argument":
                                    name_node = kw.child_by_field_name("name")
                                    val_node = kw.child_by_field_name("value")
                                    if name_node and _node_text(name_node) == "methods":
                                        methods_text = _node_text(val_node)
                                        route_methods = [m.strip("\"' ").upper() for m in re.findall(r"['\"][a-zA-Z]+['\"]", methods_text)]
                    if not route_methods:
                        route_methods = ["GET"]
                elif any(m in dec_name_lower for m in ("app.get", "bp.get", "router.get")):
                    route_methods = ["GET"]
                    if dec_args: route_path = dec_args[0]
                elif any(m in dec_name_lower for m in ("app.post", "bp.post", "router.post")):
                    route_methods = ["POST"]
                    if dec_args: route_path = dec_args[0]
                elif any(m in dec_name_lower for m in ("app.put", "bp.put", "router.put")):
                    route_methods = ["PUT"]
                    if dec_args: route_path = dec_args[0]
                elif any(m in dec_name_lower for m in ("app.delete", "bp.delete", "router.delete")):
                    route_methods = ["DELETE"]
                    if dec_args: route_path = dec_args[0]
                elif any(m in dec_name_lower for m in ("app.patch", "bp.patch", "router.patch")):
                    route_methods = ["PATCH"]
                    if dec_args: route_path = dec_args[0]
                    
            # Check inline body
            if has_inline_role_check(body_text):
                has_role_check = True
                
            if has_auth and not has_role_check:
                findings.append(FunctionAuthzFinding(
                    rule_id=AuthWithoutAuthzRule.rule_id,
                    cwe_id=AuthWithoutAuthzRule.cwe_id,
                    category=AuthWithoutAuthzRule.category,
                    severity=AuthWithoutAuthzRule.severity,
                    file_path=file_path,
                    line_number=func_node.start_point[0] + 1,
                    endpoint=f"{route_methods[0]} {route_path}" if route_methods and route_path else None,
                    http_methods=route_methods,
                    required_role="admin",
                    found_guard="login_required",
                    missing_guard="Sensitive operation decorated with authentication but missing role check",
                    evidence=_node_text(dec_def)[:120],
                    confidence=0.80,
                    layer="ast"
                ))
                
        return findings

    @staticmethod
    def analyze_javascript(root: Node, file_path: str) -> list[FunctionAuthzFinding]:
        findings = []
        
        calls = _collect_nodes(root, "call_expression")
        for call in calls:
            func = call.child_by_field_name("function")
            if not func:
                continue
            func_text = _node_text(func)
            
            is_js_route = any(prefix in func_text for prefix in ["app.get", "app.post", "app.put", "app.delete", "app.patch", "router.get", "router.post", "router.put", "router.delete", "router.patch"])
            if not is_js_route:
                continue
                
            args_node = call.child_by_field_name("arguments")
            if not args_node or len(args_node.children) < 3:
                continue
                
            path_node = args_node.children[1]
            if path_node.type != "string":
                continue
            route_path = _node_text(path_node).strip("\"'")
            
            method = "GET"
            for m in ("get", "post", "put", "delete", "patch"):
                if f".{m}" in func_text:
                    method = m.upper()
                    break
                    
            # Check handler body for destructive ops
            handler_node = args_node.children[-2]
            body_text = _node_text(handler_node)
            has_destructive = any(op in body_text for op in DESTRUCTIVE_OPERATIONS)
            if not has_destructive:
                continue
                
            # Check middlewares
            has_auth = False
            has_role_check = False
            middleware_args = args_node.children[2:-2]
            
            for mw in middleware_args:
                mw_text = _node_text(mw)
                if any(ao in mw_text for ao in AUTH_ONLY_DECORATORS):
                    has_auth = True
                if any(rc in mw_text for rc in ROLE_CHECK_DECORATORS):
                    has_role_check = True
                    
            # Check inline body
            if has_inline_role_check(body_text):
                has_role_check = True
                
            if has_auth and not has_role_check:
                findings.append(FunctionAuthzFinding(
                    rule_id=AuthWithoutAuthzRule.rule_id,
                    cwe_id=AuthWithoutAuthzRule.cwe_id,
                    category=AuthWithoutAuthzRule.category,
                    severity=AuthWithoutAuthzRule.severity,
                    file_path=file_path,
                    line_number=call.start_point[0] + 1,
                    endpoint=f"{method} {route_path}",
                    http_methods=[method],
                    required_role="admin",
                    found_guard="authentication middleware",
                    missing_guard="Sensitive Express operation has authentication middleware but missing role/authorization checks",
                    evidence=_node_text(call)[:120],
                    confidence=0.80,
                    layer="ast"
                ))
                
        return findings
