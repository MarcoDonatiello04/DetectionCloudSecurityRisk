import re

from tree_sitter import Node

from src.core.broken_function_level_authorization.models import FunctionAuthzFinding

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PRIVILEGED_PATH_PATTERNS = {
    "/admin",
    "/admins",
    "/internal",
    "/management",
    "/debug",
    "/config",
    "/settings/admin",
    "/users/*/role",
    "/users/*/promote",
    "/users/*/ban",
    "/export",
    "/reports/all",
    "/metrics/internal",
}

ROLE_CHECK_DECORATORS = {
    "roles_required",
    "require_role",
    "admin_required",
    "permission_required",
    "get_current_admin",
    "check_permission",
    "permission_classes",
    "IsAdminUser",
    "require_admin",
    "admin_only",
    "staff_required",
}


# Helper to normalize route paths
def normalize_path(path: str) -> str:
    path = re.sub(r"<[^>]+>", "*", path)
    path = re.sub(r"{[^}]+}", "*", path)
    path = re.sub(r":[a-zA-Z0-9_]+", "*", path)
    path = re.sub(r"/+", "/", path)
    if path.endswith("/") and len(path) > 1:
        path = path[:-1]
    return path


# Helper to check if a path is privileged
def is_privileged_path(path: str, http_method: str = "GET") -> bool:
    norm = normalize_path(path)

    # Check patterns
    for pattern in PRIVILEGED_PATH_PATTERNS:
        pattern_regex = re.escape(pattern).replace(r"\*", r"[^/]+")
        pattern_regex = r"^" + pattern_regex + r"(/.*)?$"
        if re.match(pattern_regex, norm):
            return True

    # Check collection operation
    if http_method.upper() in ("DELETE", "PUT"):
        segments = [s for s in norm.split("/") if s]
        if segments:
            last_segment = segments[-1]
            if last_segment != "*":
                return True

    return False


# Helper to check for inline role checks
def has_inline_role_check(body_text: str) -> bool:
    if any(kw in body_text for kw in ("is_admin", "is_staff", "has_role", "check_permission")):
        return True
    pattern = r"\b(role)\s*(==|!=|in\b|\bis\b)|in\s+[^:\n]*role"
    return bool(re.search(pattern, body_text))


# Helper to extract text from a tree-sitter node
def _node_text(node: Node | None) -> str:
    return node.text.decode("utf-8", errors="replace") if node and node.text else ""


# Helper to collect nodes of a specific type
def _collect_nodes(root: Node, node_type: str) -> list[Node]:
    result = []
    _walk_collect(root, node_type, result)
    return result


def _walk_collect(node: Node, node_type: str, acc: list[Node]) -> None:
    if node.type == node_type:
        acc.append(node)
    for child in node.children:
        _walk_collect(child, node_type, acc)


# Helper to extract route info from a Python decorator call
def _parse_python_decorator(dec_node: Node) -> tuple[str, list[str]]:
    call_nodes = _collect_nodes(dec_node, "call")
    if call_nodes:
        call_node = call_nodes[0]
        func = call_node.child_by_field_name("function")
        func_name = _node_text(func) if func else ""

        # Clean comment from func_name
        for char in ("#", "//"):
            if char in func_name:
                func_name = func_name.split(char)[0]
        func_name = func_name.strip()

        # Get path string from arguments
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

    # Clean comment from dec_text
    for char in ("#", "//"):
        if char in dec_text:
            dec_text = dec_text.split(char)[0]
    return dec_text.strip(), []


class PrivilegedEndpointNoRoleCheckRule:
    rule_id = "BF-001"
    cwe_id = "CWE-285"
    category = "privileged_endpoint_no_role_check"
    severity = "CRITICAL"

    @staticmethod
    def analyze_python(root: Node, file_path: str) -> list[FunctionAuthzFinding]:
        findings = []

        # Look for decorated definitions
        dec_defs = _collect_nodes(root, "decorated_definition")
        for dec_def in dec_defs:
            # Extract decorators and function definition
            decorators = [c for c in dec_def.children if c.type == "decorator"]
            func_node = next((c for c in dec_def.children if c.type == "function_definition"), None)
            if not func_node:
                continue

            # Check if this is a route handler
            is_route = False
            route_path = ""
            route_methods = []

            for dec in decorators:
                dec_name, dec_args = _parse_python_decorator(dec)
                dec_name_lower = dec_name.lower()

                # FastAPI / Flask routing check
                if any(
                    x in dec_name_lower
                    for x in ("app.route", "bp.route", "blueprint.route", "router.route")
                ):
                    is_route = True
                    if dec_args:
                        route_path = dec_args[0]
                    # Check Flask methods argument
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
                                        route_methods = [
                                            m.strip("\"' ").upper()
                                            for m in re.findall(
                                                r"['\"][a-zA-Z]+['\"]", methods_text
                                            )
                                        ]
                    if not route_methods:
                        route_methods = ["GET"]

                elif any(m in dec_name_lower for m in ("app.get", "bp.get", "router.get")):
                    is_route = True
                    route_methods = ["GET"]
                    if dec_args:
                        route_path = dec_args[0]
                elif any(m in dec_name_lower for m in ("app.post", "bp.post", "router.post")):
                    is_route = True
                    route_methods = ["POST"]
                    if dec_args:
                        route_path = dec_args[0]
                elif any(m in dec_name_lower for m in ("app.put", "bp.put", "router.put")):
                    is_route = True
                    route_methods = ["PUT"]
                    if dec_args:
                        route_path = dec_args[0]
                elif any(m in dec_name_lower for m in ("app.delete", "bp.delete", "router.delete")):
                    is_route = True
                    route_methods = ["DELETE"]
                    if dec_args:
                        route_path = dec_args[0]
                elif any(m in dec_name_lower for m in ("app.patch", "bp.patch", "router.patch")):
                    is_route = True
                    route_methods = ["PATCH"]
                    if dec_args:
                        route_path = dec_args[0]

            if not is_route or not route_path:
                continue

            # Verify if path is privileged
            for method in route_methods:
                if is_privileged_path(route_path, method):
                    # Check if role check exists
                    has_role_check = False
                    for dec in decorators:
                        dec_name, _ = _parse_python_decorator(dec)
                        # Check if any role check keyword matches
                        if any(rc in dec_name for rc in ROLE_CHECK_DECORATORS):
                            has_role_check = True
                            break

                    # Check inline body
                    body = func_node.child_by_field_name("body")
                    body_text = _node_text(body) if body else ""
                    if has_inline_role_check(body_text):
                        has_role_check = True

                    if not has_role_check:
                        # Determine confidence
                        confidence = (
                            0.75
                            if method in ("DELETE", "PUT")
                            and not any(
                                p in route_path
                                for p in ("/admin", "/internal", "/management", "/debug", "/config")
                            )
                            else 0.95
                        )
                        findings.append(
                            FunctionAuthzFinding(
                                rule_id=PrivilegedEndpointNoRoleCheckRule.rule_id,
                                cwe_id=PrivilegedEndpointNoRoleCheckRule.cwe_id,
                                category=PrivilegedEndpointNoRoleCheckRule.category,
                                severity=PrivilegedEndpointNoRoleCheckRule.severity,
                                file_path=file_path,
                                line_number=func_node.start_point[0] + 1,
                                endpoint=f"{method} {route_path}",
                                http_methods=route_methods,
                                required_role="admin",
                                found_guard=None,
                                missing_guard="Privileged endpoint missing role enforcement (@require_role or inline role checks)",
                                evidence=_node_text(dec_def)[:120],
                                confidence=confidence,
                                layer="ast",
                            )
                        )
                        break

        return findings

    @staticmethod
    def analyze_javascript(root: Node, file_path: str) -> list[FunctionAuthzFinding]:
        findings = []

        # Scan call expressions (app.get, router.delete etc)
        calls = _collect_nodes(root, "call_expression")
        for call in calls:
            func = call.child_by_field_name("function")
            if not func:
                continue
            func_text = _node_text(func)

            # Match routing prefixes
            is_js_route = any(
                prefix in func_text
                for prefix in [
                    "app.get",
                    "app.post",
                    "app.put",
                    "app.delete",
                    "app.patch",
                    "router.get",
                    "router.post",
                    "router.put",
                    "router.delete",
                    "router.patch",
                ]
            )
            if not is_js_route:
                continue

            # Extract method
            method = "GET"
            for m in ("get", "post", "put", "delete", "patch"):
                if f".{m}" in func_text:
                    method = m.upper()
                    break

            # Extract path (first argument)
            args_node = call.child_by_field_name("arguments")
            if (
                not args_node or len(args_node.children) < 3
            ):  # 1st arg is path, last is handler, should have at least path and handler
                continue

            path_node = args_node.children[
                1
            ]  # standard tree-sitter javascript: argument list starts with '(' then arguments
            if path_node.type != "string":
                continue
            route_path = _node_text(path_node).strip("\"'")

            if is_privileged_path(route_path, method):
                # Check midddlewares for role checks
                has_role_check = False
                middleware_args = args_node.children[
                    2:-2
                ]  # skip path (1st) and handler (last), and parenthesis

                for mw in middleware_args:
                    mw_text = _node_text(mw)
                    if any(rc in mw_text for rc in ROLE_CHECK_DECORATORS):
                        has_role_check = True
                        break

                # Check inline body of the handler function
                handler_node = args_node.children[-2]
                body_text = _node_text(handler_node)
                if has_inline_role_check(body_text):
                    has_role_check = True

                if not has_role_check:
                    confidence = (
                        0.75
                        if method in ("DELETE", "PUT")
                        and not any(
                            p in route_path
                            for p in ("/admin", "/internal", "/management", "/debug", "/config")
                        )
                        else 0.95
                    )
                    findings.append(
                        FunctionAuthzFinding(
                            rule_id=PrivilegedEndpointNoRoleCheckRule.rule_id,
                            cwe_id=PrivilegedEndpointNoRoleCheckRule.cwe_id,
                            category=PrivilegedEndpointNoRoleCheckRule.category,
                            severity=PrivilegedEndpointNoRoleCheckRule.severity,
                            file_path=file_path,
                            line_number=call.start_point[0] + 1,
                            endpoint=f"{method} {route_path}",
                            http_methods=[method],
                            required_role="admin",
                            found_guard=None,
                            missing_guard="Privileged JS endpoint missing role check middleware or inline role check",
                            evidence=_node_text(call)[:120],
                            confidence=confidence,
                            layer="ast",
                        )
                    )

        return findings
