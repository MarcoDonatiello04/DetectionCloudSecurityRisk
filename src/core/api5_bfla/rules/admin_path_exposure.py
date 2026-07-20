from tree_sitter import Node

from src.core.api5_bfla.models import FunctionAuthzFinding
from src.core.api5_bfla.rules.privileged_endpoint_no_role_check import (
    ROLE_CHECK_DECORATORS,
    _collect_nodes,
    _node_text,
    _parse_python_decorator,
    has_inline_role_check,
    is_privileged_path,
)

BULK_FUNCTION_PATTERNS = {"export_all", "list_all", "get_all", "delete_all", "bulk_", "mass_"}
BULK_BODY_PATTERNS = {".all()", "query.all()", "findall(", "find_all("}


def _get_blueprint_info(root: Node) -> dict[str, str]:
    blueprints = {}
    assignments = _collect_nodes(root, "assignment")
    for assign in assignments:
        left = assign.child_by_field_name("left")
        right = assign.child_by_field_name("right")
        if left and right and right.type == "call":
            func = right.child_by_field_name("function")
            if func and _node_text(func) == "Blueprint":
                bp_var = _node_text(left)
                args = right.child_by_field_name("arguments")
                url_prefix = ""
                if args:
                    for arg in args.children:
                        if arg.type == "keyword_argument":
                            name_node = arg.child_by_field_name("name")
                            val_node = arg.child_by_field_name("value")
                            if name_node and _node_text(name_node) == "url_prefix":
                                url_prefix = _node_text(val_node).strip("\"'")
                blueprints[bp_var] = url_prefix
    return blueprints


class AdminPathExposureRule:
    rule_id = "BF-004"
    cwe_id = "CWE-284"
    category = "admin_path_exposure"
    severity = "HIGH"

    @staticmethod
    def analyze_python(root: Node, file_path: str) -> list[FunctionAuthzFinding]:
        findings = []

        blueprints = _get_blueprint_info(root)

        bp_protected = {}
        dec_defs = _collect_nodes(root, "decorated_definition")

        for bp_var, prefix in blueprints.items():
            bp_protected[bp_var] = False
            for dec_def in dec_defs:
                decorators = [c for c in dec_def.children if c.type == "decorator"]
                for dec in decorators:
                    dec_name, _ = _parse_python_decorator(dec)
                    if dec_name == f"{bp_var}.before_request":
                        func = next(
                            (c for c in dec_def.children if c.type == "function_definition"), None
                        )
                        if func:
                            body = func.child_by_field_name("body")
                            body_text = _node_text(body) if body else ""
                            if has_inline_role_check(body_text):
                                bp_protected[bp_var] = True
                                break
                            # Check decorators on before_request function
                            for d in decorators:
                                d_name, _ = _parse_python_decorator(d)
                                if any(rc in d_name for rc in ROLE_CHECK_DECORATORS):
                                    bp_protected[bp_var] = True
                                    break

        for dec_def in dec_defs:
            decorators = [c for c in dec_def.children if c.type == "decorator"]
            func_node = next((c for c in dec_def.children if c.type == "function_definition"), None)
            if not func_node:
                continue

            func_name = _node_text(func_node.child_by_field_name("name")) if func_node else ""
            body = func_node.child_by_field_name("body")
            body_text = _node_text(body) if body else ""

            is_route = False
            bp_var_used = None
            route_path = ""

            for dec in decorators:
                dec_name, dec_args = _parse_python_decorator(dec)
                dec_name_lower = dec_name.lower()

                for bp_var in blueprints:
                    if dec_name.startswith(f"{bp_var}."):
                        is_route = True
                        bp_var_used = bp_var
                        if dec_args:
                            route_path = dec_args[0]
                        break

                if any(
                    x in dec_name_lower
                    for x in ("app.route", "app.get", "app.post", "app.put", "app.delete")
                ):
                    is_route = True
                    if dec_args:
                        route_path = dec_args[0]

            if not is_route:
                continue

            has_role_check = False
            for dec in decorators:
                dec_name, _ = _parse_python_decorator(dec)
                if any(rc in dec_name for rc in ROLE_CHECK_DECORATORS):
                    has_role_check = True
                    break
            if has_inline_role_check(body_text):
                has_role_check = True

            # Pattern A: Blueprint route on admin prefix without blueprint global before_request check
            if bp_var_used and not has_role_check:
                prefix = blueprints[bp_var_used]
                if any(adm in prefix for adm in ("/admin", "/internal")):
                    if not bp_protected.get(bp_var_used, False):
                        findings.append(
                            FunctionAuthzFinding(
                                rule_id=AdminPathExposureRule.rule_id,
                                cwe_id=AdminPathExposureRule.cwe_id,
                                category=AdminPathExposureRule.category,
                                severity=AdminPathExposureRule.severity,
                                file_path=file_path,
                                line_number=func_node.start_point[0] + 1,
                                endpoint=f"GET {prefix}{route_path}",
                                http_methods=["GET"],
                                required_role="admin",
                                found_guard=None,
                                missing_guard="Blueprint has administrative prefix but lacks global before_request role check, and route handler lacks individual protection",
                                evidence=_node_text(dec_def)[:120],
                                confidence=0.90,
                                layer="ast",
                            )
                        )
                        continue

            # Pattern B: Bulk function on ordinary path without role check
            full_path = ""
            full_path = blueprints[bp_var_used] + route_path if bp_var_used else route_path

            if not is_privileged_path(full_path) and not has_role_check:
                is_bulk = any(bp in func_name.lower() for bp in BULK_FUNCTION_PATTERNS)
                if not is_bulk:
                    is_bulk = any(bp in body_text for bp in BULK_BODY_PATTERNS)
                if is_bulk:
                    findings.append(
                        FunctionAuthzFinding(
                            rule_id=AdminPathExposureRule.rule_id,
                            cwe_id=AdminPathExposureRule.cwe_id,
                            category=AdminPathExposureRule.category,
                            severity=AdminPathExposureRule.severity,
                            file_path=file_path,
                            line_number=func_node.start_point[0] + 1,
                            endpoint=f"GET {full_path}",
                            http_methods=["GET"],
                            required_role="admin",
                            found_guard=None,
                            missing_guard="Bulk database query/export executed on ordinary path without role checks",
                            evidence=_node_text(dec_def)[:120],
                            confidence=0.70,
                            layer="ast",
                        )
                    )

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

            is_js_route = any(
                prefix in func_text
                for prefix in [
                    "app.get",
                    "app.post",
                    "app.put",
                    "app.delete",
                    "router.get",
                    "router.post",
                    "router.put",
                    "router.delete",
                ]
            )
            if not is_js_route:
                continue

            args_node = call.child_by_field_name("arguments")
            if not args_node or len(args_node.children) < 3:
                continue

            path_node = args_node.children[1]
            if path_node.type != "string":
                continue
            route_path = _node_text(path_node).strip("\"'")

            if not is_privileged_path(route_path):
                handler_node = args_node.children[-2]
                body_text = _node_text(handler_node)

                has_role_check = False
                middleware_args = args_node.children[2:-2]
                for mw in middleware_args:
                    mw_text = _node_text(mw)
                    if any(rc in mw_text for rc in ROLE_CHECK_DECORATORS):
                        has_role_check = True
                if has_inline_role_check(body_text):
                    has_role_check = True

                if not has_role_check:
                    is_bulk = any(bp in body_text for bp in BULK_BODY_PATTERNS)
                    if is_bulk:
                        findings.append(
                            FunctionAuthzFinding(
                                rule_id=AdminPathExposureRule.rule_id,
                                cwe_id=AdminPathExposureRule.cwe_id,
                                category=AdminPathExposureRule.category,
                                severity=AdminPathExposureRule.severity,
                                file_path=file_path,
                                line_number=call.start_point[0] + 1,
                                endpoint=f"GET {route_path}",
                                http_methods=["GET"],
                                required_role="admin",
                                found_guard=None,
                                missing_guard="Semantic admin/bulk query executed on ordinary path without authorization middleware",
                                evidence=_node_text(call)[:120],
                                confidence=0.70,
                                layer="ast",
                            )
                        )
        return findings

    @staticmethod
    def analyze_openapi(spec: dict) -> list[FunctionAuthzFinding]:
        findings = []
        paths = spec.get("paths") or {}
        global_security = spec.get("security") or []

        for path_str, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            if "/admin" in path_str.lower() or "/internal" in path_str.lower():
                for method in ("get", "post", "put", "delete", "patch"):
                    op = path_item.get(method)
                    if isinstance(op, dict):
                        op_security = op.get("security")
                        has_authz = False
                        if op_security is not None:
                            if isinstance(op_security, list) and len(op_security) > 0:
                                has_authz = True
                        elif global_security:
                            has_authz = True

                        if not has_authz:
                            findings.append(
                                FunctionAuthzFinding(
                                    rule_id=AdminPathExposureRule.rule_id,
                                    cwe_id=AdminPathExposureRule.cwe_id,
                                    category=AdminPathExposureRule.category,
                                    severity=AdminPathExposureRule.severity,
                                    file_path="openapi_spec",
                                    line_number=None,
                                    endpoint=f"{method.upper()} {path_str}",
                                    http_methods=[method.upper()],
                                    required_role="admin",
                                    found_guard=None,
                                    missing_guard="OpenAPI admin path exposed without documented security constraints",
                                    evidence=f"{method.upper()} {path_str}",
                                    confidence=0.90,
                                    layer="openapi",
                                )
                            )
        return findings
