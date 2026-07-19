from tree_sitter import Node

from src.core.broken_function_level_authorization.models import FunctionAuthzFinding
from src.core.broken_function_level_authorization.rules.auth_without_authz import (
    AUTH_ONLY_DECORATORS,
)
from src.core.broken_function_level_authorization.rules.privileged_endpoint_no_role_check import (
    ROLE_CHECK_DECORATORS,
    _collect_nodes,
    _node_text,
    _parse_python_decorator,
    has_inline_role_check,
)

SHADOW_PATH_PATTERNS = {
    "/debug/",
    "/test/",
    "/testing/",
    "/dev/",
    "/development/",
    "/internal/",
    "/private/",
    "/seed/",
    "/fixture/",
    "/mock/",
    "/backdoor/",
    "/bypass/",
}

SHADOW_FN_KEYWORDS = {"seed_", "create_admin", "reset_all", "bypass_", "debug_", "test_", "dev_"}


def is_shadow_path(path: str) -> bool:
    path_lower = path.lower()
    # Normalize multiple slashes and add leading/trailing slashes for check
    normalized = "/" + path_lower.strip("/") + "/"
    return any(p in normalized for p in SHADOW_PATH_PATTERNS)


class ShadowAdminFunctionRule:
    rule_id = "BF-006"
    cwe_id = "CWE-285"
    category = "shadow_admin_function"
    severity = "HIGH"

    @staticmethod
    def analyze_python(root: Node, file_path: str) -> list[FunctionAuthzFinding]:
        findings = []

        # Maps blueprint variable name to its prefix
        from src.core.broken_function_level_authorization.rules.admin_path_exposure import (
            _get_blueprint_info,
        )

        blueprints = _get_blueprint_info(root)

        dec_defs = _collect_nodes(root, "decorated_definition")
        for dec_def in dec_defs:
            decorators = [c for c in dec_def.children if c.type == "decorator"]
            func_node = next((c for c in dec_def.children if c.type == "function_definition"), None)
            if not func_node:
                continue

            func_name = _node_text(func_node.child_by_field_name("name")) if func_node else ""
            body = func_node.child_by_field_name("body")
            body_text = _node_text(body) if body else ""

            is_route = False
            route_path = ""
            bp_var_used = None
            route_methods = ["GET"]

            for dec in decorators:
                dec_name, dec_args = _parse_python_decorator(dec)
                dec_name_lower = dec_name.lower()

                # Check blueprint or app level
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

            full_path = ""
            full_path = blueprints[bp_var_used] + route_path if bp_var_used else route_path

            # Verify decorators for protection
            has_auth = False
            has_role_check = False
            for dec in decorators:
                dec_name, _ = _parse_python_decorator(dec)
                if any(ao in dec_name for ao in AUTH_ONLY_DECORATORS):
                    has_auth = True
                if any(rc in dec_name for rc in ROLE_CHECK_DECORATORS):
                    has_role_check = True
            if has_inline_role_check(body_text):
                has_role_check = True

            # 1. Path is a shadow/debug path
            if is_shadow_path(full_path):
                if not has_role_check:
                    severity = (
                        "MEDIUM"
                        if has_auth and any(x in full_path.lower() for x in ("debug", "test"))
                        else "HIGH"
                    )
                    findings.append(
                        FunctionAuthzFinding(
                            rule_id=ShadowAdminFunctionRule.rule_id,
                            cwe_id=ShadowAdminFunctionRule.cwe_id,
                            category=ShadowAdminFunctionRule.category,
                            severity=severity,
                            file_path=file_path,
                            line_number=func_node.start_point[0] + 1,
                            endpoint=f"GET {full_path}",
                            http_methods=route_methods,
                            required_role="admin",
                            found_guard="login_required" if has_auth else None,
                            missing_guard="Shadow admin / debug endpoint exposed in production without role check",
                            evidence=_node_text(dec_def)[:120],
                            confidence=0.90,
                            layer="ast",
                        )
                    )
                else:
                    # TN: has require_role, but path contains debug/test -> LOW finding
                    if any(x in full_path.lower() for x in ("debug", "test")):
                        findings.append(
                            FunctionAuthzFinding(
                                rule_id=ShadowAdminFunctionRule.rule_id,
                                cwe_id=ShadowAdminFunctionRule.cwe_id,
                                category=ShadowAdminFunctionRule.category,
                                severity="LOW",
                                file_path=file_path,
                                line_number=func_node.start_point[0] + 1,
                                endpoint=f"GET {full_path}",
                                http_methods=route_methods,
                                required_role="admin",
                                found_guard="require_role",
                                missing_guard="Suspect debug/test endpoint still present in production (protected but check if it should be removed)",
                                evidence=_node_text(dec_def)[:120],
                                confidence=0.75,
                                layer="ast",
                            )
                        )
            else:
                # 2. Path not shadow, but function name implies shadow function (e.g. seed_..., create_admin)
                if any(kw in func_name.lower() for kw in SHADOW_FN_KEYWORDS):
                    if not has_role_check:
                        findings.append(
                            FunctionAuthzFinding(
                                rule_id=ShadowAdminFunctionRule.rule_id,
                                cwe_id=ShadowAdminFunctionRule.cwe_id,
                                category=ShadowAdminFunctionRule.category,
                                severity="LOW",
                                file_path=file_path,
                                line_number=func_node.start_point[0] + 1,
                                endpoint=f"GET {full_path}",
                                http_methods=route_methods,
                                required_role="admin",
                                found_guard=None,
                                missing_guard="Function name indicates test/seed/dev helper without role checks",
                                evidence=_node_text(dec_def)[:120],
                                confidence=0.50,
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

            # Check guards
            has_auth = False
            has_role_check = False
            middleware_args = args_node.children[2:-2]
            for mw in middleware_args:
                mw_text = _node_text(mw)
                if any(ao in mw_text for ao in AUTH_ONLY_DECORATORS):
                    has_auth = True
                if any(rc in mw_text for rc in ROLE_CHECK_DECORATORS):
                    has_role_check = True

            handler_node = args_node.children[-2]
            body_text = _node_text(handler_node)
            if has_inline_role_check(body_text):
                has_role_check = True

            if is_shadow_path(route_path):
                if not has_role_check:
                    severity = (
                        "MEDIUM"
                        if has_auth and any(x in route_path.lower() for x in ("debug", "test"))
                        else "HIGH"
                    )
                    findings.append(
                        FunctionAuthzFinding(
                            rule_id=ShadowAdminFunctionRule.rule_id,
                            cwe_id=ShadowAdminFunctionRule.cwe_id,
                            category=ShadowAdminFunctionRule.category,
                            severity=severity,
                            file_path=file_path,
                            line_number=call.start_point[0] + 1,
                            endpoint=f"GET {route_path}",
                            http_methods=["GET"],
                            required_role="admin",
                            found_guard="login_required" if has_auth else None,
                            missing_guard="Shadow JS admin / debug endpoint exposed without role middleware",
                            evidence=_node_text(call)[:120],
                            confidence=0.90,
                            layer="ast",
                        )
                    )
                else:
                    if any(x in route_path.lower() for x in ("debug", "test")):
                        findings.append(
                            FunctionAuthzFinding(
                                rule_id=ShadowAdminFunctionRule.rule_id,
                                cwe_id=ShadowAdminFunctionRule.cwe_id,
                                category=ShadowAdminFunctionRule.category,
                                severity="LOW",
                                file_path=file_path,
                                line_number=call.start_point[0] + 1,
                                endpoint=f"GET {route_path}",
                                http_methods=["GET"],
                                required_role="admin",
                                found_guard="require_role",
                                missing_guard="Suspect debug/test Express endpoint in production",
                                evidence=_node_text(call)[:120],
                                confidence=0.75,
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
            if is_shadow_path(path_str):
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
                                    rule_id=ShadowAdminFunctionRule.rule_id,
                                    cwe_id=ShadowAdminFunctionRule.cwe_id,
                                    category=ShadowAdminFunctionRule.category,
                                    severity="HIGH",
                                    file_path="openapi_spec",
                                    line_number=None,
                                    endpoint=f"{method.upper()} {path_str}",
                                    http_methods=[method.upper()],
                                    required_role="admin",
                                    found_guard=None,
                                    missing_guard="OpenAPI documents debug/test path without security restriction",
                                    evidence=f"{method.upper()} {path_str}",
                                    confidence=0.90,
                                    layer="openapi",
                                )
                            )
        return findings
