"""
RC-004 — GraphQL Batching Unlimited

Detects GraphQL server initialisation without query depth/complexity limiters.
An unprotected GraphQL server is trivially DoS-able via deeply nested or
highly complex queries.

Supported frameworks:
  Python: strawberry.Schema, graphene.Schema, Ariadne make_executable_schema,
          GraphQL (graphql-core), Graphene Django
  JavaScript/TypeScript: ApolloServer, new GraphQLServer, createServer (graphql-ws)
"""

from __future__ import annotations

from tree_sitter import Node

from src.core.unrestricted_resource_consumption.models import ResourceConsumptionFinding

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Python GraphQL constructor call names
PY_GRAPHQL_CONSTRUCTORS = {
    "strawberry.Schema",
    "Schema",  # graphene.Schema / graphql-core Schema
    "GraphQL",  # graphql-core WSGI/ASGI app
    "make_executable_schema",  # Ariadne
    "build_schema",
}

# Python extension/plugin names that provide depth/complexity protection
PY_PROTECTION_NAMES = {
    "QueryDepthLimiter",
    "depth_limit_validator",
    "cost_validator",
    "MaxAliasesLimiter",
    "MaxDirectivesLimiter",
    "AddValidationRules",
    "query_depth_limiter",
    "NoSchemaIntrospectionCustomRule",
}

# JS/TS GraphQL constructor call names
JS_GRAPHQL_CONSTRUCTORS = {
    "ApolloServer",
    "GraphQLServer",
    "createServer",
}

# JS/TS protection option keys
JS_PROTECTION_KEYS = {
    "validationRules",
    "depthLimit",
    "complexityLimit",
    "plugins",
    "introspection",
    "csrfPrevention",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _node_text(node: Node) -> str:
    return node.text.decode("utf-8", errors="replace") if node.text else ""


def _collect_nodes(root: Node, node_type: str) -> list[Node]:
    result: list[Node] = []
    _walk(root, node_type, result)
    return result


def _walk(node: Node, node_type: str, acc: list[Node]) -> None:
    if node.type == node_type:
        acc.append(node)
    for child in node.children:
        _walk(child, node_type, acc)


def _get_attribute_chain(node: Node) -> list[str]:
    if node.type == "identifier":
        return [_node_text(node)]
    if node.type == "attribute":
        parts: list[str] = []
        for child in node.children:
            if child.type in ("identifier", "attribute"):
                parts.extend(_get_attribute_chain(child))
        return parts
    return []


def _dotted(chain: list[str]) -> str:
    return ".".join(chain)


# ---------------------------------------------------------------------------
# Python analysis
# ---------------------------------------------------------------------------


def _is_py_graphql_call(call_node: Node) -> bool:
    func = call_node.child_by_field_name("function")
    if func is None:
        return False
    chain = _get_attribute_chain(func)
    name = _dotted(chain)
    return name in PY_GRAPHQL_CONSTRUCTORS or chain[-1] in PY_GRAPHQL_CONSTRUCTORS


def _py_call_has_protection(call_node: Node) -> bool:
    """Returns True if the call arguments reference any protection extension."""
    args = call_node.child_by_field_name("arguments")
    if args is None:
        return False
    args_text = _node_text(args)
    return any(p in args_text for p in PY_PROTECTION_NAMES)


def _analyze_python(root: Node, file_path: str) -> list[ResourceConsumptionFinding]:
    findings: list[ResourceConsumptionFinding] = []
    calls = _collect_nodes(root, "call")
    for call in calls:
        if not _is_py_graphql_call(call):
            continue
        if _py_call_has_protection(call):
            continue
        func = call.child_by_field_name("function")
        func_name = _node_text(func) if func else "GraphQL"
        findings.append(
            ResourceConsumptionFinding(
                rule_id="RC-004",
                cwe_id="CWE-400",
                category="graphql_batching_unlimited",
                severity="HIGH",
                file_path=file_path,
                line_number=call.start_point[0] + 1,
                endpoint=None,
                parameter=None,
                evidence=f"{func_name}(...) without depth/complexity limiter extension",
                missing_guard=(
                    "No QueryDepthLimiter / cost_validator in extensions= or validation_rules="
                ),
                confidence=0.85,
                layer="ast",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# JavaScript analysis
# ---------------------------------------------------------------------------


def _is_js_graphql_call(call_node: Node) -> bool:
    func = call_node.child_by_field_name("function")
    if func is None:
        return False
    chain = _get_attribute_chain(func)
    return bool(chain) and chain[-1] in JS_GRAPHQL_CONSTRUCTORS


def _js_call_has_protection(call_node: Node) -> bool:
    args = call_node.child_by_field_name("arguments")
    if args is None:
        return False
    args_text = _node_text(args)
    return any(p in args_text for p in JS_PROTECTION_KEYS)


def _analyze_javascript(root: Node, file_path: str) -> list[ResourceConsumptionFinding]:
    findings: list[ResourceConsumptionFinding] = []
    for call_type in ("call_expression", "new_expression"):
        for call in _collect_nodes(root, call_type):
            if not _is_js_graphql_call(call):
                continue
            if _js_call_has_protection(call):
                continue
            func = call.child_by_field_name("function")
            func_name = _node_text(func) if func else "GraphQLServer"
            findings.append(
                ResourceConsumptionFinding(
                    rule_id="RC-004",
                    cwe_id="CWE-400",
                    category="graphql_batching_unlimited",
                    severity="HIGH",
                    file_path=file_path,
                    line_number=call.start_point[0] + 1,
                    endpoint=None,
                    parameter=None,
                    evidence=f"new {func_name}(...) without validationRules or depthLimit",
                    missing_guard="No validationRules: [depthLimit(...)] or complexity limiter",
                    confidence=0.85,
                    layer="ast",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class GraphQLBatchingRule:
    rule_id = "RC-004"
    cwe_id = "CWE-400"
    category = "graphql_batching_unlimited"
    severity = "HIGH"

    @staticmethod
    def analyze_python(root: Node, file_path: str) -> list[ResourceConsumptionFinding]:
        return _analyze_python(root, file_path)

    @staticmethod
    def analyze_javascript(root: Node, file_path: str) -> list[ResourceConsumptionFinding]:
        return _analyze_javascript(root, file_path)
