"""
RC-001 — Unbounded Pagination

Detects route handlers where a pagination parameter (limit, page_size, per_page,
count, size) is read from the request and passed to a query/ORM method WITHOUT
any capping guard (min/max/if-comparison).

Supports:
  - Flask: request.args.get('limit') → .limit(x) / queryset[:x]
  - Django: request.GET.get('limit') → queryset[:limit]
  - FastAPI: limit: int = Query(default=...) without le=
  - Express (JS): req.query.limit → .limit(limit) / .take(limit)
  - SQLAlchemy: .limit(user_var) without upstream validation
"""

from __future__ import annotations

from typing import Optional

from tree_sitter import Node

from src.core.unrestricted_resource_consumption.models import ResourceConsumptionFinding

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PAGINATION_PARAMS = {"limit", "page_size", "per_page", "count", "size", "offset", "take", "skip"}

# Method names that consume a pagination variable
ORM_LIMIT_METHODS = {"limit", "take", "first", "offset", "skip", "paginate"}

# Guard call names that cap the value
CAP_FUNCTIONS = {"min", "max", "Math.min", "Math.max", "clamp", "min_value", "max_value"}

# Request source attribute chains
REQUEST_ARG_ATTRS = {
    # Flask / Django
    ("request", "args", "get"),
    ("request", "GET", "get"),
    ("request", "json", "get"),
    ("request", "form", "get"),
    ("request", "query_params", "get"),
}


# ---------------------------------------------------------------------------
# Helpers — AST traversal
# ---------------------------------------------------------------------------

def _node_text(node: Node) -> str:
    return node.text.decode("utf-8", errors="replace") if node.text else ""


def _collect_nodes(root: Node, node_type: str) -> list[Node]:
    """Recursively collect all descendant nodes of a given type."""
    result: list[Node] = []
    _walk_collect(root, node_type, result)
    return result


def _walk_collect(node: Node, node_type: str, acc: list[Node]) -> None:
    if node.type == node_type:
        acc.append(node)
    for child in node.children:
        _walk_collect(child, node_type, acc)


def _get_attribute_chain(node: Node) -> list[str]:
    """
    For an attribute node `a.b.c`, return ['a', 'b', 'c'].
    For an identifier, return [name].
    """
    if node.type == "identifier":
        return [_node_text(node)]
    if node.type == "attribute":
        parts: list[str] = []
        for child in node.children:
            if child.type in ("identifier", "attribute"):
                parts.extend(_get_attribute_chain(child))
            # skip '.'
        return parts
    return []


def _is_request_param_source(call_node: Node) -> Optional[str]:
    """
    Returns the string key of the parameter if this call is a request-param
    extraction (e.g. request.args.get('limit')), else None.
    """
    if call_node.type != "call":
        return None
    func = call_node.child_by_field_name("function")
    if func is None:
        return None
    chain = _get_attribute_chain(func)
    # Check against known patterns
    if tuple(chain) in REQUEST_ARG_ATTRS:
        # Extract the first string argument as the key name
        args = call_node.child_by_field_name("arguments")
        if args:
            for arg in args.children:
                if arg.type == "string":
                    key = _node_text(arg).strip("\"'")
                    return key
    return None


def _is_fastapi_query_with_le(param_node: Node) -> tuple[bool, bool]:
    """
    For a FastAPI function parameter default that is Query(...), returns:
    (is_query_param, has_le_constraint).
    """
    # parameter → default_value → call to Query(...)
    default = param_node.child_by_field_name("default_value")
    if default is None:
        return False, False
    if default.type != "call":
        return False, False
    func = default.child_by_field_name("function")
    if func is None or _node_text(func) != "Query":
        return False, False
    # It is a Query() param — check kwargs for 'le'
    args = default.child_by_field_name("arguments")
    if args is None:
        return True, False
    has_le = False
    for kw in args.children:
        if kw.type == "keyword_argument":
            name_node = kw.child_by_field_name("name")
            if name_node and _node_text(name_node) in ("le", "lte", "max_value", "ge"):
                has_le = True
    return True, has_le


def _name_is_pagination_param(name: str) -> bool:
    return name.lower() in PAGINATION_PARAMS


def _body_has_capping_guard(body: Node, var_name: str) -> bool:
    """
    Returns True if the function body contains a min/max/if-comparison guard
    on the given variable before it is used in an ORM call.
    """
    # Look for: min(var, ...) / max(var, ...) / if var > CONST / if var >= CONST
    calls = _collect_nodes(body, "call")
    for call in calls:
        func = call.child_by_field_name("function")
        if func and _node_text(func) in CAP_FUNCTIONS:
            args = call.child_by_field_name("arguments")
            if args:
                for arg in args.children:
                    if _node_text(arg) == var_name:
                        return True

    # Look for comparison / if-statement guard
    comparisons = _collect_nodes(body, "comparison_operator")
    for comp in comparisons:
        if any(_node_text(c) == var_name for c in comp.children):
            return True

    # Check augmented assignment or explicit bounds check
    ifs = _collect_nodes(body, "if_statement")
    for if_node in ifs:
        cond = if_node.child_by_field_name("condition")
        if cond and var_name in _node_text(cond):
            return True

    return False


def _body_uses_var_in_orm(body: Node, var_name: str) -> Optional[Node]:
    """
    Returns the call node where var_name is passed to an ORM limit method.
    """
    calls = _collect_nodes(body, "call")
    for call in calls:
        func = call.child_by_field_name("function")
        if func is None:
            continue
        chain = _get_attribute_chain(func)
        if not chain:
            continue
        method = chain[-1].lower()
        if method in ORM_LIMIT_METHODS:
            args = call.child_by_field_name("arguments")
            if args:
                for arg in args.children:
                    if _node_text(arg) == var_name:
                        return call
    # Also check slice: queryset[:limit]
    slices = _collect_nodes(body, "subscript")
    for sub in slices:
        slice_node = sub.child_by_field_name("slice")
        if slice_node and var_name in _node_text(slice_node):
            return sub
    return None


# ---------------------------------------------------------------------------
# Python analysis
# ---------------------------------------------------------------------------

def _analyze_python_function(func_node: Node, file_path: str) -> list[ResourceConsumptionFinding]:
    findings: list[ResourceConsumptionFinding] = []
    body = func_node.child_by_field_name("body")
    if body is None:
        return findings

    # --- FastAPI Query() parameters ---
    params = func_node.child_by_field_name("parameters")
    if params:
        for param in params.children:
            if param.type in ("default_parameter", "typed_default_parameter"):
                name_node = param.child_by_field_name("name")
                if name_node is None:
                    continue
                param_name = _node_text(name_node)
                if not _name_is_pagination_param(param_name):
                    continue
                is_query, has_le = _is_fastapi_query_with_le(param)
                if is_query and not has_le:
                    findings.append(ResourceConsumptionFinding(
                        rule_id="RC-001",
                        cwe_id="CWE-400",
                        category="unbounded_pagination",
                        severity="HIGH",
                        file_path=file_path,
                        line_number=param.start_point[0] + 1,
                        endpoint=None,
                        parameter=param_name,
                        evidence=_node_text(param)[:120],
                        missing_guard="FastAPI Query() missing le= (upper-bound) constraint",
                        confidence=0.9,
                        layer="ast",
                    ))

    # --- Assignment-based taint: limit = request.args.get('limit') ---
    assignments = _collect_nodes(body, "assignment")
    for assign in assignments:
        lhs = assign.child_by_field_name("left")
        rhs = assign.child_by_field_name("right")
        if lhs is None or rhs is None:
            continue
        if lhs.type != "identifier":
            continue
        var_name = _node_text(lhs)
        if not _name_is_pagination_param(var_name):
            continue

        # Check if RHS is a request-param source
        key = _is_request_param_source(rhs)
        if key is None and rhs.type == "call":
            # Could be indirect: limit = int(request.args.get('limit'))
            inner_calls = _collect_nodes(rhs, "call")
            for ic in inner_calls:
                key = _is_request_param_source(ic)
                if key:
                    break
        if key is None:
            continue

        # Variable is tainted. Check for capping guard.
        if _body_has_capping_guard(body, var_name):
            continue

        # Check it actually flows into an ORM call
        orm_call = _body_uses_var_in_orm(body, var_name)
        if orm_call is None:
            # Still flag — the parameter is unbounded even if ORM call not found yet
            # but lower confidence
            findings.append(ResourceConsumptionFinding(
                rule_id="RC-001",
                cwe_id="CWE-400",
                category="unbounded_pagination",
                severity="MEDIUM",
                file_path=file_path,
                line_number=assign.start_point[0] + 1,
                endpoint=None,
                parameter=var_name,
                evidence=_node_text(assign)[:120],
                missing_guard="No upper-bound cap (min/max/if-check) on pagination parameter",
                confidence=0.6,
                layer="ast",
            ))
        else:
            findings.append(ResourceConsumptionFinding(
                rule_id="RC-001",
                cwe_id="CWE-400",
                category="unbounded_pagination",
                severity="HIGH",
                file_path=file_path,
                line_number=assign.start_point[0] + 1,
                endpoint=None,
                parameter=var_name,
                evidence=_node_text(assign)[:120],
                missing_guard="No upper-bound cap (min/max/if-check) before ORM/query usage",
                confidence=0.85,
                layer="ast",
            ))
    return findings


# ---------------------------------------------------------------------------
# JavaScript / TypeScript analysis
# ---------------------------------------------------------------------------

def _analyze_js_function(func_node: Node, file_path: str) -> list[ResourceConsumptionFinding]:
    """Detect req.query.limit → .limit(limit) without Math.min guard."""
    findings: list[ResourceConsumptionFinding] = []
    body = func_node.child_by_field_name("body")
    if body is None:
        return findings

    # Look for variable declarations where init is req.query.<param>
    var_decls = _collect_nodes(body, "variable_declarator")
    for decl in var_decls:
        name_node = decl.child_by_field_name("name")
        value_node = decl.child_by_field_name("value")
        if name_node is None or value_node is None:
            continue
        var_name = _node_text(name_node)
        if not _name_is_pagination_param(var_name):
            continue
        # Check if RHS is req.query.xxx / request.query.xxx
        chain = _get_attribute_chain(value_node)
        if len(chain) >= 2 and chain[-2].lower() in ("query", "params"):
            # Tainted. Check for Math.min guard
            if not _body_has_capping_guard(body, var_name):
                findings.append(ResourceConsumptionFinding(
                    rule_id="RC-001",
                    cwe_id="CWE-400",
                    category="unbounded_pagination",
                    severity="HIGH",
                    file_path=file_path,
                    line_number=decl.start_point[0] + 1,
                    endpoint=None,
                    parameter=var_name,
                    evidence=_node_text(decl)[:120],
                    missing_guard="No Math.min/max cap on pagination query parameter",
                    confidence=0.8,
                    layer="ast",
                ))
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class PaginationRule:
    rule_id = "RC-001"
    cwe_id = "CWE-400"
    category = "unbounded_pagination"
    severity = "HIGH"

    @staticmethod
    def analyze_python(root: Node, file_path: str) -> list[ResourceConsumptionFinding]:
        """Analyze a parsed Python AST root node."""
        findings: list[ResourceConsumptionFinding] = []
        func_nodes = _collect_nodes(root, "function_definition")
        for fn in func_nodes:
            findings.extend(_analyze_python_function(fn, file_path))
        return findings

    @staticmethod
    def analyze_javascript(root: Node, file_path: str) -> list[ResourceConsumptionFinding]:
        """Analyze a parsed JavaScript/TypeScript AST root node."""
        findings: list[ResourceConsumptionFinding] = []
        for fn_type in ("function_declaration", "arrow_function", "function_expression"):
            for fn in _collect_nodes(root, fn_type):
                findings.extend(_analyze_js_function(fn, file_path))
        return findings
