"""
RC-005 — Loop on User-Controlled Input (Missing Bound Validation)

Detects for/while loops that iterate over a collection that originates from
request body/params WITHOUT a preceding length/count guard.

Taint model (simplified, intra-procedural):
  Source: request.json.get('items') / request.json['items'] /
          request.body / req.body.xxx
  Sink:   for item in <tainted_var>
  Guard:  len(<var>) > MAX / len(<var>) < MAX / if len(<var>)

Python and JavaScript supported.
"""

from __future__ import annotations

from tree_sitter import Node

from src.core.api4_resource_consumption.models import ResourceConsumptionFinding

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Request-body source attribute chains (Python)
PY_REQUEST_BODY_SOURCES = {
    ("request", "json", "get"),
    ("request", "json"),
    ("request", "get_json"),
    ("request", "data"),
    ("request", "form", "get"),
    ("request", "form"),
}

# Keywords that indicate a len-based guard
LEN_GUARD_KEYWORDS = ("len(", "length", ".size", "count(", "MAX_ITEMS", "max_items", "MAX_BATCH")


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


def _text_contains_len_guard(text: str) -> bool:
    return any(kw in text for kw in LEN_GUARD_KEYWORDS)


# ---------------------------------------------------------------------------
# Taint source detection — Python
# ---------------------------------------------------------------------------


def _is_py_request_body_source(node: Node) -> bool:
    """
    Returns True if the node is a call/subscript that reads from the request body.
    Examples:
      request.json.get('items')
      request.json['items']
      request.get_json()['items']
    """
    if node.type == "call":
        func = node.child_by_field_name("function")
        if func is None:
            return False
        chain = _get_attribute_chain(func)
        t = tuple(chain)
        if t in PY_REQUEST_BODY_SOURCES:
            return True
        if len(chain) >= 2 and chain[-1] == "get_json":
            return True
    if node.type == "subscript":
        val = node.child_by_field_name("value")
        if val is None:
            return False
        chain = _get_attribute_chain(val)
        if len(chain) >= 2 and chain[0] == "request" and "json" in chain:
            return True
        if _is_py_request_body_source(val):
            return True
    # Also direct attribute: request.json (then subscripted higher up)
    if node.type == "attribute":
        chain = _get_attribute_chain(node)
        return len(chain) >= 2 and chain[0] == "request" and chain[-1] in ("json", "data", "form")
    return False


def _collect_tainted_vars_python(body: Node) -> set[str]:
    """Return set of variable names that are tainted from request body."""
    tainted: set[str] = set()
    assignments = _collect_nodes(body, "assignment")
    for assign in assignments:
        lhs = assign.child_by_field_name("left")
        rhs = assign.child_by_field_name("right")
        if lhs is None or rhs is None:
            continue
        if lhs.type != "identifier":
            continue
        # Check if RHS is or contains a request body source
        if _is_py_request_body_source(rhs):
            tainted.add(_node_text(lhs))
            continue
        # Indirect: items = request.json.get('items', [])
        for sub_call in _collect_nodes(rhs, "call"):
            if _is_py_request_body_source(sub_call):
                tainted.add(_node_text(lhs))
                break
        for sub_sub in _collect_nodes(rhs, "subscript"):
            if _is_py_request_body_source(sub_sub):
                tainted.add(_node_text(lhs))
                break
    return tainted


# ---------------------------------------------------------------------------
# Python analysis
# ---------------------------------------------------------------------------


def _analyze_python_function(func_node: Node, file_path: str) -> list[ResourceConsumptionFinding]:
    findings: list[ResourceConsumptionFinding] = []
    body = func_node.child_by_field_name("body")
    if body is None:
        return findings

    tainted = _collect_tainted_vars_python(body)
    if not tainted:
        return findings

    body_text = _node_text(body)

    # Walk for_statement nodes
    for for_node in _collect_nodes(body, "for_statement"):
        iterable = for_node.child_by_field_name("right")  # Python: 'right' is iterable
        if iterable is None:
            # Try alternate field name
            children = [
                c for c in for_node.children if c.type not in ("for", "in", ":", "identifier")
            ]
            if len(children) >= 1:
                iterable = children[-1]
        if iterable is None:
            continue
        iter_name = _node_text(iterable).strip()
        if iter_name not in tainted:
            # Also check if iterating over tainted[...] or call(tainted)
            if not any(t in iter_name for t in tainted):
                continue

        # Found a loop on a tainted variable — check for len guard BEFORE the loop
        # Approximate: check if body_text before loop start has len guard
        pre_loop_text = body_text[: for_node.start_byte - body.start_byte]
        if _text_contains_len_guard(pre_loop_text) or any(
            t in pre_loop_text and ("len(" in pre_loop_text or "MAX" in pre_loop_text)
            for t in tainted
        ):
            continue

        findings.append(
            ResourceConsumptionFinding(
                rule_id="RC-005",
                cwe_id="CWE-400",
                category="loop_on_user_input",
                severity="HIGH",
                file_path=file_path,
                line_number=for_node.start_point[0] + 1,
                endpoint=None,
                parameter=iter_name,
                evidence=_node_text(for_node)[:120],
                missing_guard="No len() / count check before iterating over user-supplied collection",
                confidence=0.75,
                layer="ast",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# JavaScript analysis — taint from req.body / req.query
# ---------------------------------------------------------------------------


def _is_js_request_body(node: Node) -> bool:
    chain = _get_attribute_chain(node)
    if not chain:
        return False
    return chain[0] in ("req", "request") and len(chain) >= 2 and chain[1] in ("body", "json")


def _collect_tainted_vars_js(func_body: Node) -> set[str]:
    tainted: set[str] = set()
    for decl in _collect_nodes(func_body, "variable_declarator"):
        name_node = decl.child_by_field_name("name")
        value_node = decl.child_by_field_name("value")
        if name_node is None or value_node is None:
            continue
        if _is_js_request_body(value_node):
            tainted.add(_node_text(name_node))
        # Also member access chains: req.body.items
        for sub_attr in _collect_nodes(value_node, "member_expression"):
            if _is_js_request_body(sub_attr):
                tainted.add(_node_text(name_node))
                break
    return tainted


def _analyze_js_function(func_node: Node, file_path: str) -> list[ResourceConsumptionFinding]:
    findings: list[ResourceConsumptionFinding] = []
    body = func_node.child_by_field_name("body")
    if body is None:
        return findings

    tainted = _collect_tainted_vars_js(body)
    if not tainted:
        return findings

    body_text = _node_text(body)

    for for_node in _collect_nodes(body, "for_of_statement"):
        # for (const item of <iterable>)
        right_children = [
            c
            for c in for_node.children
            if c.type not in ("for", "of", "const", "let", "var", "(", ")", "identifier")
        ]
        if not right_children:
            continue
        iterable_node = right_children[0]
        iter_name = _node_text(iterable_node).strip()
        if not any(t in iter_name for t in tainted):
            continue
        pre_loop_text = body_text[: for_node.start_byte - body.start_byte]
        if _text_contains_len_guard(pre_loop_text):
            continue
        findings.append(
            ResourceConsumptionFinding(
                rule_id="RC-005",
                cwe_id="CWE-400",
                category="loop_on_user_input",
                severity="HIGH",
                file_path=file_path,
                line_number=for_node.start_point[0] + 1,
                endpoint=None,
                parameter=iter_name,
                evidence=_node_text(for_node)[:120],
                missing_guard="No .length check before iterating over user-supplied array",
                confidence=0.75,
                layer="ast",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class LoopBoundsRule:
    rule_id = "RC-005"
    cwe_id = "CWE-400"
    category = "loop_on_user_input"
    severity = "HIGH"

    @staticmethod
    def analyze_python(root: Node, file_path: str) -> list[ResourceConsumptionFinding]:
        findings: list[ResourceConsumptionFinding] = []
        for fn in _collect_nodes(root, "function_definition"):
            findings.extend(_analyze_python_function(fn, file_path))
        return findings

    @staticmethod
    def analyze_javascript(root: Node, file_path: str) -> list[ResourceConsumptionFinding]:
        findings: list[ResourceConsumptionFinding] = []
        for fn_type in ("function_declaration", "arrow_function", "function_expression"):
            for fn in _collect_nodes(root, fn_type):
                findings.extend(_analyze_js_function(fn, file_path))
        return findings
