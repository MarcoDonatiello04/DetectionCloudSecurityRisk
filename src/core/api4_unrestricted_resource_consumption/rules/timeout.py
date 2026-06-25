"""
RC-003 — Missing HTTP Timeout

Detects outbound HTTP calls made without a `timeout` parameter.
A worker blocked on a hung connection is a classic resource exhaustion vector.

Supported libraries:
  Python: requests, httpx, urllib (via urllib.request.urlopen)
  JavaScript: axios, fetch, node-fetch, got

Confidence escalation: 0.95 if the URL or function name contains a paid-service
keyword (sms, twilio, sendgrid, stripe, mailgun, vonage, otp, notify, ses).
"""

from __future__ import annotations

from tree_sitter import Node

from src.core.api4_unrestricted_resource_consumption.models import ResourceConsumptionFinding


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Python HTTP caller objects and their attribute methods
PY_HTTP_CALLERS = {
    "requests": {"get", "post", "put", "patch", "delete", "head", "options", "request"},
    "httpx": {"get", "post", "put", "patch", "delete", "head", "options", "request", "stream"},
    "urllib": {"urlopen"},
    "http": {"request"},
}

# Flat set of (object, method) pairs for fast lookup
_PY_CALLER_PAIRS: set[tuple[str, str]] = {
    (obj, method) for obj, methods in PY_HTTP_CALLERS.items() for method in methods
}

# JavaScript HTTP callers (function / method names)
JS_HTTP_CALLERS = {"fetch", "axios", "got", "superagent"}
JS_AXIOS_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "request"}

# Keywords that indicate a paid-service call (higher confidence)
PAID_SERVICE_KEYWORDS = {
    "sms", "twilio", "sendgrid", "stripe", "mailgun", "vonage", "otp",
    "notify", "notification", "ses", "email", "whatsapp", "telegram",
}

# Context managers that provide timeout (Python only)
TIMEOUT_CONTEXT_MANAGERS = {"anyio.fail_after", "asyncio.timeout", "trio.fail_after"}


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


def _call_is_http(call_node: Node) -> bool:
    """Returns True if this call is a known outbound HTTP call."""
    func = call_node.child_by_field_name("function")
    if func is None:
        return False
    chain = _get_attribute_chain(func)
    if len(chain) >= 2:
        pair = (chain[-2], chain[-1])
        if pair in _PY_CALLER_PAIRS:
            return True
    return False


def _call_has_timeout_kwarg(call_node: Node) -> bool:
    """Returns True if the call has a keyword argument named 'timeout'."""
    args = call_node.child_by_field_name("arguments")
    if args is None:
        return False
    for child in args.children:
        if child.type == "keyword_argument":
            name = child.child_by_field_name("name")
            if name and _node_text(name) == "timeout":
                return True
    return False


def _is_inside_timeout_ctx(call_node: Node, root: Node) -> bool:
    """
    Returns True if the call is lexically inside a context manager that provides
    a timeout (anyio.fail_after, asyncio.timeout, trio.fail_after).
    """
    # Walk up the tree by collecting all with_statement nodes that contain the call
    with_stmts = _collect_nodes(root, "with_statement")
    for ws in with_stmts:
        ws_text = _node_text(ws)
        if any(cm in ws_text for cm in TIMEOUT_CONTEXT_MANAGERS):
            # Check if our call_node is inside this with_statement
            if call_node.start_byte >= ws.start_byte and call_node.end_byte <= ws.end_byte:
                return True
    return False


def _paid_service_confidence(call_node: Node) -> float:
    """Returns elevated confidence if the call references a paid-service endpoint."""
    call_text = _node_text(call_node).lower()
    for kw in PAID_SERVICE_KEYWORDS:
        if kw in call_text:
            return 0.95
    return 0.7


# ---------------------------------------------------------------------------
# Python analysis
# ---------------------------------------------------------------------------

def _analyze_python(root: Node, file_path: str) -> list[ResourceConsumptionFinding]:
    findings: list[ResourceConsumptionFinding] = []
    calls = _collect_nodes(root, "call")
    for call in calls:
        if not _call_is_http(call):
            continue
        if _call_has_timeout_kwarg(call):
            continue
        if _is_inside_timeout_ctx(call, root):
            continue
        confidence = _paid_service_confidence(call)
        findings.append(ResourceConsumptionFinding(
            rule_id="RC-003",
            cwe_id="CWE-400",
            category="missing_http_timeout",
            severity="HIGH",
            file_path=file_path,
            line_number=call.start_point[0] + 1,
            endpoint=None,
            parameter=None,
            evidence=_node_text(call)[:120],
            missing_guard="No timeout= keyword argument on outbound HTTP call",
            confidence=confidence,
            layer="ast",
        ))
    return findings


# ---------------------------------------------------------------------------
# JavaScript analysis
# ---------------------------------------------------------------------------

def _js_call_is_http(call_node: Node) -> bool:
    """Detect axios.get/post/... or fetch() calls."""
    func = call_node.child_by_field_name("function")
    if func is None:
        return False
    chain = _get_attribute_chain(func)
    if not chain:
        return False
    # fetch(url)
    if chain[-1] == "fetch":
        return True
    # axios.get / axios.post / etc.
    if len(chain) >= 2 and chain[-2] == "axios" and chain[-1] in JS_AXIOS_METHODS:
        return True
    # axios(url, {...})
    if chain[-1] == "axios":
        return True
    # got(url) / got.get / superagent.get
    if chain[0] in ("got", "superagent"):
        return True
    return False


def _js_call_has_timeout(call_node: Node) -> bool:
    """Check if the options object argument contains a 'timeout' property."""
    args = call_node.child_by_field_name("arguments")
    if args is None:
        return False
    args_text = _node_text(args)
    return "timeout" in args_text


def _analyze_javascript(root: Node, file_path: str) -> list[ResourceConsumptionFinding]:
    findings: list[ResourceConsumptionFinding] = []
    for call_type in ("call_expression", "await_expression"):
        nodes = _collect_nodes(root, call_type)
        for node in nodes:
            # Unwrap await if needed
            call = node
            if node.type == "await_expression":
                call_candidates = _collect_nodes(node, "call_expression")
                if not call_candidates:
                    continue
                call = call_candidates[0]

            if not _js_call_is_http(call):
                continue
            if _js_call_has_timeout(call):
                continue
            confidence = _paid_service_confidence(call)
            findings.append(ResourceConsumptionFinding(
                rule_id="RC-003",
                cwe_id="CWE-400",
                category="missing_http_timeout",
                severity="HIGH",
                file_path=file_path,
                line_number=call.start_point[0] + 1,
                endpoint=None,
                parameter=None,
                evidence=_node_text(call)[:120],
                missing_guard="No timeout property in HTTP call options",
                confidence=confidence,
                layer="ast",
            ))
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class TimeoutRule:
    rule_id = "RC-003"
    cwe_id = "CWE-400"
    category = "missing_http_timeout"
    severity = "HIGH"

    @staticmethod
    def analyze_python(root: Node, file_path: str) -> list[ResourceConsumptionFinding]:
        return _analyze_python(root, file_path)

    @staticmethod
    def analyze_javascript(root: Node, file_path: str) -> list[ResourceConsumptionFinding]:
        return _analyze_javascript(root, file_path)
