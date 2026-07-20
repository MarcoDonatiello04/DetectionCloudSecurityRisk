"""
RC-002 — Missing Upload Size Limit

Detects route handlers that accept file uploads without an explicit size check
BEFORE the file is read or saved.

Supported patterns:
  - Flask: request.files['x'] without app.config['MAX_CONTENT_LENGTH'] check
  - FastAPI: UploadFile param without file.size > MAX check
  - Express/Multer (JS): multer({ dest: '...' }) without limits.fileSize
"""

from __future__ import annotations

from tree_sitter import Node

from src.core.api4_resource_consumption.models import ResourceConsumptionFinding

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


def _func_text(node: Node) -> str:
    return _node_text(node)


# ---------------------------------------------------------------------------
# Flask / Python — request.files detection
# ---------------------------------------------------------------------------


def _body_accesses_request_files(body: Node) -> Node | None:
    """Returns the node where request.files is accessed, if any."""
    subscripts = _collect_nodes(body, "subscript")
    for sub in subscripts:
        val = sub.child_by_field_name("value")
        if val is None:
            continue
        chain = _get_attribute_chain(val)
        if chain and chain[-1] == "files" and chain[0] == "request":
            return sub
    # Also attribute access: request.files (without subscript)
    for attr in _collect_nodes(body, "attribute"):
        chain = _get_attribute_chain(attr)
        if chain == ["request", "files"]:
            return attr
    return None


def _body_has_size_check(body: Node) -> bool:
    """
    Returns True if the function body contains any of:
    - file.size / file.content_length comparison
    - len(content) check
    - request.content_length check
    - MAX_CONTENT_LENGTH reference
    """
    body_text = _node_text(body)
    size_keywords = (
        "content_length",
        "MAX_CONTENT_LENGTH",
        "file.size",
        "file.content_length",
        "max_size",
        "MAX_SIZE",
        "len(content",
        "len(data",
    )
    for kw in size_keywords:
        if kw in body_text:
            return True

    # Check comparisons involving 'size'
    comparisons = _collect_nodes(body, "comparison_operator")
    for comp in comparisons:
        comp_text = _node_text(comp).lower()
        if "size" in comp_text or "length" in comp_text:
            return True

    return False


def _analyze_python_upload_function(
    func_node: Node, file_path: str
) -> ResourceConsumptionFinding | None:
    body = func_node.child_by_field_name("body")
    if body is None:
        return None

    file_access = _body_accesses_request_files(body)
    if file_access is None:
        # Also check FastAPI UploadFile in params
        params = func_node.child_by_field_name("parameters")
        if params is None:
            return None
        param_text = _node_text(params)
        if "UploadFile" not in param_text:
            return None
        # Check if body has a size guard before read()
        reads = _collect_nodes(body, "call")
        for call in reads:
            func = call.child_by_field_name("function")
            if func and "read" in _node_text(func):
                # Found a read() call — check if size guard exists before it
                if not _body_has_size_check(body):
                    name_node = func_node.child_by_field_name("name")
                    return ResourceConsumptionFinding(
                        rule_id="RC-002",
                        cwe_id="CWE-400",
                        category="missing_upload_size_limit",
                        severity="HIGH",
                        file_path=file_path,
                        line_number=call.start_point[0] + 1,
                        endpoint=None,
                        parameter="file",
                        evidence=f"UploadFile handler reads without size check: {_node_text(call)[:80]}",
                        missing_guard="No file.size > MAX_SIZE check before file.read()",
                        confidence=0.85,
                        layer="ast",
                    )
        return None

    # Flask-style: request.files used
    if not _body_has_size_check(body):
        name_node = func_node.child_by_field_name("name")
        fn_name = _node_text(name_node) if name_node else "unknown"
        return ResourceConsumptionFinding(
            rule_id="RC-002",
            cwe_id="CWE-400",
            category="missing_upload_size_limit",
            severity="HIGH",
            file_path=file_path,
            line_number=file_access.start_point[0] + 1,
            endpoint=None,
            parameter="file",
            evidence=f"{fn_name}: accesses request.files without size validation",
            missing_guard="No content_length / MAX_CONTENT_LENGTH guard before file access",
            confidence=0.8,
            layer="ast",
        )
    return None


# ---------------------------------------------------------------------------
# JavaScript — Multer without limits
# ---------------------------------------------------------------------------


def _analyze_js_multer(root: Node, file_path: str) -> list[ResourceConsumptionFinding]:
    """
    Detects multer({ dest: '...' }) without limits: { fileSize: ... }.
    """
    findings: list[ResourceConsumptionFinding] = []
    calls = _collect_nodes(root, "call_expression")
    for call in calls:
        func = call.child_by_field_name("function")
        if func is None:
            continue
        if _node_text(func) != "multer":
            continue
        # Found a multer() call — inspect the argument object
        args = call.child_by_field_name("arguments")
        if args is None:
            # multer() with no args — definitely no limits
            findings.append(
                ResourceConsumptionFinding(
                    rule_id="RC-002",
                    cwe_id="CWE-400",
                    category="missing_upload_size_limit",
                    severity="HIGH",
                    file_path=file_path,
                    line_number=call.start_point[0] + 1,
                    endpoint=None,
                    parameter="file",
                    evidence="multer() called without any configuration",
                    missing_guard="multer config missing limits: { fileSize: ... }",
                    confidence=0.9,
                    layer="ast",
                )
            )
            continue
        args_text = _node_text(args)
        if "limits" not in args_text and "fileSize" not in args_text:
            findings.append(
                ResourceConsumptionFinding(
                    rule_id="RC-002",
                    cwe_id="CWE-400",
                    category="missing_upload_size_limit",
                    severity="HIGH",
                    file_path=file_path,
                    line_number=call.start_point[0] + 1,
                    endpoint=None,
                    parameter="file",
                    evidence=f"multer config: {args_text[:100]}",
                    missing_guard="multer config missing limits: { fileSize: ... }",
                    confidence=0.9,
                    layer="ast",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class UploadRule:
    rule_id = "RC-002"
    cwe_id = "CWE-400"
    category = "missing_upload_size_limit"
    severity = "HIGH"

    @staticmethod
    def analyze_python(root: Node, file_path: str) -> list[ResourceConsumptionFinding]:
        findings: list[ResourceConsumptionFinding] = []
        for fn_type in ("function_definition",):
            for fn in _collect_nodes(root, fn_type):
                finding = _analyze_python_upload_function(fn, file_path)
                if finding:
                    findings.append(finding)
        return findings

    @staticmethod
    def analyze_javascript(root: Node, file_path: str) -> list[ResourceConsumptionFinding]:
        return _analyze_js_multer(root, file_path)
