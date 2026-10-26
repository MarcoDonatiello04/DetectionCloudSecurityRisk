"""
Layer 3 — OpenAPI Spec Enrichment for API4:2023 Unrestricted Resource Consumption.

Analyzes a pre-parsed OpenAPI 3.x / Swagger 2.0 dict for missing resource
consumption constraints in the API contract. This layer is OPTIONAL: if no
spec is passed to detector.analyze(), it is silently skipped.

Rules implemented:
  RC-010 — Pagination parameter without maximum constraint
  RC-011 — File upload endpoint without maxLength / maxItems
  RC-012 — "Expensive" endpoint without documented rate protection
  RC-013 — Batch / Array payload without maxItems constraint

Enrichment:
  If enrich_spec=True, each finding is also written into the spec dict
  under x-security-analysis extension fields (legal per OpenAPI spec).

Entry point: analyze_openapi(spec, enrich_spec=False) -> list[ResourceConsumptionFinding]
"""

from __future__ import annotations

import logging
import re
from typing import Any

from src.core.api4_resource_consumption.models import ResourceConsumptionFinding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Pagination-related parameter names (case-insensitive)
PAGINATION_PARAM_NAMES = {
    "limit",
    "page_size",
    "per_page",
    "count",
    "size",
    "max",
    "take",
    "top",
    "n",
    "offset",
    "skip",
}

# Maximum value considered "sane" — above this we still warn but lower severity
SANE_MAX_LIMIT = 1000

# HTTP methods to inspect
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}

# Content types that imply file upload
UPLOAD_CONTENT_TYPES = {"multipart/form-data", "application/octet-stream"}

# Patterns that identify "expensive" endpoints. Each keyword has a kind:
#   "action"   — names the costly work itself (export, transcode, predict...): the
#                endpoint is expensive whatever the HTTP method.
#   "resource" — names a resource whose *creation* is costly (a payment, an SMS,
#                a report): only POST triggers the cost. Reading, updating or
#                deleting an existing invoice or notification is plain CRUD.
# Matching is on whole words (path segments, operationId, summary, description),
# never on substrings, so "ai" does not match "email" or "detail".
EXPENSIVE_PATTERNS: list[tuple[str, str, str]] = [
    ("sms", "SMS provider call", "resource"),
    ("otp", "OTP / SMS provider call", "resource"),
    ("verify phone", "SMS verification", "action"),
    ("email", "Email provider call", "resource"),
    ("notify", "Notification provider call", "action"),
    ("notification", "Notification provider call", "resource"),
    ("export", "CPU/bandwidth intensive export", "action"),
    ("download", "Bandwidth intensive download", "action"),
    ("report", "CPU/bandwidth intensive report", "resource"),
    ("thumbnail", "CPU-intensive image processing", "action"),
    ("resize", "CPU-intensive image processing", "action"),
    ("transcode", "CPU-intensive media processing", "action"),
    ("charge", "Financial transaction", "resource"),
    ("payment", "Financial transaction", "resource"),
    ("invoice", "Financial transaction", "resource"),
    ("ai", "AI inference (expensive)", "resource"),
    ("ml", "ML inference (expensive)", "resource"),
    ("predict", "ML inference (expensive)", "action"),
]

# A "resource" keyword is costly only when the operation triggers work instead of
# manipulating a stored item:
#   - POST (creates the resource: issues the invoice, sends the SMS);
#   - PUT/PATCH on a collection-level path (PUT /sms has no item to update);
#   - any method whose path/operationId/summary carries a trigger verb
#     (PUT /invoices/{id}/send, operationId "resendOtp").
COST_TRIGGERING_METHODS = {"POST"}
COLLECTION_TRIGGERING_METHODS = {"PUT", "PATCH"}
TRIGGER_VERBS = {
    "send",
    "resend",
    "generate",
    "regenerate",
    "issue",
    "dispatch",
    "deliver",
    "process",
    "run",
    "execute",
    "trigger",
    "render",
    "convert",
}

# Structural signals: they reveal a costly endpoint even when its name is neutral.
# Request fields — each entry lists groups of field words; the signal fires when
# at least one word of every group is present among the operation's input fields.
REQUEST_FIELD_SIGNALS: list[tuple[tuple[frozenset[str], ...], str]] = [
    (
        (frozenset({"phone", "msisdn"}), frozenset({"message", "text", "body", "sms", "template"})),
        "SMS provider call (phone + message fields)",
    ),
    (
        (frozenset({"to", "recipient", "recipients"}), frozenset({"subject"})),
        "Email provider call (recipient + subject fields)",
    ),
    ((frozenset({"amount"}), frozenset({"currency"})), "Financial transaction (amount + currency)"),
    ((frozenset({"cvc", "cvv"}),), "Financial transaction (card fields)"),
    ((frozenset({"prompt"}),), "AI inference (prompt field)"),
    ((frozenset({"max tokens", "temperature"}),), "AI inference (generation parameters)"),
]
# Field words this short match only a whole field name ("to"), never a word of it
# ("path_to_file").
MIN_FIELD_WORD_LENGTH = 3

# Responses — media types produced by generation or bulk transfer, and 202 Accepted
# (work queued for asynchronous processing).
GENERATED_MEDIA_TYPES: dict[str, str] = {
    "application/pdf": "Generated PDF document",
    "text/csv": "Generated CSV export",
    "application/zip": "Generated archive",
    "application/octet-stream": "Bandwidth intensive binary download",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "Generated spreadsheet",
    "application/vnd.ms-excel": "Generated spreadsheet",
    "video/": "Media delivery / processing",
    "audio/": "Media delivery / processing",
}

# Keywords in description/summary that imply documented rate limiting
THROTTLE_KEYWORDS = {
    "rate limit",
    "rate-limit",
    "throttle",
    "throttling",
    "per hour",
    "per minute",
    "per day",
    "requests/hour",
    "calls per",
    "max requests",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    *,
    rule_id: str,
    cwe_id: str,
    category: str,
    severity: str,
    file_path: str,
    line_number: int | None,
    endpoint: str | None,
    parameter: str | None,
    evidence: str,
    missing_guard: str,
    confidence: float,
) -> ResourceConsumptionFinding:
    return ResourceConsumptionFinding(
        rule_id=rule_id,
        cwe_id=cwe_id,
        category=category,
        severity=severity,
        file_path=file_path,
        line_number=line_number,
        endpoint=endpoint,
        parameter=parameter,
        evidence=evidence,
        missing_guard=missing_guard,
        confidence=confidence,
        layer="openapi",
    )


def detect_spec_version(spec: dict) -> str:
    """
    Returns the spec version string.
    Raises ValueError for unrecognized formats.
    """
    if "openapi" in spec:
        return spec["openapi"]  # "3.0.x" or "3.1.x"
    if "swagger" in spec:
        return spec["swagger"]  # "2.0"
    raise ValueError("Unrecognized spec format — missing 'openapi' or 'swagger' key")


def _get_paths(spec: dict) -> dict:
    return spec.get("paths") or {}


def _get_global_security(spec: dict) -> list:
    return spec.get("security") or []


def _iter_operations(paths: dict):
    """
    Yields (path_str, method, operation_dict) for every operation in the spec.
    """
    for path_str, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method in HTTP_METHODS:
            operation = path_item.get(method)
            if isinstance(operation, dict):
                yield path_str, method.upper(), operation


def _resolve_schema(schema: Any, spec: dict) -> dict:
    """
    Resolve a $ref in a schema if present (shallow, one level).
    Returns the resolved schema dict or the original if no $ref.
    """
    if not isinstance(schema, dict):
        return {}
    ref = schema.get("$ref")
    if ref and isinstance(ref, str) and ref.startswith("#/"):
        parts = ref.lstrip("#/").split("/")
        node: Any = spec
        for part in parts:
            if isinstance(node, dict):
                node = node.get(part, {})
            else:
                return {}
        return node if isinstance(node, dict) else {}
    return schema


# ---------------------------------------------------------------------------
# RC-010 — Pagination parameter without maximum
# ---------------------------------------------------------------------------


def _check_schema_for_max(
    schema: dict,
    param_name: str,
    path_str: str,
    method: str,
    source: str,  # "parameter" or "requestBody"
) -> ResourceConsumptionFinding | None:
    """
    Check a single schema dict for missing maximum constraint on a pagination field.
    """
    maximum = schema.get("maximum")
    if maximum is None:
        return _make_finding(
            rule_id="RC-010",
            cwe_id="CWE-400",
            category="openapi_no_max_constraint",
            severity="HIGH",
            file_path="openapi_spec",
            line_number=None,
            endpoint=f"{method} {path_str}",
            parameter=param_name,
            evidence=f"{method} {path_str} — {source} '{param_name}' has no maximum constraint",
            missing_guard="Add maximum: <int> to the parameter schema (e.g. maximum: 100)",
            confidence=0.9,
        )
    if isinstance(maximum, (int, float)) and maximum > SANE_MAX_LIMIT:
        return _make_finding(
            rule_id="RC-010",
            cwe_id="CWE-400",
            category="openapi_no_max_constraint",
            severity="LOW",
            file_path="openapi_spec",
            line_number=None,
            endpoint=f"{method} {path_str}",
            parameter=param_name,
            evidence=f"{method} {path_str} — '{param_name}' maximum={maximum} exceeds {SANE_MAX_LIMIT}",
            missing_guard=f"Reduce maximum to a business-appropriate limit (≤ {SANE_MAX_LIMIT})",
            confidence=0.6,
        )
    return None


def _analyze_rc010(paths: dict, spec: dict) -> list[ResourceConsumptionFinding]:
    findings: list[ResourceConsumptionFinding] = []

    for path_str, method, operation in _iter_operations(paths):
        # 1. Check query/path parameters
        parameters = operation.get("parameters") or []
        for param in parameters:
            if not isinstance(param, dict):
                continue
            param = _resolve_schema(param, spec)
            name = str(param.get("name", "")).lower()
            if name not in PAGINATION_PARAM_NAMES:
                continue
            # OpenAPI 3: schema is nested under 'schema'
            schema = param.get("schema") or {}
            schema = _resolve_schema(schema, spec)
            if not schema:
                # Swagger 2: schema fields are inline on the parameter
                schema = param
            finding = _check_schema_for_max(schema, name, path_str, method, "parameter")
            if finding:
                findings.append(finding)

        # 2. Check requestBody with application/json (may contain pagination props)
        request_body = operation.get("requestBody") or {}
        content = request_body.get("content") or {}
        json_content = content.get("application/json") or {}
        body_schema = _resolve_schema(json_content.get("schema") or {}, spec)
        properties = body_schema.get("properties") or {}
        for prop_name, prop_schema in properties.items():
            if prop_name.lower() not in PAGINATION_PARAM_NAMES:
                continue
            prop_schema = _resolve_schema(prop_schema, spec)
            finding = _check_schema_for_max(prop_schema, prop_name, path_str, method, "requestBody")
            if finding:
                findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# RC-011 — File upload without maxLength / maxItems
# ---------------------------------------------------------------------------


def _analyze_rc011(paths: dict, spec: dict) -> list[ResourceConsumptionFinding]:
    findings: list[ResourceConsumptionFinding] = []

    for path_str, method, operation in _iter_operations(paths):
        request_body = operation.get("requestBody") or {}
        content = request_body.get("content") or {}

        for content_type, media_type_obj in content.items():
            if not any(ct in content_type.lower() for ct in UPLOAD_CONTENT_TYPES):
                continue

            if not isinstance(media_type_obj, dict):
                continue

            schema = _resolve_schema(media_type_obj.get("schema") or {}, spec)
            properties = schema.get("properties") or {}

            # Check each property for binary fields without maxLength
            for prop_name, prop_schema in properties.items():
                prop_schema = _resolve_schema(prop_schema, spec)
                prop_type = prop_schema.get("type", "")
                prop_format = prop_schema.get("format", "")

                if prop_type == "string" and prop_format == "binary":
                    if "maxLength" not in prop_schema:
                        findings.append(
                            _make_finding(
                                rule_id="RC-011",
                                cwe_id="CWE-400",
                                category="openapi_no_upload_size_limit",
                                severity="HIGH",
                                file_path="openapi_spec",
                                line_number=None,
                                endpoint=f"{method} {path_str}",
                                parameter=prop_name,
                                evidence=(
                                    f"{method} {path_str} — upload field '{prop_name}' "
                                    f"(format: binary) has no maxLength"
                                ),
                                missing_guard="Add maxLength: <bytes> to the binary property schema",
                                confidence=0.9,
                            )
                        )

                elif prop_type == "array" and "maxItems" not in prop_schema:
                    findings.append(
                        _make_finding(
                            rule_id="RC-011",
                            cwe_id="CWE-400",
                            category="openapi_no_upload_size_limit",
                            severity="MEDIUM",
                            file_path="openapi_spec",
                            line_number=None,
                            endpoint=f"{method} {path_str}",
                            parameter=prop_name,
                            evidence=(
                                f"{method} {path_str} — array field '{prop_name}' "
                                f"has no maxItems constraint"
                            ),
                            missing_guard="Add maxItems: <int> to the array property schema",
                            confidence=0.8,
                        )
                    )

            # Also check top-level schema if it is array
            if schema.get("type") == "array" and "maxItems" not in schema:
                findings.append(
                    _make_finding(
                        rule_id="RC-011",
                        cwe_id="CWE-400",
                        category="openapi_no_upload_size_limit",
                        severity="MEDIUM",
                        file_path="openapi_spec",
                        line_number=None,
                        endpoint=f"{method} {path_str}",
                        parameter=None,
                        evidence=f"{method} {path_str} — top-level array schema has no maxItems",
                        missing_guard="Add maxItems: <int> to the array schema",
                        confidence=0.75,
                    )
                )

    return findings


# ---------------------------------------------------------------------------
# RC-012 — Expensive endpoint without documented protection
# ---------------------------------------------------------------------------


def _words(text: str) -> str:
    """
    Normalizes free text or a path into space-separated lowercase words:
    splits camelCase, drops path parameters ({id}) and every non-alphanumeric
    separator, so keywords can be matched as whole words.
    """
    text = re.sub(r"\{[^}]*\}", " ", text)
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    return " ".join(re.findall(r"[a-z0-9]+", text.lower()))


def _triggers_cost(path_str: str, method: str, trigger_text: str) -> bool:
    """
    True when the operation starts work rather than reading, updating or
    deleting a stored item (see COST_TRIGGERING_METHODS / TRIGGER_VERBS).
    """
    if method in COST_TRIGGERING_METHODS:
        return True
    last_segment = path_str.rstrip("/").rsplit("/", 1)[-1]
    if method in COLLECTION_TRIGGERING_METHODS and not last_segment.startswith("{"):
        return True
    return any(word in TRIGGER_VERBS for word in trigger_text.split())


def _path_is_expensive(path_str: str, operation: dict, method: str = "POST") -> str | None:
    """
    Returns the matched pattern name if the endpoint is considered expensive.
    Checks path + operationId + summary + description as whole words (plural
    forms included). A "resource" keyword counts only when the operation
    triggers work: GET /invoices/{id} is a read, POST /invoices issues one.
    """
    naming = " ".join(
        _words(str(part))
        for part in (path_str, operation.get("operationId", ""), operation.get("summary", ""))
    )
    combined = f"{naming} {_words(str(operation.get('description', '')))}"
    triggers_cost = _triggers_cost(path_str, method.upper(), naming)

    for pattern, _, kind in EXPENSIVE_PATTERNS:
        if kind == "resource" and not triggers_cost:
            continue
        if re.search(rf"\b{re.escape(pattern)}(?:e?s)?\b", combined):
            return pattern
    return None


def _collect_schema_fields(schema: Any, spec: dict, fields: set[str], depth: int = 0) -> None:
    """Adds the normalized property names of a schema (nested objects and array items)."""
    schema = _resolve_schema(schema, spec)
    if depth > 4 or not schema:
        return
    for prop_name, prop_schema in (schema.get("properties") or {}).items():
        fields.add(_words(str(prop_name)))
        _collect_schema_fields(prop_schema, spec, fields, depth + 1)
    if "items" in schema:
        _collect_schema_fields(schema["items"], spec, fields, depth + 1)
    for combinator in ("allOf", "oneOf", "anyOf"):
        for sub in schema.get(combinator) or []:
            _collect_schema_fields(sub, spec, fields, depth + 1)


def _input_fields(operation: dict, spec: dict) -> set[str]:
    """Normalized names of every input the operation accepts (parameters + body)."""
    fields: set[str] = set()
    for param in operation.get("parameters") or []:
        param = _resolve_schema(param, spec)
        if param.get("name"):
            fields.add(_words(str(param["name"])))
        if param.get("in") == "body":  # Swagger 2.0 body parameter
            _collect_schema_fields(param.get("schema"), spec, fields)
    request_body = _resolve_schema(operation.get("requestBody") or {}, spec)
    for media_type_obj in (request_body.get("content") or {}).values():
        if isinstance(media_type_obj, dict):
            _collect_schema_fields(media_type_obj.get("schema"), spec, fields)
    return fields


def _structural_cost_signal(operation: dict, spec: dict) -> tuple[str, str, float] | None:
    """
    Looks for evidence of cost in the contract structure rather than in names:
    request fields that betray the provider call, 202 Accepted, generated media
    types. Returns (reason, severity, confidence) or None.
    """
    fields = _input_fields(operation, spec)
    field_words = fields | {
        word for field in fields for word in field.split() if len(word) >= MIN_FIELD_WORD_LENGTH
    }
    for groups, reason in REQUEST_FIELD_SIGNALS:
        if all(group & field_words for group in groups):
            return reason, "HIGH", 0.8

    responses = operation.get("responses") or {}
    if "202" in {str(code) for code in responses}:
        return "Asynchronous processing (202 Accepted)", "MEDIUM", 0.7
    for code, response in responses.items():
        if not str(code).startswith("2"):
            continue
        response = _resolve_schema(response, spec)
        media_types = list((response.get("content") or {}).keys())
        media_types += list(operation.get("produces") or [])  # Swagger 2.0
        for media_type in media_types:
            for prefix, reason in GENERATED_MEDIA_TYPES.items():
                if media_type.lower().startswith(prefix):
                    return f"{reason} ({media_type})", "MEDIUM", 0.7
    return None


def _has_documented_protection(operation: dict, global_security: list) -> bool:
    """
    Returns True if the operation has any of:
    1. security[] field (non-empty) at operation or global level
    2. x-rate-limit extension field
    3. Throttle keyword in description or summary
    """
    # 1. security scheme
    op_security = operation.get("security")
    if op_security is not None:
        # security: [] (empty list) means explicitly unauthenticated
        if isinstance(op_security, list) and len(op_security) > 0:
            return True
    elif global_security:
        return True

    # 2. x-rate-limit extension
    for key in operation:
        if key.lower().startswith("x-rate") or key.lower().startswith("x-throttle"):
            return True

    # 3. Throttle keyword in description/summary
    description = str(operation.get("description", "")).lower()
    summary = str(operation.get("summary", "")).lower()
    combined = description + " " + summary
    return bool(any(kw in combined for kw in THROTTLE_KEYWORDS))


def _analyze_rc012(paths: dict, spec: dict) -> list[ResourceConsumptionFinding]:
    findings: list[ResourceConsumptionFinding] = []
    global_security = _get_global_security(spec)

    for path_str, method, operation in _iter_operations(paths):
        matched_pattern = _path_is_expensive(path_str, operation, method)
        if matched_pattern:
            reason = f"matches expensive pattern '{matched_pattern}'"
            severity, confidence = "HIGH", 0.85
        else:
            signal = _structural_cost_signal(operation, spec)
            if not signal:
                continue
            reason, severity, confidence = signal
            reason = f"structural cost signal: {reason}"

        if _has_documented_protection(operation, global_security):
            continue

        findings.append(
            _make_finding(
                rule_id="RC-012",
                cwe_id="CWE-770",
                category="openapi_expensive_endpoint_unprotected",
                severity=severity,
                file_path="openapi_spec",
                line_number=None,
                endpoint=f"{method} {path_str}",
                parameter=None,
                evidence=(
                    f"{method} {path_str} — {reason} without security or rate-limit documentation"
                ),
                missing_guard=(
                    "Add security: [{scheme: []}] or x-rate-limit extension "
                    "or document throttling in description"
                ),
                confidence=confidence,
            )
        )

    return findings


# ---------------------------------------------------------------------------
# RC-013 — Batch / Array payload without maxItems constraint
# ---------------------------------------------------------------------------


def _analyze_rc013(paths: dict, spec: dict) -> list[ResourceConsumptionFinding]:
    """
    Detects endpoints accepting JSON payloads with unbounded arrays (batch requests,
    bulk operations) without maxItems constraint, creating Unrestricted Resource
    Consumption risks (DoS via massive array allocation).
    """
    findings: list[ResourceConsumptionFinding] = []

    for path_str, method, operation in _iter_operations(paths):
        request_body = operation.get("requestBody") or {}
        content = request_body.get("content") or {}

        for content_type, media_type_obj in content.items():
            if "json" not in content_type.lower():
                continue
            if not isinstance(media_type_obj, dict):
                continue

            schema = _resolve_schema(media_type_obj.get("schema") or {}, spec)
            is_batch_path = any(
                kw in path_str.lower() for kw in ("batch", "bulk", "multi", "import", "items")
            )
            sev = "HIGH" if is_batch_path else "MEDIUM"

            # 1. Top-level array: [ { ... }, { ... } ]
            if schema.get("type") == "array" and "maxItems" not in schema:
                findings.append(
                    _make_finding(
                        rule_id="RC-013",
                        cwe_id="CWE-400",
                        category="openapi_no_batch_limit",
                        severity=sev,
                        file_path="openapi_spec",
                        line_number=None,
                        endpoint=f"{method} {path_str}",
                        parameter=None,
                        evidence=f"{method} {path_str} — top-level JSON array payload has no maxItems constraint",
                        missing_guard="Add maxItems: <int> to the top-level array schema to limit batch operations",
                        confidence=0.85,
                    )
                )

            # 2. Object properties with type: array
            properties = schema.get("properties") or {}
            for prop_name, prop_schema in properties.items():
                prop_schema = _resolve_schema(prop_schema, spec)
                if prop_schema.get("type") == "array" and "maxItems" not in prop_schema:
                    findings.append(
                        _make_finding(
                            rule_id="RC-013",
                            cwe_id="CWE-400",
                            category="openapi_no_batch_limit",
                            severity=sev,
                            file_path="openapi_spec",
                            line_number=None,
                            endpoint=f"{method} {path_str}",
                            parameter=prop_name,
                            evidence=f"{method} {path_str} — JSON payload array field '{prop_name}' has no maxItems constraint",
                            missing_guard="Add maxItems: <int> to the array property schema",
                            confidence=0.8,
                        )
                    )

    return findings


# ---------------------------------------------------------------------------
# Spec enrichment (optional)
# ---------------------------------------------------------------------------


def _enrich_spec(
    spec: dict,
    paths: dict,
    findings: list[ResourceConsumptionFinding],
) -> None:
    """
    Add x-security-analysis extension to affected operations in-place.
    Only adds new x- fields; never modifies existing spec fields.
    """
    # Group findings by (path, method)
    endpoint_findings: dict[str, list[ResourceConsumptionFinding]] = {}
    for f in findings:
        if f.endpoint:
            endpoint_findings.setdefault(f.endpoint, []).append(f)

    for endpoint_key, ep_findings in endpoint_findings.items():
        parts = endpoint_key.split(" ", 1)
        if len(parts) != 2:
            continue
        method, path_str = parts[0].lower(), parts[1]

        path_item = paths.get(path_str)
        if not isinstance(path_item, dict):
            continue
        operation = path_item.get(method)
        if not isinstance(operation, dict):
            continue

        analysis_entries = []
        for f in ep_findings:
            analysis_entries.append(
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "parameter": f.parameter,
                    "missing_guard": f.missing_guard,
                    "confidence": f.confidence,
                }
            )

        # Write x-security-analysis (do not overwrite if already present)
        if "x-security-analysis" not in operation:
            operation["x-security-analysis"] = {"api4_findings": analysis_entries}
        else:
            # Append to existing list without replacing
            existing = operation["x-security-analysis"]
            if isinstance(existing, dict) and "api4_findings" in existing:
                existing["api4_findings"].extend(analysis_entries)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze_openapi(
    spec: dict,
    enrich_spec: bool = False,
) -> list[ResourceConsumptionFinding]:
    """
    Analyze a pre-parsed OpenAPI 3.x / Swagger 2.0 dict.

    Args:
        spec:        Parsed OpenAPI/Swagger dictionary.
        enrich_spec: If True, adds x-security-analysis extension fields to
                     the spec dict in-place (legal per OpenAPI spec extension rules).

    Returns:
        List of ResourceConsumptionFinding with layer='openapi'.

    Notes:
        - Supports OpenAPI 3.0, 3.1 and Swagger 2.0.
        - Does NOT raise on malformed specs — returns [] with a warning log.
        - If enrich_spec=True, the passed spec dict is mutated.
    """
    if not isinstance(spec, dict) or not spec:
        logger.debug("Empty or non-dict spec passed to analyze_openapi — skipping")
        return []

    try:
        version = detect_spec_version(spec)
        logger.debug("Analyzing OpenAPI spec version: %s", version)
    except ValueError as exc:
        logger.warning("OpenAPI spec version detection failed: %s", exc)
        # Still attempt analysis — many specs are valid but missing version
        version = "unknown"

    paths = _get_paths(spec)
    if not paths:
        logger.debug("No paths found in OpenAPI spec")
        return []

    all_findings: list[ResourceConsumptionFinding] = []

    try:
        all_findings.extend(_analyze_rc010(paths, spec))
    except Exception as exc:
        logger.warning("RC-010 analysis failed: %s", exc)

    try:
        all_findings.extend(_analyze_rc011(paths, spec))
    except Exception as exc:
        logger.warning("RC-011 analysis failed: %s", exc)

    try:
        all_findings.extend(_analyze_rc012(paths, spec))
    except Exception as exc:
        logger.warning("RC-012 analysis failed: %s", exc)

    try:
        all_findings.extend(_analyze_rc013(paths, spec))
    except Exception as exc:
        logger.warning("RC-013 analysis failed: %s", exc)

    if enrich_spec:
        try:
            _enrich_spec(spec, paths, all_findings)
        except Exception as exc:
            logger.warning("Spec enrichment failed: %s", exc)

    logger.info("OpenAPI layer: %d findings on %d paths", len(all_findings), len(paths))
    return all_findings
