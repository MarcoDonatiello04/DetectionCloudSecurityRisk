"""
RC-006 — Third-Party / Paid-Service Call Without Rate Throttle

Detects route handler functions that call paid-service APIs (SMS, email, OTP,
payment) without any rate-limiting decorator or Redis-based counter guard.

Rule:
- An RC-006 finding is valid ONLY if there is at least one import of a recognized paid SDK,
  and the call is traceable to that import.
"""

from __future__ import annotations

from tree_sitter import Node

from src.core.unrestricted_resource_consumption.models import ResourceConsumptionFinding

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PAID_SDK_IMPORTS = {
    # Comunicazione
    "twilio",
    "sendgrid",
    "mailgun",
    "vonage",
    "nexmo",
    "boto3.ses",
    "boto3.sns",
    "firebase_admin.messaging",
    "plivo",
    "messagebird",
    "bandwidth",
    # Pagamenti
    "stripe",
    "braintree",
    "paypal",
    "adyen",
    "square",
    # AI/LLM (pay-per-token)
    "openai",
    "anthropic",
    "cohere",
    "mistralai",
    "google.generativeai",
    "azure.ai",
    # Cloud costosi
    "boto3.rekognition",
    "boto3.transcribe",
    "boto3.translate",
    "google.cloud.vision",
    "google.cloud.speech",
    "azure.cognitiveservices",
}

PAID_FUNCTION_NAMES = {
    # Solo nomi inequivocabilmente legati a provider a pagamento
    "send_sms",
    "send_otp",
    "messages.create",  # Twilio pattern
    "payment_intents.create",  # Stripe pattern
    "chat.completions.create",  # OpenAI pattern
    "generate_content",  # Google AI pattern
}

RATE_LIMIT_DECORATOR_NAMES = {
    "rate_limit",
    "ratelimit",
    "throttle",
    "limiter",
    "limit",
    "rate_limited",
    "slow_down",
}

REDIS_COUNTER_PATTERNS = (
    "redis.get",
    "redis.incr",
    "redis.setex",
    "cache.get",
    "r.get(",
    "r.incr(",
    "rate_limit",
    "throttle",
)


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
    if node.type in ("identifier", "property_identifier", "shorthand_property_identifier"):
        return [_node_text(node)]
    if node.type in ("attribute", "member_expression"):
        parts: list[str] = []
        for child in node.children:
            if child.type in (
                "identifier",
                "property_identifier",
                "shorthand_property_identifier",
                "attribute",
                "member_expression",
            ):
                parts.extend(_get_attribute_chain(child))
        return parts
    return []


# ---------------------------------------------------------------------------
# SDK Import Gating & Variable Tracking
# ---------------------------------------------------------------------------


def _get_dotted_names_in_python_imports(root: Node) -> list[str]:
    names = []
    for node in _collect_nodes(root, "import_statement"):
        for child in _collect_nodes(node, "dotted_name"):
            names.append(_node_text(child))
    for node in _collect_nodes(root, "import_from_statement"):
        for child in node.children:
            if child.type == "dotted_name":
                names.append(_node_text(child))
                break
    return names


def _get_js_imports(root: Node) -> list[str]:
    names = []
    for node in _collect_nodes(root, "import_declaration"):
        for child in node.children:
            if child.type == "string":
                txt = _node_text(child).strip("'\"` ")
                names.append(txt)
    for call in _collect_nodes(root, "call_expression"):
        func = call.child_by_field_name("function")
        if func and _node_text(func) == "require":
            args = call.child_by_field_name("arguments")
            if args:
                for child in _collect_nodes(args, "string"):
                    txt = _node_text(child).strip("'\"` ")
                    names.append(txt)
    return names


def file_has_paid_sdk_import(root: Node, is_js: bool) -> bool:
    imported = _get_js_imports(root) if is_js else _get_dotted_names_in_python_imports(root)

    for imp in imported:
        imp_lower = imp.lower()
        if imp_lower in PAID_SDK_IMPORTS:
            return True
        first_segment = imp_lower.split(".")[0]
        if first_segment in PAID_SDK_IMPORTS:
            return True
        if first_segment in {"boto3", "firebase_admin", "google", "azure"}:
            return True
    return False


def _get_tracked_variables(root: Node) -> set[str]:
    tracked = set()

    # 1. Gather names bound in imports
    for node in _collect_nodes(root, "import_statement"):
        for child in node.children:
            if child.type == "dotted_name":
                txt = _node_text(child)
                tracked.add(txt.split(".")[0])
            elif child.type == "aliased_import":
                alias_node = child.child_by_field_name("alias")
                if alias_node:
                    tracked.add(_node_text(alias_node))
                else:
                    name_node = child.child_by_field_name("name")
                    if name_node:
                        tracked.add(_node_text(name_node).split(".")[0])

    for node in _collect_nodes(root, "import_from_statement"):
        seen_import = False
        for child in node.children:
            if child.type == "import":
                seen_import = True
                continue
            if seen_import:
                if child.type in ("dotted_name", "identifier"):
                    tracked.add(_node_text(child))
                elif child.type == "aliased_import":
                    alias_node = child.child_by_field_name("alias")
                    if alias_node:
                        tracked.add(_node_text(alias_node))
                    else:
                        name_node = child.child_by_field_name("name")
                        if name_node:
                            tracked.add(_node_text(name_node))

    # 2. Variable assignments
    for assign in _collect_nodes(root, "assignment"):
        left = assign.child_by_field_name("left")
        right = assign.child_by_field_name("right")
        if left and right and left.type == "identifier":
            left_name = _node_text(left)
            if right.type == "call":
                func = right.child_by_field_name("function")
                if func:
                    func_name = _node_text(func).split(".")[-1]
                    if (
                        func_name in {"Client", "TwilioClient", "OpenAI", "Stripe", "StripeClient"}
                        or func_name in tracked
                    ):
                        tracked.add(left_name)

    return tracked


def _get_js_tracked_variables(root: Node) -> set[str]:
    tracked = set()

    for node in _collect_nodes(root, "import_declaration"):
        for child in _collect_nodes(node, "identifier"):
            tracked.add(_node_text(child))
        for child in _collect_nodes(node, "namespace_import"):
            for id_child in _collect_nodes(child, "identifier"):
                tracked.add(_node_text(id_child))

    for node in _collect_nodes(root, "lexical_declaration"):
        has_require = False
        for call in _collect_nodes(node, "call_expression"):
            func = call.child_by_field_name("function")
            if func and _node_text(func) == "require":
                has_require = True
                break
        if has_require:
            for child in _collect_nodes(node, "identifier"):
                tracked.add(_node_text(child))
            for child in _collect_nodes(node, "shorthand_property_identifier"):
                tracked.add(_node_text(child))

    for decl in _collect_nodes(root, "variable_declarator"):
        name = decl.child_by_field_name("name")
        value = decl.child_by_field_name("value")
        if name and value and name.type == "identifier":
            name_text = _node_text(name)
            if value.type == "new_expression":
                constructor = value.child_by_field_name("constructor")
                if constructor:
                    cname = _node_text(constructor).split(".")[-1]
                    if cname in {"Client", "OpenAI", "Stripe"} or cname in tracked:
                        tracked.add(name_text)

    return tracked


# ---------------------------------------------------------------------------
# Call Matching & Throttling Checks
# ---------------------------------------------------------------------------


def _is_paid_call_python(call: Node, tracked: set[str]) -> bool:
    func = call.child_by_field_name("function")
    if func is None:
        return False
    chain = _get_attribute_chain(func)
    if not chain:
        return False

    if len(chain) == 1:
        return chain[0] in {"send_sms", "send_otp", "generate_content"}

    base = chain[0]
    suffix_2 = ".".join(chain[-2:])
    suffix_3 = ".".join(chain[-3:])

    return bool(
        (
            suffix_2 in {"messages.create", "payment_intents.create"}
            or suffix_3 in {"chat.completions.create"}
        )
        and (
            base in tracked
            or base.lower() in {"client", "twilio", "stripe", "openai", "vonage", "sdk"}
        )
    )


def _is_paid_call_js(call: Node, tracked: set[str]) -> bool:
    func = call.child_by_field_name("function")
    if func is None:
        if call.children:
            func = call.children[0]
        else:
            return False

    chain = _get_attribute_chain(func)
    if not chain:
        text = _node_text(func)
        chain = text.split(".")

    if not chain:
        return False

    if len(chain) == 1:
        return chain[0] in {"send_sms", "send_otp", "generate_content"}

    base = chain[0]
    suffix_2 = ".".join(chain[-2:])
    suffix_3 = ".".join(chain[-3:])

    return bool(
        (
            suffix_2 in {"messages.create", "payment_intents.create"}
            or suffix_3 in {"chat.completions.create"}
        )
        and (
            base in tracked
            or base.lower() in {"client", "twilio", "stripe", "openai", "vonage", "sdk"}
        )
    )


def _decorator_list_has_rate_limit(decorators: list[Node]) -> bool:
    for dec in decorators:
        dec_text = _node_text(dec).lower()
        if any(rl in dec_text for rl in RATE_LIMIT_DECORATOR_NAMES):
            return True
    return False


def _body_has_redis_throttle(body: Node) -> bool:
    body_text = _node_text(body)
    return any(pat in body_text for pat in REDIS_COUNTER_PATTERNS)


def _collect_decorators_for_func(decorated_def: Node) -> list[Node]:
    return [c for c in decorated_def.children if c.type == "decorator"]


def _find_enclosing_function_name(node: Node) -> str:
    curr = node.parent
    while curr:
        if (
            curr.type in ("function_declaration", "function_definition")
            or curr.type == "variable_declarator"
        ):
            name_node = curr.child_by_field_name("name")
            if name_node:
                return _node_text(name_node)
        curr = curr.parent
    return "handler"


def _build_finding_details(call: Node, fn_name: str) -> tuple[str, str]:
    evidence = _node_text(call)[:120]
    call_text = evidence.lower()

    if "twilio" in call_text or "messages.create" in call_text:
        missing_guard = f"No rate limit before Twilio SMS call in {fn_name}()"
    elif "openai" in call_text or "chat.completions" in call_text:
        missing_guard = f"No per-user throttle before OpenAI call in {fn_name}() handler"
    elif "stripe" in call_text or "payment_intents" in call_text:
        missing_guard = f"No rate limit before Stripe payment call in {fn_name}()"
    else:
        missing_guard = f"No rate limit before paid-service call in {fn_name}()"

    return evidence, missing_guard


# ---------------------------------------------------------------------------
# Python & JavaScript Analysis
# ---------------------------------------------------------------------------


def _analyze_python(root: Node, file_path: str) -> list[ResourceConsumptionFinding]:
    if not file_has_paid_sdk_import(root, is_js=False):
        return []

    findings: list[ResourceConsumptionFinding] = []
    tracked = _get_tracked_variables(root)

    for dec_def in _collect_nodes(root, "decorated_definition"):
        decorators = _collect_decorators_for_func(dec_def)
        func_nodes = [c for c in dec_def.children if c.type == "function_definition"]
        for func_node in func_nodes:
            body = func_node.child_by_field_name("body")
            if body is None:
                continue

            paid_calls = []
            for call in _collect_nodes(body, "call"):
                if _is_paid_call_python(call, tracked):
                    paid_calls.append(call)

            if not paid_calls:
                continue

            if _decorator_list_has_rate_limit(decorators):
                continue
            if _body_has_redis_throttle(body):
                continue

            name_node = func_node.child_by_field_name("name")
            fn_name = _node_text(name_node) if name_node else "handler"

            for call in paid_calls:
                evidence, missing_guard = _build_finding_details(call, fn_name)
                findings.append(
                    ResourceConsumptionFinding(
                        rule_id="RC-006",
                        cwe_id="CWE-770",
                        category="third_party_no_throttle",
                        severity="HIGH",
                        file_path=file_path,
                        line_number=call.start_point[0] + 1,
                        endpoint=None,
                        parameter=None,
                        evidence=evidence,
                        missing_guard=missing_guard,
                        confidence=0.85,
                        layer="ast",
                    )
                )

    decorated_funcs: set[int] = set()
    for dec_def in _collect_nodes(root, "decorated_definition"):
        for fn in _collect_nodes(dec_def, "function_definition"):
            decorated_funcs.add(fn.start_byte)

    for func_node in _collect_nodes(root, "function_definition"):
        if func_node.start_byte in decorated_funcs:
            continue
        body = func_node.child_by_field_name("body")
        if body is None:
            continue

        paid_calls = []
        for call in _collect_nodes(body, "call"):
            if _is_paid_call_python(call, tracked):
                paid_calls.append(call)

        if not paid_calls:
            continue
        if _body_has_redis_throttle(body):
            continue

        name_node = func_node.child_by_field_name("name")
        fn_name = _node_text(name_node) if name_node else "function"

        for call in paid_calls:
            evidence, missing_guard = _build_finding_details(call, fn_name)
            findings.append(
                ResourceConsumptionFinding(
                    rule_id="RC-006",
                    cwe_id="CWE-770",
                    category="third_party_no_throttle",
                    severity="MEDIUM",
                    file_path=file_path,
                    line_number=call.start_point[0] + 1,
                    endpoint=None,
                    parameter=None,
                    evidence=evidence,
                    missing_guard=missing_guard,
                    confidence=0.7,
                    layer="ast",
                )
            )

    return findings


def _js_handler_has_throttle(handler_node: Node) -> bool:
    handler_text = _node_text(handler_node).lower()
    return any(kw in handler_text for kw in ("ratelimit", "throttle", "limiter", "redis"))


def _analyze_javascript(root: Node, file_path: str) -> list[ResourceConsumptionFinding]:
    if not file_has_paid_sdk_import(root, is_js=True):
        return []

    findings: list[ResourceConsumptionFinding] = []
    tracked = _get_js_tracked_variables(root)

    for fn_type in ("function_declaration", "arrow_function", "function_expression"):
        for fn in _collect_nodes(root, fn_type):
            body = fn.child_by_field_name("body")
            if body is None:
                continue

            paid_calls = []
            for call in _collect_nodes(body, "call_expression"):
                if _is_paid_call_js(call, tracked):
                    paid_calls.append(call)

            if not paid_calls:
                continue

            if _js_handler_has_throttle(fn):
                continue

            fn_name = _find_enclosing_function_name(fn)
            for call in paid_calls:
                evidence, missing_guard = _build_finding_details(call, fn_name)
                findings.append(
                    ResourceConsumptionFinding(
                        rule_id="RC-006",
                        cwe_id="CWE-770",
                        category="third_party_no_throttle",
                        severity="HIGH",
                        file_path=file_path,
                        line_number=call.start_point[0] + 1,
                        endpoint=None,
                        parameter=None,
                        evidence=evidence,
                        missing_guard=missing_guard,
                        confidence=0.85,
                        layer="ast",
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class ThirdPartyCostRule:
    rule_id = "RC-006"
    cwe_id = "CWE-770"
    category = "third_party_no_throttle"
    severity = "HIGH"

    @staticmethod
    def analyze_python(root: Node, file_path: str) -> list[ResourceConsumptionFinding]:
        return _analyze_python(root, file_path)

    @staticmethod
    def analyze_javascript(root: Node, file_path: str) -> list[ResourceConsumptionFinding]:
        return _analyze_javascript(root, file_path)
