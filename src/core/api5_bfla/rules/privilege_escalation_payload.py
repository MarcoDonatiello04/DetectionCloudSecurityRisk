"""
BF-007 — Privilege Escalation via Payload (CWE-269).

Scenario OWASP API5:2023: ``POST /api/invites/new`` con body ``{"role": "admin"}``.
Un handler estrae un campo di privilegio dal payload della richiesta e lo assegna
a un oggetto/modello senza verificare che il *chiamante* abbia il diritto di
concedere quel privilegio. Un generico controllo di autenticazione non basta.

Fuori ambito:
- il campo letto solo per filtro/lettura (``filter_by(role=...)``, ``findOne({role})``);
- il mass assignment generico (``user.update(**request.json)``), che e API3/BOPLA.

BF-007 e *non esclusiva* nella deduplicazione per path (``detector.NON_EXCLUSIVE_RULES``):
risponde a "quale valore viene assegnato", mentre BF-001/BF-002 rispondono a
"chi puo invocare la funzione", quindi sullo stesso endpoint possono coesistere.
"""

import re

from tree_sitter import Node

from src.core.api5_bfla.models import FunctionAuthzFinding, RuleID
from src.core.api5_bfla.rules.auth_without_authz import AUTH_ONLY_DECORATORS
from src.core.api5_bfla.rules.privileged_endpoint_no_role_check import (
    ROLE_CHECK_DECORATORS,
    _collect_nodes,
    _node_text,
    _parse_python_decorator,
)

# ---------------------------------------------------------------------------
# Constants (configurabili)
# ---------------------------------------------------------------------------

PRIVILEGE_FIELDS = {
    "role",
    "is_admin",
    "is_staff",
    "permissions",
    "group",
    "scope",
    "admin",
    "privilege",
    # alias camelCase per payload JavaScript
    "isAdmin",
    "isStaff",
}

PY_PAYLOAD_SOURCES = (
    "request.json",
    "request.get_json",
    "request.form",
    "request.data",
    "request.values",
    "request.POST",
)
JS_PAYLOAD_SOURCES = ("req.body", "request.body", "ctx.request.body")

# Chiamate di sola lettura/filtro: gli argomenti non sono assegnazioni.
READ_ONLY_CALLS = {
    "filter",
    "filter_by",
    "exclude",
    "where",
    "find",
    "find_one",
    "findOne",
    "findAll",
    "findMany",
    "findFirst",
    "count",
    "exists",
    "select",
    "search",
}
# Chiamate di lookup il cui argomento keyword e un criterio, non un valore assegnato.
LOOKUP_CALLS = {"get", "get_or_404", "get_object_or_404", "first"}

# Annotazioni FastAPI che non rappresentano il body della richiesta.
NON_PAYLOAD_ANNOTATIONS = {
    "Request",
    "Response",
    "Session",
    "AsyncSession",
    "BackgroundTasks",
    "UploadFile",
    "WebSocket",
    "HTTPConnection",
    "Optional",
    "Union",
    "Annotated",
    "List",
    "Dict",
    "None",
}
NON_BODY_DEFAULTS = ("Depends(", "Security(", "Query(", "Path(", "Header(", "Cookie(")

JS_ROLE_MIDDLEWARE = {
    "requireRole",
    "requireAdmin",
    "checkRole",
    "hasRole",
    "adminOnly",
    "isAdmin",
    "authorizeRoles",
    "checkPermission",
}

# Controllo sul privilegio del *chiamante* (non sul valore del payload).
_CALLER = (
    r"(?:current_user|g\.user|request\.user|req\.user|ctx\.state\.user|caller|actor|requester)"
)
_CALLER_ATTR = (
    r"(?:is_admin|isAdmin|is_staff|isStaff|is_superuser|role|roles|permissions|scopes?"
    r"|has_role|hasRole|has_perm|has_permission|hasPermission|can)"
)
CALLER_PRIVILEGE_RE = re.compile(rf"\b{_CALLER}\.{_CALLER_ATTR}\b")
GUARD_CALL_RE = re.compile(
    r"\b(?:has_role|hasRole|has_permission|hasPermission|check_permission|checkPermission"
    r"|require_role|requireRole|can_assign_role|canAssignRole|can_grant|canGrant)\s*\("
)

_PRIV_COLUMNS = "|".join(sorted(re.escape(f) for f in PRIVILEGE_FIELDS))
SQL_UPDATE_PRIV_RE = re.compile(
    rf"\bUPDATE\b[\s\S]*?\bSET\b[\s\S]*?\b(?:{_PRIV_COLUMNS})\s*=", re.IGNORECASE
)

_PY_ROUTE_RE = re.compile(r"\.(route|api_route|get|post|put|patch|delete)$")
_JS_ROUTE_RE = re.compile(r"\b(?:app|router)\.(get|post|put|patch|delete)$")


def _strip_string(node: Node) -> str:
    return _node_text(node).strip("\"'`")


def _callee_name(fn: Node | None) -> str:
    """Ultimo segmento del nome della funzione chiamata (``db.users.update`` -> ``update``)."""
    text = _node_text(fn)
    return re.split(r"[.\s]", text.strip())[-1] if text else ""


def _is_guarded(condition_texts: list[str], body_text: str) -> bool:
    if GUARD_CALL_RE.search(body_text):
        return True
    return any(CALLER_PRIVILEGE_RE.search(t) for t in condition_texts)


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------


class _PyHandlerScan:
    """Taint leggero, in ordine di sorgente, dal payload ai sink di assegnazione."""

    def __init__(self, payload_vars: set[str]) -> None:
        self.payload_vars = set(payload_vars)
        self.tainted: dict[str, str] = {}  # variabile -> campo di privilegio d'origine

    def is_payload(self, node: Node | None) -> bool:
        if node is None:
            return False
        text = _node_text(node).strip()
        if node.type == "identifier":
            return text in self.payload_vars
        if node.type == "parenthesized_expression":
            return any(self.is_payload(c) for c in node.named_children)
        if node.type == "boolean_operator":  # request.get_json() or {}
            return self.is_payload(node.child_by_field_name("left"))
        if node.type == "call" and _node_text(node.child_by_field_name("function")) in (
            "dict",
            "copy.deepcopy",
        ):
            args = node.child_by_field_name("arguments")
            return bool(args and args.named_children and self.is_payload(args.named_children[0]))
        return any(text.startswith(src) for src in PY_PAYLOAD_SOURCES)

    def field_of(self, node: Node) -> str | None:
        """Se ``node`` estrae un campo di privilegio dal payload, restituisce il campo."""
        if node.type == "identifier":
            return self.tainted.get(_node_text(node))
        if node.type == "subscript":
            obj = node.child_by_field_name("value")
            key = node.child_by_field_name("subscript")
            if key is not None and key.type == "string" and self.is_payload(obj):
                name = _strip_string(key)
                return name if name in PRIVILEGE_FIELDS else None
        elif node.type == "attribute":
            obj = node.child_by_field_name("object")
            attr = _node_text(node.child_by_field_name("attribute"))
            if attr in PRIVILEGE_FIELDS and self.is_payload(obj):
                return attr
        elif node.type == "call":
            fn = node.child_by_field_name("function")
            if fn is not None and fn.type == "attribute":
                method = _node_text(fn.child_by_field_name("attribute"))
                if method in ("get", "pop") and self.is_payload(fn.child_by_field_name("object")):
                    args = node.child_by_field_name("arguments")
                    first = args.named_children[0] if args and args.named_children else None
                    if first is not None and first.type == "string":
                        name = _strip_string(first)
                        return name if name in PRIVILEGE_FIELDS else None
        return None

    def sensitive_in(self, node: Node | None) -> str | None:
        """Primo campo di privilegio del payload che confluisce nel sottoalbero."""
        if node is None:
            return None
        field = self.field_of(node)
        if field:
            return field
        if node.type == "call":
            callee = _callee_name(node.child_by_field_name("function"))
            if callee in READ_ONLY_CALLS:
                return None
            args = node.child_by_field_name("arguments")
            fn_field = self.sensitive_in(node.child_by_field_name("function"))
            if fn_field:
                return fn_field
            if args is None:
                return None
            for arg in args.named_children:
                if callee in LOOKUP_CALLS and arg.type == "keyword_argument":
                    continue
                found = self.sensitive_in(arg)
                if found:
                    return found
            return None
        for child in node.named_children:
            found = self.sensitive_in(child)
            if found:
                return found
        return None

    # -- sink -----------------------------------------------------------------

    def visit_assignment(self, node: Node) -> str | None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return None
        field = self.sensitive_in(right)
        if left.type == "identifier":
            name = _node_text(left)
            if field:
                self.tainted[name] = field
            elif self.is_payload(right):
                self.payload_vars.add(name)
            else:
                self.tainted.pop(name, None)
            return None
        if left.type in ("attribute", "subscript") and field:
            target = left.child_by_field_name("object" if left.type == "attribute" else "value")
            if not self.is_payload(target):
                return field
        return None

    def visit_call(self, node: Node) -> str | None:
        fn = node.child_by_field_name("function")
        callee = _callee_name(fn)
        args = node.child_by_field_name("arguments")
        if args is None or callee in READ_ONLY_CALLS:
            return None
        named = args.named_children

        if _node_text(fn) == "setattr" and len(named) >= 3:
            attr_name, value = named[1], named[2]
            field = self.sensitive_in(value)
            if field:
                return field
            if attr_name.type == "string" and _strip_string(attr_name) in PRIVILEGE_FIELDS:
                return self.field_of(value)
            return None

        for arg in named:
            if arg.type == "keyword_argument" and callee not in LOOKUP_CALLS:
                kw = _node_text(arg.child_by_field_name("name"))
                if kw in PRIVILEGE_FIELDS:
                    field = self.sensitive_in(arg.child_by_field_name("value"))
                    if field:
                        return field
            elif arg.type == "dictionary":
                for pair in arg.named_children:
                    if pair.type != "pair":
                        continue
                    key = pair.child_by_field_name("key")
                    if key is not None and key.type == "string":
                        if _strip_string(key) in PRIVILEGE_FIELDS:
                            field = self.sensitive_in(pair.child_by_field_name("value"))
                            if field:
                                return field

        if any(a.type == "string" and SQL_UPDATE_PRIV_RE.search(_node_text(a)) for a in named):
            return self.sensitive_in(args)
        return None


def _py_route(decorators: list[Node]) -> tuple[bool, str | None, list[str]]:
    for dec in decorators:
        dec_name, dec_args = _parse_python_decorator(dec)
        if dec_name.endswith("api_view"):  # DRF function-based view: path in urls.py
            methods = re.findall(r"['\"]([A-Za-z]+)['\"]", _node_text(dec))
            return True, None, [m.upper() for m in methods] or ["GET"]
        match = _PY_ROUTE_RE.search(dec_name)
        if not match:
            continue
        verb = match.group(1)
        path = dec_args[0] if dec_args else None
        if verb in ("route", "api_route"):
            methods_kw = re.search(r"methods\s*=\s*\[([^\]]*)\]", _node_text(dec))
            methods = (
                re.findall(r"['\"]([A-Za-z]+)['\"]", methods_kw.group(1)) if methods_kw else []
            )
            return True, path, [m.upper() for m in methods] or ["GET"]
        return True, path, [verb.upper()]
    return False, None, []


def _py_body_params(func_node: Node) -> set[str]:
    """Parametri FastAPI tipizzati con un modello (Pydantic/DTO): sono il body della richiesta."""
    params = func_node.child_by_field_name("parameters")
    result: set[str] = set()
    if params is None:
        return result
    for param in params.named_children:
        if param.type not in ("typed_parameter", "typed_default_parameter"):
            continue
        default = param.child_by_field_name("value")
        if default is not None and any(d in _node_text(default) for d in NON_BODY_DEFAULTS):
            continue
        name_node = param.child_by_field_name("name")
        if name_node is None:
            name_node = next((c for c in param.named_children if c.type == "identifier"), None)
        annotation = _node_text(param.child_by_field_name("type"))
        type_names = re.findall(r"[A-Za-z_]\w*", annotation)
        if name_node is not None and any(
            t[0].isupper() and t not in NON_PAYLOAD_ANNOTATIONS for t in type_names
        ):
            result.add(_node_text(name_node))
    return result


def _walk_in_order(node: Node):
    yield node
    for child in node.children:
        yield from _walk_in_order(child)


class PrivilegeEscalationPayloadRule:
    rule_id = RuleID.BF_007.value
    cwe_id = "CWE-269"
    category = "privilege_escalation_via_payload"
    severity = "CRITICAL"
    missing_guard = (
        "Privilege field taken from the request payload is assigned without verifying that "
        "the caller is allowed to grant that privilege"
    )

    @staticmethod
    def _finding(
        file_path: str,
        sink: Node,
        endpoint: str | None,
        methods: list[str],
        field: str,
        found_guard: str | None,
    ) -> FunctionAuthzFinding:
        rule = PrivilegeEscalationPayloadRule
        return FunctionAuthzFinding(
            rule_id=rule.rule_id,
            cwe_id=rule.cwe_id,
            category=rule.category,
            severity=rule.severity,
            file_path=file_path,
            line_number=sink.start_point[0] + 1,
            endpoint=endpoint,
            http_methods=methods,
            required_role="admin",
            found_guard=found_guard,
            missing_guard=f"{rule.missing_guard} (field: '{field}')",
            evidence=_node_text(sink)[:120],
            confidence=0.90,
            layer="ast",
        )

    @staticmethod
    def analyze_python(root: Node, file_path: str) -> list[FunctionAuthzFinding]:
        findings = []
        for dec_def in _collect_nodes(root, "decorated_definition"):
            decorators = [c for c in dec_def.children if c.type == "decorator"]
            func_node = next((c for c in dec_def.children if c.type == "function_definition"), None)
            if func_node is None:
                continue
            is_route, path, methods = _py_route(decorators)
            if not is_route:
                continue
            body = func_node.child_by_field_name("body")
            if body is None:
                continue

            decorator_names = [_parse_python_decorator(d)[0] for d in decorators]
            if any(rc in name for name in decorator_names for rc in ROLE_CHECK_DECORATORS):
                continue
            conditions = [
                _node_text(n.child_by_field_name("condition"))
                for kind in ("if_statement", "elif_clause")
                for n in _collect_nodes(body, kind)
            ] + [_node_text(n) for n in _collect_nodes(body, "assert_statement")]
            if _is_guarded(conditions, _node_text(body)):
                continue

            scan = _PyHandlerScan(_py_body_params(func_node))
            for node in _walk_in_order(body):
                if node.type == "assignment":
                    field = scan.visit_assignment(node)
                elif node.type == "call":
                    field = scan.visit_call(node)
                else:
                    continue
                if field:
                    auth = next(
                        (n for n in decorator_names if any(a in n for a in AUTH_ONLY_DECORATORS)),
                        None,
                    )
                    endpoint = f"{methods[0]} {path}" if path else None
                    findings.append(
                        PrivilegeEscalationPayloadRule._finding(
                            file_path, node, endpoint, methods, field, auth
                        )
                    )
                    break
        return findings

    # -----------------------------------------------------------------------
    # JavaScript / TypeScript (Express)
    # -----------------------------------------------------------------------

    @staticmethod
    def analyze_javascript(root: Node, file_path: str) -> list[FunctionAuthzFinding]:
        findings = []
        for call in _collect_nodes(root, "call_expression"):
            match = _JS_ROUTE_RE.search(_node_text(call.child_by_field_name("function")))
            if not match:
                continue
            args = call.child_by_field_name("arguments")
            named = args.named_children if args else []
            if len(named) < 2 or named[0].type != "string":
                continue
            handler = named[-1]
            if handler.type not in ("arrow_function", "function_expression", "function"):
                continue
            middlewares = [_node_text(m) for m in named[1:-1]]
            role_markers = ROLE_CHECK_DECORATORS | JS_ROLE_MIDDLEWARE
            if any(rc in mw for mw in middlewares for rc in role_markers):
                continue
            conditions = [
                _node_text(n.child_by_field_name("condition"))
                for n in _collect_nodes(handler, "if_statement")
            ]
            if _is_guarded(conditions, _node_text(handler)):
                continue

            scan = _JsHandlerScan()
            sink, field = scan.first_sink(handler)
            if sink is None:
                continue
            method = match.group(1).upper()
            auth = next(
                (mw for mw in middlewares if any(a in mw for a in AUTH_ONLY_DECORATORS)), None
            )
            findings.append(
                PrivilegeEscalationPayloadRule._finding(
                    file_path,
                    sink,
                    f"{method} {_strip_string(named[0])}",
                    [method],
                    field,
                    auth,
                )
            )
        return findings


class _JsHandlerScan:
    def __init__(self) -> None:
        self.payload_vars: set[str] = set()
        self.tainted: dict[str, str] = {}

    def is_payload(self, node: Node | None) -> bool:
        if node is None:
            return False
        text = _node_text(node).strip()
        if node.type == "identifier":
            return text in self.payload_vars
        if node.type == "parenthesized_expression":
            return any(self.is_payload(c) for c in node.named_children)
        if node.type == "binary_expression":  # req.body || {}
            return self.is_payload(node.child_by_field_name("left"))
        return any(text == src or text.startswith(src + ".") for src in JS_PAYLOAD_SOURCES)

    def field_of(self, node: Node) -> str | None:
        if node.type == "identifier":
            return self.tainted.get(_node_text(node))
        if node.type == "member_expression":
            prop = _node_text(node.child_by_field_name("property"))
            if prop in PRIVILEGE_FIELDS and self.is_payload(node.child_by_field_name("object")):
                return prop
        elif node.type == "subscript_expression":
            index = node.child_by_field_name("index")
            if index is not None and index.type == "string":
                name = _strip_string(index)
                if name in PRIVILEGE_FIELDS and self.is_payload(node.child_by_field_name("object")):
                    return name
        return None

    def sensitive_in(self, node: Node | None) -> str | None:
        if node is None:
            return None
        field = self.field_of(node)
        if field:
            return field
        if node.type in ("call_expression", "new_expression"):
            callee = node.child_by_field_name("function") or node.child_by_field_name("constructor")
            if _callee_name(callee) in READ_ONLY_CALLS:
                return None
        for child in node.named_children:
            found = self.sensitive_in(child)
            if found:
                return found
        return None

    def _object_sink(self, obj: Node) -> str | None:
        """Proprieta di privilegio valorizzate dal payload in un letterale oggetto."""
        for prop in obj.named_children:
            if prop.type == "shorthand_property_identifier":
                name = _node_text(prop)
                if name in PRIVILEGE_FIELDS and name in self.tainted:
                    return self.tainted[name]
            elif prop.type == "pair":
                key = _strip_string(prop.child_by_field_name("key"))
                value = prop.child_by_field_name("value")
                if key == "where":
                    continue
                if key in PRIVILEGE_FIELDS:
                    field = self.sensitive_in(value)
                    if field:
                        return field
                if value is not None and value.type == "object":
                    field = self._object_sink(value)
                    if field:
                        return field
        return None

    def _declare(self, node: Node) -> None:
        name = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
        if name is None or value is None:
            return
        if name.type == "identifier":
            field = self.sensitive_in(value)
            if field:
                self.tainted[_node_text(name)] = field
            elif self.is_payload(value):
                self.payload_vars.add(_node_text(name))
            return
        if name.type == "object_pattern" and self.is_payload(value):
            for prop in name.named_children:
                if prop.type == "shorthand_property_identifier_pattern":
                    key = _node_text(prop)
                    if key in PRIVILEGE_FIELDS:
                        self.tainted[key] = key
                elif prop.type == "object_assignment_pattern":  # { role = "user" }
                    key = _node_text(prop.child_by_field_name("left"))
                    if key in PRIVILEGE_FIELDS:
                        self.tainted[key] = key
                elif prop.type == "pair_pattern":  # { role: newRole }
                    key = _strip_string(prop.child_by_field_name("key"))
                    if key in PRIVILEGE_FIELDS:
                        self.tainted[_node_text(prop.child_by_field_name("value"))] = key

    def first_sink(self, handler: Node) -> tuple[Node | None, str]:
        for node in _walk_in_order(handler):
            if node.type == "variable_declarator":
                self._declare(node)
            elif node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                field = self.sensitive_in(right)
                if left is not None and left.type == "identifier":
                    if field:
                        self.tainted[_node_text(left)] = field
                    elif self.is_payload(right):
                        self.payload_vars.add(_node_text(left))
                elif left is not None and field:
                    target = left.child_by_field_name("object")
                    if not self.is_payload(target):
                        return node, field
            elif node.type in ("call_expression", "new_expression"):
                callee = node.child_by_field_name("function") or node.child_by_field_name(
                    "constructor"
                )
                if _callee_name(callee) in READ_ONLY_CALLS:
                    continue
                args = node.child_by_field_name("arguments")
                if args is None:
                    continue
                for arg in args.named_children:
                    if arg.type == "object":
                        field = self._object_sink(arg)
                        if field:
                            return node, field
                if any(
                    a.type in ("string", "template_string")
                    and SQL_UPDATE_PRIV_RE.search(_node_text(a))
                    for a in args.named_children
                ):
                    field = self.sensitive_in(args)
                    if field:
                        return node, field
        return None, ""
