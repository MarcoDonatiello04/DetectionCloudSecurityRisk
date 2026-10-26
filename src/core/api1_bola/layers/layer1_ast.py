"""
Layer 1 — analisi AST (tree-sitter) degli handler di rotta per API1:2023 (BOLA).

Individua gli handler Flask/FastAPI (Python) ed Express (JavaScript) il cui path
contiene un identificativo di oggetto, estrae le guardie dichiarate (decorator,
middleware, dipendenze FastAPI) e delega a ``ownership_facts`` la lettura del corpo:
quale istruzione accede all'oggetto con quell'ID e se l'accesso è legato al
soggetto autenticato. Sui fatti raccolti girano le regole OA-001…OA-005.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterator
from pathlib import Path

import tree_sitter_javascript as tsjavascript
import tree_sitter_python as tspython
from tree_sitter import Language, Node, Parser

from src.core.api1_bola.discovery.object_discovery import ObjectReferenceDiscoveryEngine
from src.core.api1_bola.layers.ownership_facts import (
    JAVASCRIPT,
    PYTHON,
    HelperSummary,
    analyze_handler,
    is_privileged_guard,
    summarize_helper,
)
from src.core.api1_bola.models import ObjectAuthzFinding, OwnershipCheck, RouteHandler
from src.core.api1_bola.rules.direct_object_reference_no_check import (
    DirectObjectReferenceNoCheckRule,
)
from src.core.api1_bola.rules.inconsistent_authz_across_methods import (
    InconsistentAuthzAcrossMethodsRule,
)
from src.core.api1_bola.rules.missing_ownership_filter import MissingOwnershipFilterRule
from src.core.api1_bola.rules.serial_id_no_authz_decorator import (
    SerialIdNoAuthzDecoratorRule,
)
from src.core.api1_bola.rules.unvalidated_nested_object_reference import (
    UnvalidatedNestedObjectReferenceRule,
)

logger = logging.getLogger(__name__)

PYTHON_EXTENSIONS = {".py"}
JS_EXTENSIONS = {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}
SUPPORTED_EXTENSIONS = PYTHON_EXTENSIONS | JS_EXTENSIONS
MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB

SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
    ".mypy_cache",
    ".tox",
    "site-packages",
    "egg-info",
}

HTTP_METHODS = ("get", "post", "put", "patch", "delete")

# Regole eseguite sull'insieme degli handler (OA-003 confronta handler diversi).
RULES: list[Callable[[list[RouteHandler]], list[ObjectAuthzFinding]]] = [
    MissingOwnershipFilterRule.analyze,
    DirectObjectReferenceNoCheckRule.analyze,
    InconsistentAuthzAcrossMethodsRule.analyze,
    UnvalidatedNestedObjectReferenceRule.analyze,
    SerialIdNoAuthzDecoratorRule.analyze,
]

# Guardie dichiarate su decorator (Python) o middleware (Express)
_PY_AUTH_GUARD = re.compile(
    r"(?i)(login_required|jwt_required|token_required|auth_required|requires?_auth|"
    r"authenticat|verify_(?:jwt|token)|fresh_jwt_required|permission_classes|@\s*auth\.)"
)
_JS_AUTH_GUARD = re.compile(
    r"(?i)(\bauth\w*|authenticat|requireLogin|ensureLoggedIn|isLoggedIn|verify_?(?:jwt|token)"
    r"|\bjwt|passport|\bprotect\b|checkJwt|requireUser)"
)
_OWNERSHIP_GUARD = re.compile(
    r"(?i)(owner(?:ship)?_?required|requires?_?owner(?:ship)?|object_?permission|"
    r"check_?object_?permissions?|verify_?ownership|owns_?resource|isOwner|checkOwnership|"
    r"canAccess|authorizeResource|checkAccess)"
)
# Dipendenze FastAPI che autenticano (e, se "user", restituiscono l'identità)
_FASTAPI_DEP = re.compile(
    r"([A-Za-z_]\w*)\s*(?::\s*[^=,()]+)?=\s*(?:Depends|Security)\s*\(\s*([\w\.]+)"
)
_FASTAPI_AUTH_DEP = re.compile(r"(?i)(user|auth|token|verify|oauth|jwt|principal|identity)")


# ---------------------------------------------------------------------------
# tree-sitter
# ---------------------------------------------------------------------------

_LANGUAGES: dict[str, Language | None] = {}


def _get_language(name: str) -> Language | None:
    if name not in _LANGUAGES:
        try:
            module = tspython if name == PYTHON else tsjavascript
            _LANGUAGES[name] = Language(module.language())
        except Exception as exc:  # pragma: no cover - dipende dall'installazione
            logger.warning("tree-sitter grammar %s unavailable: %s", name, exc)
            _LANGUAGES[name] = None
    return _LANGUAGES[name]


def _text(node: Node | None) -> str:
    return node.text.decode("utf-8", errors="replace") if node and node.text else ""


def _collect(root: Node, node_type: str) -> list[Node]:
    result: list[Node] = []
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == node_type:
            result.append(node)
        stack.extend(reversed(node.children))
    return result


def _body_lines(node: Node, source_lines: list[str], skip_rows: set[int]) -> list[tuple[int, str]]:
    """Righe del nodo come (numero di riga 1-based, testo), escluse le righe in ``skip_rows``."""
    start_row, start_col = node.start_point
    end_row, end_col = node.end_point
    lines = []
    for row in range(start_row, end_row + 1):
        if row in skip_rows or row >= len(source_lines):
            continue
        text = source_lines[row]
        if row == end_row:
            text = text[:end_col]
        if row == start_row:
            text = text[start_col:]
        lines.append((row + 1, text))
    return lines


# ---------------------------------------------------------------------------
# Parametri di path
# ---------------------------------------------------------------------------


def _is_id_name(name: str) -> bool:
    return ObjectReferenceDiscoveryEngine.is_id_field(name) or name.lower() in {"pk", "slug"}


def path_parameters(path: str) -> list[tuple[str, bool]]:
    """
    Parametri di path in ordine di comparsa, con flag "numerico".
    Supporta Flask (``<int:id>``), OpenAPI/FastAPI (``{id}``, ``{id:int}``) ed Express
    (``:id``, ``:id(\\d+)``).
    """
    found: list[tuple[int, str, bool]] = []
    for m in re.finditer(r"<(?:(\w+)(?:\([^)]*\))?:)?(\w+)>", path):
        found.append((m.start(), m.group(2), (m.group(1) or "") in ("int", "float")))
    for m in re.finditer(r"\{(\w+)(?::([^}]*))?\}", path):
        found.append((m.start(), m.group(1), (m.group(2) or "").startswith("int")))
    for m in re.finditer(r"(?<![\w}]):(\w+)(\(([^)]*)\))?", path):
        found.append((m.start(), m.group(1), "\\d" in (m.group(3) or "")))
    return [(name, numeric) for _pos, name, numeric in sorted(found)]


def _clean_express_path(path: str) -> str:
    path = re.sub(r"(:\w+)\([^)]*\)", r"\1", path)
    return re.sub(r"(:\w+)\?", r"\1", path)


def _new_handler(
    file_path: str, line: int, name: str, path: str, methods: list[str], language: str
) -> RouteHandler:
    params = path_parameters(path)
    id_params = [n for n, numeric in params if numeric or _is_id_name(n)]
    numeric = [n for n, is_num in params if is_num and n in id_params]
    return RouteHandler(
        file_path=file_path,
        line_number=line,
        function_name=name,
        path=path,
        http_methods=methods,
        language=language,
        id_params=id_params,
        numeric_id_params=numeric,
    )


def _apply_guards(handler: RouteHandler, guards: list[str], auth_re: re.Pattern) -> None:
    """Classifica decorator/middleware in autenticazione, ownership e ruolo privilegiato."""
    for guard in guards:
        handler.guards.append(guard)
        if _OWNERSHIP_GUARD.search(guard):
            handler.ownership_checks.append(
                OwnershipCheck("decorator", handler.line_number, guard, list(handler.id_params))
            )
            handler.has_authentication = True
            handler.auth_evidence = handler.auth_evidence or guard
        if auth_re.search(guard):
            handler.has_authentication = True
            handler.auth_evidence = handler.auth_evidence or guard
        if is_privileged_guard(guard):
            # Una guardia di ruolo presuppone un chiamante autenticato
            handler.privileged_role_guard = handler.privileged_role_guard or guard
            handler.has_authentication = True
            handler.auth_evidence = handler.auth_evidence or guard


# ---------------------------------------------------------------------------
# Python (Flask / FastAPI)
# ---------------------------------------------------------------------------

_PY_ROUTE_DEC = re.compile(r"^@\s*([\w\.]+)\s*\((.*)\)\s*$", re.S)
_PY_STRING = re.compile(r"\s*[rbuf]*(['\"])(.*?)\1")


def _parse_route_call(name: str, args: str) -> tuple[str, list[str]] | None:
    suffix = name.rsplit(".", 1)[-1].lower()
    path_match = _PY_STRING.match(args)
    if not path_match or not path_match.group(2).startswith("/"):
        return None
    if suffix in HTTP_METHODS:
        return path_match.group(2), [suffix.upper()]
    if suffix in ("route", "api_route", "add_url_rule"):
        methods_match = re.search(r"methods\s*=\s*[\[\(]([^\]\)]*)[\]\)]", args)
        methods = (
            [m.upper() for m in re.findall(r"['\"](\w+)['\"]", methods_match.group(1))]
            if methods_match
            else ["GET"]
        )
        return path_match.group(2), methods
    return None


def _python_prefixes(source: str) -> tuple[dict[str, str], set[str]]:
    """Prefisso per variabile Blueprint/APIRouter e router con dipendenze di autenticazione."""
    prefixes: dict[str, str] = {}
    authed: set[str] = set()
    for m in re.finditer(r"(\w+)\s*=\s*(?:\w+\.)?(Blueprint|APIRouter|FastAPI)\s*\(", source):
        args = _paren_args(source, m.end() - 1)
        prefix = re.search(r"(?:url_prefix|prefix)\s*=\s*['\"]([^'\"]*)['\"]", args)
        if prefix:
            prefixes[m.group(1)] = prefix.group(1).rstrip("/")
        deps = re.search(r"dependencies\s*=\s*\[(.*)\]", args, re.S)
        if deps and _FASTAPI_AUTH_DEP.search(deps.group(1)):
            authed.add(m.group(1))
    for m in re.finditer(
        r"register_blueprint\s*\(\s*(\w+)[^)]*url_prefix\s*=\s*['\"]([^'\"]*)", source
    ):
        prefixes[m.group(1)] = m.group(2).rstrip("/")
    return prefixes, authed


def _paren_args(source: str, open_pos: int) -> str:
    depth = 0
    for i in range(open_pos, len(source)):
        if source[i] == "(":
            depth += 1
        elif source[i] == ")":
            depth -= 1
            if depth == 0:
                return source[open_pos + 1 : i]
    return source[open_pos + 1 :]


def _docstring_rows(func: Node) -> set[int]:
    body = func.child_by_field_name("body")
    if body is None or not body.named_children:
        return set()
    first = body.named_children[0]
    if first.type == "expression_statement" and first.named_children:
        if first.named_children[0].type == "string":
            return set(range(first.start_point[0], first.end_point[0] + 1))
    return set()


def _python_file_auth(root: Node) -> set[str]:
    """Variabili app/blueprint con un ``before_request`` che impone l'autenticazione."""
    authed: set[str] = set()
    for dec_def in _collect(root, "decorated_definition"):
        decorators = [_text(c) for c in dec_def.children if c.type == "decorator"]
        func = dec_def.child_by_field_name("definition")
        for dec in decorators:
            m = re.match(r"@\s*(\w+)\.before(?:_app)?_request\b", dec)
            if m and func is not None:
                body = _text(func.child_by_field_name("body"))
                if re.search(r"(?i)abort\s*\(\s*401|verify_jwt|jwt|token|login|authenticat", body):
                    authed.add(m.group(1))
    return authed


def _python_param_names(func: Node) -> list[str]:
    names = []
    params = func.child_by_field_name("parameters")
    for i, child in enumerate(params.named_children if params is not None else []):
        if child.type == "identifier":
            name = _text(child)
        else:
            ident = child.child_by_field_name("name") or next(
                (c for c in child.named_children if c.type == "identifier"), None
            )
            name = _text(ident) if ident is not None else f"_arg{i}"
        if name not in ("self", "cls"):
            names.append(name)
    return names


def _python_helpers(
    functions: dict[str, Node], route_funcs: set[str], lines: list[str]
) -> dict[str, HelperSummary]:
    """Riassunti delle funzioni del file che non sono handler di rotta (un livello)."""
    helpers = {}
    for name, func in functions.items():
        body = func.child_by_field_name("body")
        if name in route_funcs or body is None:
            continue
        body_lines = _body_lines(body, lines, _docstring_rows(func))
        helpers[name] = summarize_helper(name, _python_param_names(func), body_lines, PYTHON)
    return helpers


def _python_handlers(root: Node, source: str, file_path: str) -> list[RouteHandler]:
    lines = source.splitlines()
    prefixes, router_auth = _python_prefixes(source)
    file_auth = _python_file_auth(root) | router_auth
    functions = {
        _text(f.child_by_field_name("name")): f for f in _collect(root, "function_definition")
    }
    routes: list[tuple[Node, str, list[str], str, list[str]]] = []

    for dec_def in _collect(root, "decorated_definition"):
        func = dec_def.child_by_field_name("definition")
        if func is None or func.type != "function_definition":
            continue
        decorators = [_text(c) for c in dec_def.children if c.type == "decorator"]
        guards = []
        found_routes = []
        for dec in decorators:
            m = _PY_ROUTE_DEC.match(dec.strip())
            parsed = _parse_route_call(m.group(1), m.group(2)) if m else None
            if parsed and m:
                owner = m.group(1).rsplit(".", 1)[0]
                found_routes.append((owner, parsed[0], parsed[1], m.group(2)))
            else:
                guards.append(dec.strip())
        for owner, path, methods, args in found_routes:
            route_guards = list(guards)
            dep_args = re.search(r"dependencies\s*=\s*\[(.*)\]", args, re.S)
            if dep_args and _FASTAPI_AUTH_DEP.search(dep_args.group(1)):
                route_guards.append(f"dependencies=[{dep_args.group(1).strip()}]")
            routes.append((func, prefixes.get(owner, "") + path, methods, owner, route_guards))

    for call in _collect(root, "call"):
        fn = _text(call.child_by_field_name("function"))
        if not fn.endswith("add_url_rule"):
            continue
        args = _text(call.child_by_field_name("arguments"))[1:-1]
        parsed = _parse_route_call("add_url_rule", args)
        view = re.search(r"view_func\s*=\s*([\w\.]+)", args)
        if not parsed or not view:
            continue
        func = functions.get(view.group(1).rsplit(".", 1)[-1])
        if func is None:
            continue
        guards = []
        if func.parent is not None and func.parent.type == "decorated_definition":
            guards = [_text(c).strip() for c in func.parent.children if c.type == "decorator"]
        owner = fn.rsplit(".", 1)[0]
        routes.append((func, prefixes.get(owner, "") + parsed[0], parsed[1], owner, guards))

    route_funcs = {_text(r[0].child_by_field_name("name")) for r in routes}
    helpers = _python_helpers(functions, route_funcs, lines)

    handlers = []
    for func, path, methods, owner, guards in routes:
        name = _text(func.child_by_field_name("name"))
        handler = _new_handler(file_path, func.start_point[0] + 1, name, path, methods, PYTHON)
        _apply_guards(handler, guards, _PY_AUTH_GUARD)
        if owner in file_auth:
            handler.has_authentication = True
            handler.auth_evidence = (
                handler.auth_evidence or f"{owner}.before_request / dependencies"
            )

        params_text = _text(func.child_by_field_name("parameters"))
        identity_vars = []
        for dep in _FASTAPI_DEP.finditer(params_text):
            if _FASTAPI_AUTH_DEP.search(dep.group(2)):
                handler.has_authentication = True
                handler.auth_evidence = handler.auth_evidence or dep.group(0)
                if re.search(r"(?i)user|principal|identity", dep.group(2)):
                    identity_vars.append(dep.group(1))
        for param in handler.id_params:
            if re.search(rf"\b{re.escape(param)}\s*:\s*int\b", params_text):
                if param not in handler.numeric_id_params:
                    handler.numeric_id_params.append(param)

        if handler.id_params:
            body = func.child_by_field_name("body")
            if body is not None:
                body_lines = _body_lines(body, lines, _docstring_rows(func))
                analyze_handler(handler, body_lines, identity_vars=identity_vars, helpers=helpers)
        handlers.append(handler)
    return handlers


# ---------------------------------------------------------------------------
# JavaScript (Express)
# ---------------------------------------------------------------------------

_JS_FUNCTION_TYPES = {"arrow_function", "function_expression", "function", "function_declaration"}


def _js_functions(root: Node) -> dict[str, Node]:
    functions: dict[str, Node] = {}
    for fn in _collect(root, "function_declaration"):
        functions[_text(fn.child_by_field_name("name"))] = fn
    for decl in _collect(root, "variable_declarator"):
        value = decl.child_by_field_name("value")
        if value is not None and value.type in _JS_FUNCTION_TYPES:
            functions[_text(decl.child_by_field_name("name"))] = value
    return functions


def _js_file_auth(root: Node) -> bool:
    for call in _collect(root, "call_expression"):
        fn = call.child_by_field_name("function")
        if fn is None or fn.type != "member_expression":
            continue
        if _text(fn.child_by_field_name("property")) != "use":
            continue
        args = call.child_by_field_name("arguments")
        for arg in args.named_children if args is not None else []:
            if arg.type in ("string", "template_string"):
                continue
            if _JS_AUTH_GUARD.search(_text(arg)) and not _OWNERSHIP_GUARD.search(_text(arg)):
                return True
    return False


def _js_req_name(fn: Node) -> str:
    params = fn.child_by_field_name("parameters") or fn.child_by_field_name("parameter")
    if params is None:
        return "req"
    if params.type == "identifier":
        return _text(params)
    for child in params.named_children:
        if child.type == "identifier":
            return _text(child)
        if child.type == "assignment_pattern":
            return _text(child.child_by_field_name("left"))
    return "req"


def _js_mount_prefixes(root: Node) -> dict[str, str]:
    """``app.use("/api", router)`` -> {"router": "/api"}."""
    prefixes: dict[str, str] = {}
    for call in _collect(root, "call_expression"):
        fn = call.child_by_field_name("function")
        if fn is None or fn.type != "member_expression":
            continue
        if _text(fn.child_by_field_name("property")) != "use":
            continue
        args_node = call.child_by_field_name("arguments")
        args = args_node.named_children if args_node is not None else []
        if len(args) >= 2 and args[0].type == "string" and args[-1].type == "identifier":
            prefixes[_text(args[-1])] = _text(args[0]).strip("\"'`").rstrip("/")
    return prefixes


def _js_param_names(fn: Node) -> list[str]:
    params = fn.child_by_field_name("parameters") or fn.child_by_field_name("parameter")
    if params is None:
        return []
    if params.type == "identifier":
        return [_text(params)]
    names = []
    for i, child in enumerate(params.named_children):
        if child.type == "identifier":
            names.append(_text(child))
        elif child.type == "assignment_pattern":
            names.append(_text(child.child_by_field_name("left")))
        else:
            names.append(f"_arg{i}")
    return names


def _js_helpers(
    functions: dict[str, Node], route_nodes: set[int], lines: list[str]
) -> dict[str, HelperSummary]:
    helpers = {}
    for name, fn in functions.items():
        body = fn.child_by_field_name("body")
        if fn.id in route_nodes or body is None:
            continue
        params = _js_param_names(fn)
        helpers[name] = summarize_helper(
            name, params, _body_lines(body, lines, set()), JAVASCRIPT, _js_req_name(fn)
        )
    return helpers


def _javascript_handlers(root: Node, source: str, file_path: str) -> list[RouteHandler]:
    lines = source.splitlines()
    functions = _js_functions(root)
    file_auth = _js_file_auth(root)
    mounts = _js_mount_prefixes(root)
    handlers: list[RouteHandler] = []
    pending: list[tuple[RouteHandler, Node]] = []

    for call in _collect(root, "call_expression"):
        fn = call.child_by_field_name("function")
        if fn is None or fn.type != "member_expression":
            continue
        method = _text(fn.child_by_field_name("property")).lower()
        if method not in HTTP_METHODS and method != "all":
            continue
        args_node = call.child_by_field_name("arguments")
        args = args_node.named_children if args_node is not None else []
        if len(args) < 2 or args[0].type not in ("string", "template_string"):
            continue
        raw_path = _text(args[0]).strip("\"'`")
        if not raw_path.startswith("/"):
            continue

        handler_node = args[-1]
        if handler_node.type == "identifier":
            handler_node = functions.get(_text(handler_node), handler_node)
        if handler_node.type not in _JS_FUNCTION_TYPES:
            continue

        methods = [m.upper() for m in HTTP_METHODS] if method == "all" else [method.upper()]
        owner = _text(fn.child_by_field_name("object"))
        path = mounts.get(owner, "") + _clean_express_path(raw_path)
        handler = _new_handler(
            file_path,
            call.start_point[0] + 1,
            _text(handler_node.child_by_field_name("name")) or f"{method} {path}",
            path,
            methods,
            JAVASCRIPT,
        )
        for name, numeric in path_parameters(raw_path):
            if numeric and name in handler.id_params and name not in handler.numeric_id_params:
                handler.numeric_id_params.append(name)
        _apply_guards(handler, [_text(a) for a in args[1:-1]], _JS_AUTH_GUARD)
        if file_auth:
            handler.has_authentication = True
            handler.auth_evidence = handler.auth_evidence or "app.use(<auth middleware>)"

        pending.append((handler, handler_node))

    route_nodes = {node.id for _h, node in pending}
    helpers = _js_helpers(functions, route_nodes, lines)
    for handler, handler_node in pending:
        if handler.id_params:
            body = handler_node.child_by_field_name("body")
            if body is not None:
                analyze_handler(
                    handler,
                    _body_lines(body, lines, set()),
                    req_name=_js_req_name(handler_node),
                    helpers=helpers,
                )
        handlers.append(handler)
    return handlers


# ---------------------------------------------------------------------------
# Entry point del layer
# ---------------------------------------------------------------------------


def _walk_files(target: Path) -> Iterator[Path]:
    if target.is_file():
        yield target
        return
    for entry in sorted(target.rglob("*")):
        if not entry.is_file() or entry.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue
        if any(part in SKIP_DIRS for part in entry.parts):
            continue
        yield entry


def extract_handlers_from_file(file_path: Path) -> list[RouteHandler]:
    """Handler di rotta di un singolo file, con i fatti di autorizzazione già calcolati."""
    try:
        size = file_path.stat().st_size
        if size == 0 or size > MAX_FILE_SIZE:
            return []
        content = file_path.read_bytes()
    except OSError as exc:
        logger.warning("Cannot read %s: %s", file_path, exc)
        return []
    if b"\x00" in content[:8192]:
        return []

    language_name = PYTHON if file_path.suffix.lower() in PYTHON_EXTENSIONS else JAVASCRIPT
    language = _get_language(language_name)
    if language is None:
        return []
    try:
        tree = Parser(language).parse(content)
    except Exception as exc:
        logger.warning("Parse error in %s: %s", file_path, exc)
        return []

    source = content.decode("utf-8", errors="replace")
    extractor = _python_handlers if language_name == PYTHON else _javascript_handlers
    try:
        return extractor(tree.root_node, source, str(file_path))
    except Exception as exc:
        logger.warning("Handler extraction failed on %s: %s", file_path, exc)
        return []


def extract_handlers(target_path: str) -> list[RouteHandler]:
    """Tutti gli handler di rotta sotto ``target_path`` (file o directory)."""
    root = Path(target_path)
    if not root.exists():
        logger.error("Target path does not exist: %s", target_path)
        return []
    handlers: list[RouteHandler] = []
    for file_path in _walk_files(root):
        handlers.extend(extract_handlers_from_file(file_path))
    return handlers


_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def run_rules(handlers: list[RouteHandler]) -> list[ObjectAuthzFinding]:
    findings: list[ObjectAuthzFinding] = []
    for rule in RULES:
        try:
            findings.extend(rule(handlers))
        except Exception as exc:
            logger.warning("Rule %s failed: %s", rule.__qualname__, exc)
    return sorted(
        findings,
        key=lambda f: (
            _SEVERITY_ORDER.get(f.severity, 9),
            -f.confidence,
            f.file_path,
            f.line_number or 0,
            f.rule_id,
        ),
    )


def analyze_ast_with_handlers(
    target_path: str,
) -> tuple[list[ObjectAuthzFinding], list[RouteHandler]]:
    """Esegue il Layer 1: estrazione degli handler e regole OA-001…OA-005."""
    handlers = extract_handlers(target_path)
    return run_rules(handlers), handlers


def analyze_ast(target_path: str) -> list[ObjectAuthzFinding]:
    findings, _ = analyze_ast_with_handlers(target_path)
    return findings
