"""
How applications express an authorization check (BOPLA inference, B.3).

The inference phase asks this module which authorization contexts a syntax node opens for
its whole subtree (a role decorator on a function, a DRF `permission_classes` on a view, an
Express middleware in the route call, ...). The methodological criterion forbids telling the
module WHICH properties are protected; recognizing HOW frameworks declare a check is allowed.

The idioms live in a YAML catalog (config/scanner_configs/bopla-auth-idioms.yaml): names and
kinds of idioms per framework, plus the words that make a name an AUTHORIZATION check (role,
permission, scope, admin, staff, superuser, ...). Authentication-only checks (login_required,
IsAuthenticated, requireAuth, jwt_required) do not restrict properties and never count.
Without the catalog (missing or malformed file) only the historical role decorators are
recognized, as before the catalog existed.

Entry points:
  node_auth_contexts(node, lang) -> list[str]   tree-sitter node: contexts for its subtree
  line_auth_context(line) -> str | None         regex fallback, one stripped source line
  is_auth_decorator(text) -> bool               decorator source text, e.g. "@roles_required('admin')"
  is_reserved_python_function(func, tree)       stdlib-ast function reserved to a role (S02)
"""

from __future__ import annotations

import ast
import os
import re
from collections import OrderedDict
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml
from loguru import logger

_PROJECT_ROOT = Path(__file__).resolve().parents[3]

# Catalog path (absolute, or relative to the working directory or to the project root)
CATALOG_PATH = os.getenv(
    "BOPLA_AUTH_IDIOMS_CATALOG", "config/scanner_configs/bopla-auth-idioms.yaml"
)

# Role decorators recognized before the catalog existed: the built-in fallback
LEGACY_DECORATORS = (
    "roles_required",
    "require_role",
    "permission_required",
    "secured",
    "PreAuthorize",
    "HasRole",
    "Can",
    "Authorize",
    "check_auth",
)

# Kept for callers of the historical pattern (PropertyAuthorizationInferenceEngine)
DECORATOR_PATTERN = re.compile(
    r"@\s*(?:" + "|".join(LEGACY_DECORATORS) + r")\b.*",
    re.IGNORECASE,
)


def _lower_set(values) -> frozenset[str]:
    return frozenset(str(v).lower() for v in values or ())


@dataclass(frozen=True)
class IdiomCatalog:
    """The recognized idioms, grouped by kind (names compared case-insensitively)."""

    authorization_terms: frozenset[str] = frozenset()
    authentication_names: frozenset[str] = frozenset()
    decorators: frozenset[str] = field(default_factory=lambda: _lower_set(LEGACY_DECORATORS))
    argument_decorators: frozenset[str] = frozenset()
    decorator_name_terms: bool = False
    dependency_callees: frozenset[str] = frozenset()
    scope_keywords: frozenset[str] = frozenset()
    route_keywords: frozenset[str] = frozenset()
    class_attributes: frozenset[str] = frozenset()
    class_attributes_any: frozenset[str] = frozenset()
    class_bases: frozenset[str] = frozenset()
    route_methods: frozenset[str] = frozenset()
    route_languages: frozenset[str] = frozenset()
    chain_methods: frozenset[str] = frozenset()
    chain_languages: frozenset[str] = frozenset()
    wrapper_languages: frozenset[str] = frozenset()
    loaded: bool = False


DEFAULT_CATALOG = IdiomCatalog()


# ─── Catalog loading ─────────────────────────────────────────────────────────


def _resolve(path: str) -> Path | None:
    for candidate in (Path(path), _PROJECT_ROOT / path):
        if candidate.is_file():
            return candidate
    return None


def _parse_catalog(data: dict) -> IdiomCatalog:
    terms = data.get("terms") or {}
    idioms = data.get("idioms")
    if not isinstance(terms, dict) or not isinstance(idioms, list):
        raise ValueError("'terms' must be a mapping and 'idioms' a list")

    groups: dict[str, set[str]] = {}
    languages: dict[str, set[str]] = {}
    flags: set[str] = set()
    for idiom in idioms:
        if not isinstance(idiom, dict) or "kind" not in idiom:
            raise ValueError(f"idiom without kind: {idiom!r}")
        if idiom.get("enabled", True) is False:
            continue
        kind = str(idiom["kind"])
        flags.add(kind)
        groups.setdefault(kind, set()).update(str(n) for n in idiom.get("names") or ())
        languages.setdefault(kind, set()).update(
            str(n).lower() for n in idiom.get("languages") or ()
        )
        for key in ("scope_keywords", "route_keywords"):
            groups.setdefault(key, set()).update(str(n) for n in idiom.get(key) or ())

    return IdiomCatalog(
        authorization_terms=_lower_set(terms.get("authorization")),
        authentication_names=_lower_set(data.get("authentication_names")),
        decorators=_lower_set(groups.get("decorator")),
        argument_decorators=_lower_set(groups.get("decorator_with_arguments")),
        decorator_name_terms="decorator_name_terms" in flags,
        dependency_callees=frozenset(groups.get("dependency", ())),
        scope_keywords=frozenset(groups.get("scope_keywords", ())),
        route_keywords=frozenset(groups.get("route_keywords", ())),
        class_attributes=frozenset(groups.get("class_attribute", ())),
        class_attributes_any=frozenset(groups.get("class_attribute_any", ())),
        class_bases=_lower_set(groups.get("class_base")),
        route_methods=_lower_set(groups.get("route_middleware")),
        route_languages=frozenset(languages.get("route_middleware", ())),
        chain_methods=_lower_set(groups.get("middleware_chain")),
        chain_languages=frozenset(languages.get("middleware_chain", ())),
        wrapper_languages=frozenset(languages.get("handler_wrapper", ())),
        loaded=True,
    )


@lru_cache(maxsize=8)
def load_catalog(path: str | None = None) -> IdiomCatalog:
    """The catalog at `path` (default CATALOG_PATH), or the built-in fallback."""
    target = path or CATALOG_PATH
    resolved = _resolve(target)
    if resolved is None:
        logger.warning(f"Catalogo idiomi BOPLA assente ({target}): solo decoratori di ruolo.")
        return DEFAULT_CATALOG
    try:
        data = yaml.safe_load(resolved.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("the catalog is not a mapping")
        return _parse_catalog(data)
    except Exception as exc:  # malformed YAML or schema
        logger.warning(f"Catalogo idiomi BOPLA non valido ({resolved}: {exc}): uso i default.")
        return DEFAULT_CATALOG


def get_catalog() -> IdiomCatalog:
    return load_catalog(CATALOG_PATH)


# ─── Names ───────────────────────────────────────────────────────────────────

_STRING_LITERAL = re.compile(r"(\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|`[^`]*`)", re.S)
_IDENTIFIER = re.compile(r"[A-Za-z_$][\w$]*")


def _words(name: str) -> set[str]:
    """Words of an identifier, splitting snake_case and camelCase (IsAdminUser -> is/admin/user)."""
    words: set[str] = set()
    for part in re.findall(r"[A-Za-z0-9]+", name):
        words.update(w.lower() for w in re.findall(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])", part))
    return words


def is_authorization_name(name: str, catalog: IdiomCatalog | None = None) -> bool:
    """A name that declares an authorization check (requireAdmin, IsAdminUser, RolesGuard)."""
    cat = catalog or get_catalog()
    last = name.strip().split(".")[-1]
    if not last or last.lower() in cat.authentication_names:
        return False
    return bool(_words(last) & cat.authorization_terms)


def _mentions_authorization(text: str, cat: IdiomCatalog) -> bool:
    """An identifier outside string literals names an authorization check."""
    code = _STRING_LITERAL.sub(" ", text)
    return any(is_authorization_name(tok, cat) for tok in _IDENTIFIER.findall(code))


def _balanced(text: str, open_index: int) -> str:
    """Text inside the parenthesis opened at `open_index` (to the end if unbalanced)."""
    depth = 0
    for i in range(open_index, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[open_index + 1 : i]
    return text[open_index + 1 :]


def _dependency_contexts(text: str, cat: IdiomCatalog) -> list[str]:
    """FastAPI dependencies that authorize: Depends(require_admin), Security(f, scopes=[...])."""
    if not cat.dependency_callees:
        return []
    contexts = []
    for match in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", text):
        if match.group(1) not in cat.dependency_callees:
            continue
        inner = _balanced(text, match.end() - 1)
        scoped = any(
            re.search(rf"\b{re.escape(kw)}\s*=\s*[\[(]?\s*[\"']", inner)
            for kw in cat.scope_keywords
        )
        first = re.match(r"\s*(?:dependency\s*=\s*)?([A-Za-z_][\w.]*)", inner)
        if scoped or (first and is_authorization_name(first.group(1), cat)):
            contexts.append(f"{match.group(1)}({' '.join(inner.split())})")
    return contexts


def is_authorizing_decorator(text: str, catalog: IdiomCatalog | None = None) -> bool:
    """True when the decorator text (`@name(args)`) declares an authorization check."""
    cat = catalog or get_catalog()
    match = re.match(r"\s*@?\s*([A-Za-z_$][\w$.]*)", text)
    if not match:
        return False
    name = match.group(1).split(".")[-1]
    lowered = name.lower()
    args = text[match.end() :]
    if lowered in cat.authentication_names:
        return False
    if lowered in cat.decorators:
        return True
    if lowered in cat.argument_decorators:
        return _mentions_authorization(args, cat)
    if any(re.search(rf"\b{re.escape(kw)}\s*=", args) for kw in cat.route_keywords):
        if _dependency_contexts(args, cat):
            return True
    return cat.decorator_name_terms and is_authorization_name(name, cat)


def is_auth_decorator(text: str) -> bool:
    text = text.strip()
    return text.startswith("@") and is_authorizing_decorator(text)


def _class_attribute_context(name: str, value: str, cat: IdiomCatalog) -> str | None:
    if name in cat.class_attributes_any or (
        name in cat.class_attributes and _mentions_authorization(value, cat)
    ):
        return f"{name} = {' '.join(value.split())}"
    return None


# ─── Tree-sitter ─────────────────────────────────────────────────────────────


def _text(node) -> str:
    return node.text.decode("utf-8", errors="replace").strip()


_FUNCTION_LITERALS = {"arrow_function", "function_expression", "function", "func_literal"}
_ARGUMENT_LISTS = {"arguments", "argument_list"}
_STRINGS = {"string", "template_string", "interpreted_string_literal", "raw_string_literal"}
_JS_DECORATED = {"method_definition", "class_declaration", "class", "export_statement"}


def _decorator_children(node, cat: IdiomCatalog) -> list[str]:
    return [
        _text(child)
        for child in node.children
        if child.type == "decorator" and is_authorizing_decorator(_text(child), cat)
    ]


def _last_name(node) -> str:
    """Last component of a callee or reference (`app.get` -> get, `h.GetB` -> GetB)."""
    if node is None:
        return ""
    if node.type in ("member_expression", "selector_expression"):
        prop = node.child_by_field_name("property") or node.child_by_field_name("field")
        return _text(prop) if prop is not None else ""
    if node.type in ("identifier", "property_identifier", "field_identifier"):
        return _text(node)
    return ""


def _call_arguments(call) -> list:
    args = call.child_by_field_name("arguments")
    return [] if args is None else [c for c in args.named_children if c.type != "comment"]


def _middleware_name(arg) -> str:
    """Name of a middleware argument: requireAdmin, auth.requireAdmin, requireRole('admin')."""
    if arg.type == "call_expression":
        return _last_name(arg.child_by_field_name("function"))
    return _last_name(arg)


def _is_path(arg) -> bool:
    return arg.type in _STRINGS and _text(arg).strip("'\"`").startswith("/")


def _same(a, b) -> bool:
    return b is not None and (a.start_byte, a.end_byte, a.type) == (
        b.start_byte,
        b.end_byte,
        b.type,
    )


def _call_authorization(call, arg, lang: str, cat: IdiomCatalog) -> str | None:
    """
    Context that `call` gives to its handler argument `arg` (None: to every handler): an
    authorization wrapper (RequireRole("admin", h)), a route call with an authorization
    middleware among the other arguments (router.get('/x', requireAdmin, h)) or a chain
    r.With(AdminOnly).Get("/x", h).
    """
    function = call.child_by_field_name("function")
    name = _last_name(function)
    if lang in cat.wrapper_languages and is_authorization_name(name, cat):
        return f"wrapper({name})"
    args = _call_arguments(call)
    if (
        lang in cat.route_languages
        and name.lower() in cat.route_methods
        and args
        and _is_path(args[0])
    ):
        for other in args[1:]:
            middleware = _middleware_name(other)
            if not _same(other, arg) and middleware and is_authorization_name(middleware, cat):
                return f"middleware({middleware})"
    if lang in cat.chain_languages and function is not None:
        operand = function.child_by_field_name("operand") or function.child_by_field_name("object")
        if (
            operand is not None
            and operand.type == "call_expression"
            and _last_name(operand.child_by_field_name("function")).lower() in cat.chain_methods
        ):
            for middleware in map(_middleware_name, _call_arguments(operand)):
                if middleware and is_authorization_name(middleware, cat):
                    return f"middleware({middleware})"
    return None


def _literal_contexts(node, lang: str, cat: IdiomCatalog) -> list[str]:
    """A function literal passed (possibly through adapters) to an authorizing call."""
    child, parent = node, node.parent
    for _ in range(4):
        if parent is None or parent.type not in _ARGUMENT_LISTS:
            break
        call = parent.parent
        if call is None or call.type != "call_expression":
            break
        context = _call_authorization(call, child, lang, cat)
        if context:
            return [context]
        child, parent = call, call.parent
    return []


def _handler_refs(arg, cat: IdiomCatalog) -> list[str]:
    """Named handlers referenced by an argument (GetA in http.HandlerFunc(GetA))."""
    if arg.type == "call_expression":
        if is_authorization_name(_middleware_name(arg), cat):
            return []
        refs: list[str] = []
        for inner in _call_arguments(arg):
            refs.extend(_handler_refs(inner, cat))
        return refs
    name = _last_name(arg)
    if not name or name.lower() in cat.authentication_names or is_authorization_name(name, cat):
        return []
    return [name]


# Registry of named handlers per tree: {root.id: (root, lang, {name: context})}. Holding the
# root keeps its tree alive, so its id cannot be reused by another tree while cached.
_REGISTRY_CACHE: OrderedDict[int, tuple] = OrderedDict()
_REGISTRY_SIZE = 4


def _handler_registry(root, lang: str, cat: IdiomCatalog) -> dict[str, str]:
    cached = _REGISTRY_CACHE.get(root.id)
    if cached is not None and cached[0] == root and cached[1] == lang and cached[2] is cat:
        return cached[3]
    registry: dict[str, str] = {}
    stack = [root]
    while stack:
        current = stack.pop()
        if current.type == "call_expression":
            context = _call_authorization(current, None, lang, cat)
            if context:
                args = _call_arguments(current)
                for arg in args[1:] if args and _is_path(args[0]) else args:
                    for ref in _handler_refs(arg, cat):
                        registry.setdefault(ref, context)
        stack.extend(current.children)
    _REGISTRY_CACHE[root.id] = (root, lang, cat, registry)
    while len(_REGISTRY_CACHE) > _REGISTRY_SIZE:
        _REGISTRY_CACHE.popitem(last=False)
    return registry


def _definition_name(node) -> str:
    """Name of a function definition that a route may reference by name."""
    if node.type in ("function_declaration", "method_declaration", "method_definition"):
        return _last_name(node.child_by_field_name("name"))
    if node.type == "variable_declarator":
        value = node.child_by_field_name("value")
        if value is not None and value.type in _FUNCTION_LITERALS:
            return _last_name(node.child_by_field_name("name"))
    if node.type == "assignment_expression":
        right = node.child_by_field_name("right")
        if right is not None and right.type in _FUNCTION_LITERALS:
            return _last_name(node.child_by_field_name("left"))
    return ""


def _named_handler_contexts(node, lang: str, cat: IdiomCatalog) -> list[str]:
    name = _definition_name(node)
    if not name:
        return []
    root = node
    while root.parent is not None:
        root = root.parent
    context = _handler_registry(root, lang, cat).get(name)
    return [context] if context else []


def _python_class_contexts(node, cat: IdiomCatalog) -> list[str]:
    contexts = []
    bases = node.child_by_field_name("superclasses")
    if bases is not None:
        for base in bases.named_children:
            if _text(base).split(".")[-1].lower() in cat.class_bases:
                contexts.append(f"class({_text(base)})")
    body = node.child_by_field_name("body")
    for statement in body.named_children if body is not None else ():
        if statement.type != "expression_statement" or not statement.named_children:
            continue
        assignment = statement.named_children[0]
        left = assignment.child_by_field_name("left")
        right = assignment.child_by_field_name("right")
        if assignment.type == "assignment" and left is not None and right is not None:
            context = _class_attribute_context(_text(left), _text(right), cat)
            if context:
                contexts.append(context)
    return contexts


def node_auth_contexts(node, lang: str) -> list[str]:
    """Authorization contexts that `node` opens for every node below it."""
    cat = get_catalog()
    node_type = node.type
    if node_type in ("decorator", "annotation"):
        text = _text(node)
        return [text] if is_authorizing_decorator(text, cat) else []
    if node_type == "decorated_definition":
        # The decorator is a sibling of the function it guards: propagate it to the whole
        # definition so accesses in the function body inherit the context.
        return _decorator_children(node, cat)
    if lang == "python":
        if node_type == "function_definition":
            parameters = node.child_by_field_name("parameters")
            return [] if parameters is None else _dependency_contexts(_text(parameters), cat)
        if node_type == "class_definition":
            return _python_class_contexts(node, cat)
        return []

    contexts: list[str] = []
    if node_type in _JS_DECORATED:
        # NestJS: @Roles/@UseGuards are children of the method or class they guard
        contexts.extend(_decorator_children(node, cat))
    if lang in cat.route_languages | cat.wrapper_languages | cat.chain_languages:
        if node_type in _FUNCTION_LITERALS:
            contexts.extend(_literal_contexts(node, lang, cat))
        else:
            contexts.extend(_named_handler_contexts(node, lang, cat))
    return contexts


# ─── Regex fallback ──────────────────────────────────────────────────────────

_ROUTE_LINE = re.compile(r"\.\s*([A-Za-z]+)\s*\(\s*(['\"`])/[^'\"`]*\2\s*,(.*)$")


def _split_top_level(text: str) -> list[str]:
    parts, depth, current = [], 0, []
    for char in text:
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        if char == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def line_auth_context(line: str) -> str | None:
    """Regex fallback: the authorization context opened by this line, if any."""
    if is_auth_decorator(line):
        return line
    cat = get_catalog()
    route = _ROUTE_LINE.search(line)
    if (
        route
        and route.group(1).lower() in cat.route_methods
        and "typescript" in (cat.route_languages)
    ):
        for argument in _split_top_level(route.group(3)):
            argument = argument.strip()
            if "=>" in argument or argument.startswith(("function", "async")):
                break  # the handler starts here: middlewares come before it
            name = re.match(r"[A-Za-z_$][\w$.]*", argument)
            if name and is_authorization_name(name.group(0), cat):
                return line
    return None


# ─── Stdlib ast (static rule S02) ────────────────────────────────────────────

_PARENTS_CACHE: dict[int, tuple] = {}


def _enclosing_classes(func: ast.AST, tree: ast.AST) -> list[ast.ClassDef]:
    cached = _PARENTS_CACHE.get(id(tree))
    if cached is None or cached[0] is not tree:
        parents = {
            id(child): parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)
        }
        _PARENTS_CACHE.clear()
        _PARENTS_CACHE[id(tree)] = cached = (tree, parents)
    parents = cached[1]
    classes = []
    current = parents.get(id(func))
    while current is not None:
        if isinstance(current, ast.ClassDef):
            classes.append(current)
        current = parents.get(id(current))
    return classes


def is_reserved_python_function(func: ast.FunctionDef | ast.AsyncFunctionDef, tree) -> bool:
    """
    The function is reserved to a role or permission: authorization decorator, FastAPI
    dependency among its parameters, or an enclosing class guarded by DRF permission_classes,
    a permission mixin or a role decorator.
    """
    cat = get_catalog()
    if any(is_auth_decorator("@" + ast.unparse(d)) for d in func.decorator_list):
        return True
    if _dependency_contexts(ast.unparse(func.args), cat):
        return True
    for cls in _enclosing_classes(func, tree):
        if any(is_auth_decorator("@" + ast.unparse(d)) for d in cls.decorator_list):
            return True
        if any(ast.unparse(b).split(".")[-1].lower() in cat.class_bases for b in cls.bases):
            return True
        for statement in cls.body:
            if (
                isinstance(statement, ast.Assign)
                and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name)
                and _class_attribute_context(
                    statement.targets[0].id, ast.unparse(statement.value), cat
                )
            ):
                return True
    return False
