"""
BOPLA-S01 — Static mass assignment rule (OWASP API3:2023, write direction).

Looks for the classic static signature of mass assignment: the whole request body bound to
an entity without a list of accepted fields. The rule does not need to know which properties
are protected (the methodological criterion forbids telling it): it reports the missing
allowlist. Properties inferred as protected by the inference phase only raise the severity.

Recognized bindings:
  Python (stdlib ast, precise):
    - `for k, v in <body>.items(): setattr(obj, k, v)`
    - `Entity(**<body>)`, `obj.update(**<body>)`, `Model.objects.create(**<body>)`
    - `obj.__dict__.update(<body>)`, `store[key].update(<body>)`, `query.update(<body>)`
    - Django REST Framework ModelSerializer with `fields = "__all__"` and no read-only fields
  JavaScript / TypeScript (regex):
    - `Object.assign(entity, req.body)`, `Model.create(req.body)`, `new Model(req.body)`,
      `.update(...req.body)` and the like, also through a variable holding `req.body`
  Go (regex):
    - `json.NewDecoder(r.Body).Decode(&x)` / `c.ShouldBindJSON(&x)` followed by
      `db.Save(&x)` / `Create` / `Updates` of the same variable

Keys filtered by an allowlist (`if k in ALLOWED`, `if k not in ALLOWED: continue`, a dict
comprehension filtered with `in`, `_.pick`) suppress the finding. A denylist (`if k != "id"`)
does not: it is reported as a partial guard.

Entry point: scan_mass_assignment(repo_path, evidences) -> list[StaticPropertyFinding]
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from loguru import logger

from src.core.api3_bopla.discovery import PropertyDiscoveryEngine, collect_source_files
from src.core.api3_bopla.models import PropertyEvidence, StaticPropertyFinding
from src.core.api3_bopla.property_inference import PropertyAuthorizationInferenceEngine

RULE_ID = "BOPLA-S01"

# Framework expressions that hold the request body (Flask, Django, DRF, FastAPI/Starlette)
PY_REQUEST_BODY = re.compile(
    r"^(?:self\.)?request\.(?:json|get_json\(.*\)|form|data|values|POST|json\(\))$"
)
# Parameters that, by name, carry the request body in framework-free handlers
PY_BODY_PARAMS = {
    "body",
    "payload",
    "json_data",
    "request_data",
    "request_body",
    "updates",
    "changes",
    "attrs",
    "attributes",
}
# ORM / store methods that accept a whole mapping as the new state of an entity
PY_BULK_METHODS = {"create", "update", "update_or_create", "get_or_create", "insert", "upsert"}
PY_ROUTE_DECORATOR = re.compile(r"\.(route|get|post|put|patch|delete|api_route)$")
PY_HTTP_METHOD_NAMES = {"get", "post", "put", "patch", "delete"}

CONFIDENCE_FRAMEWORK_SOURCE = 0.8
CONFIDENCE_PARAM_SOURCE = 0.6
CONFIDENCE_REGEX = 0.7
CONFIDENCE_SERIALIZER = 0.6


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------


def _text(node: ast.AST) -> str:
    return ast.unparse(node)


class _FunctionScanner:
    """Mass assignment inside one function: taint from the request body to bulk bindings."""

    def __init__(self, func: ast.FunctionDef | ast.AsyncFunctionDef, file_path: str):
        self.func = func
        self.file_path = file_path
        self.tainted: dict[str, tuple[str, float]] = {}  # name -> (source text, confidence)
        self.assigned_from: dict[str, ast.expr] = {}
        self.results: list[dict] = []
        for arg in func.args.args + func.args.kwonlyargs:
            if arg.arg in PY_BODY_PARAMS:
                self.tainted[arg.arg] = (arg.arg, CONFIDENCE_PARAM_SOURCE)

    # -- taint ---------------------------------------------------------------
    def source_of(self, expr: ast.expr | None) -> tuple[str, float] | None:
        """(source text, confidence) when expr carries the request body, unfiltered."""
        if expr is None:
            return None
        if isinstance(expr, ast.Await):
            return self.source_of(expr.value)
        text = _text(expr)
        if PY_REQUEST_BODY.match(text):
            return text, CONFIDENCE_FRAMEWORK_SOURCE
        if isinstance(expr, ast.Name):
            return self.tainted.get(expr.id)
        if isinstance(expr, ast.BoolOp):  # body or {}
            for value in expr.values:
                found = self.source_of(value)
                if found:
                    return found
        if isinstance(expr, ast.Subscript):  # request.json["user"]
            return self.source_of(expr.value)
        if isinstance(expr, ast.Call):
            func = expr.func
            if isinstance(func, ast.Name) and func.id in {"dict", "loads"} and expr.args:
                return self.source_of(expr.args[0])
            if isinstance(func, ast.Attribute):
                if func.attr in {"copy", "get", "to_dict", "dict"}:
                    return self.source_of(func.value)
                if func.attr == "loads" and expr.args:  # json.loads(request.body)
                    inner = _text(expr.args[0])
                    if re.match(r"^(?:self\.)?request\.body$", inner):
                        return inner, CONFIDENCE_FRAMEWORK_SOURCE
        if isinstance(expr, ast.DictComp) and not _filtered_by_allowlist(expr):
            for generator in expr.generators:
                found = self.source_of(_iterated_mapping(generator.iter))
                if found:
                    return found
        return None

    def run(self) -> list[dict]:
        for node in _walk_in_order(self.func):
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if isinstance(target, ast.Name):
                    self.assigned_from[target.id] = node.value
                    found = self.source_of(node.value)
                    if found:
                        self.tainted[target.id] = found
                    else:
                        self.tainted.pop(target.id, None)
            elif isinstance(node, ast.For):
                self._check_setattr_loop(node)
            elif isinstance(node, ast.Call):
                self._check_bulk_call(node)
        return self.results

    # -- sinks ---------------------------------------------------------------
    def _check_setattr_loop(self, loop: ast.For) -> None:
        found = self.source_of(_iterated_mapping(loop.iter))
        if not found:
            return
        key = _loop_key(loop.target)
        if key is None:
            return
        for call, guards in _setattr_calls(loop.body, key):
            verdict, guard_text = _judge_guards(guards)
            if verdict == "allow":
                continue
            receiver = call.args[0]
            self._report(
                call,
                source=found,
                sink=_text(call),
                entity=self._entity_of(receiver),
                guard=guard_text,
            )

    def _check_bulk_call(self, call: ast.Call) -> None:
        func = call.func
        # Entity(**body), obj.update(**body), Model.objects.create(**body)
        for kw in call.keywords:
            if kw.arg is not None:
                continue
            found = self.source_of(kw.value)
            if not found:
                continue
            if isinstance(func, ast.Name) and func.id[:1].isupper():
                self._report(call, source=found, sink=_text(call), entity=func.id)
            elif isinstance(func, ast.Attribute) and func.attr in PY_BULK_METHODS:
                self._report(
                    call, source=found, sink=_text(call), entity=self._entity_of(func.value)
                )
            return
        # obj.__dict__.update(body), store[key].update(body), query.update(body)
        if isinstance(func, ast.Attribute) and func.attr == "update" and call.args:
            found = self.source_of(call.args[0])
            if not found or not _is_entity_store(func.value):
                return
            self._report(call, source=found, sink=_text(call), entity=self._entity_of(func.value))

    # -- helpers -------------------------------------------------------------
    def _entity_of(self, expr: ast.expr) -> str | None:
        return resolve_entity(expr, self.assigned_from)

    def _report(
        self,
        node: ast.AST,
        *,
        source: tuple[str, float],
        sink: str,
        entity: str | None,
        guard: str | None = None,
    ) -> None:
        self.results.append(
            {
                "line": node.lineno,
                "source": source[0],
                "confidence": source[1],
                "sink": sink,
                "entity": entity,
                "guard": guard,
                "function": self.func.name,
                "endpoint": _python_endpoint(self.func),
            }
        )


def resolve_entity(expr: ast.expr, assigned_from: dict[str, ast.expr]) -> str | None:
    """Best-effort entity name of an object, from its expression or how it was obtained."""
    text = _text(expr)
    match = re.match(r"^([A-Z]\w*)\.(?:objects|query)\b", text)
    if match:
        return match.group(1)
    if isinstance(expr, ast.Attribute) and expr.attr == "__dict__":
        return resolve_entity(expr.value, assigned_from)
    if isinstance(expr, ast.Subscript):
        key = expr.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            return key.value  # DB["users"] -> users
        return resolve_entity(expr.value, assigned_from)
    if isinstance(expr, ast.Name):
        origin = assigned_from.get(expr.id)
        if origin is not None:
            origin_text = _text(origin)
            for pattern in (
                r"\b([A-Z]\w*)\.(?:objects|query)\b",
                r"get_object_or_404\(\s*([A-Z]\w*)",
                r"^([A-Z]\w*)\(",
                r"\[\s*['\"](\w+)['\"]\s*\]",
            ):
                found = re.search(pattern, origin_text)
                if found:
                    return found.group(1)
        return expr.id  # user -> User after normalization
    return None


def _walk_in_order(node: ast.AST):
    """Pre-order walk that keeps statement order (ast.walk is breadth-first)."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue  # nested scopes are scanned on their own
        yield child
        yield from _walk_in_order(child)


def _iterated_mapping(expr: ast.expr) -> ast.expr | None:
    """`body.items()` / `body.keys()` / `body` -> body."""
    if (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Attribute)
        and expr.func.attr in {"items", "keys"}
    ):
        return expr.func.value
    return expr


def _loop_key(target: ast.expr) -> str | None:
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Tuple) and target.elts and isinstance(target.elts[0], ast.Name):
        return target.elts[0].id
    return None


def _key_comparison(test: ast.expr, key: str) -> str | None:
    """'allow' / 'deny' when `test` compares the loop key with a set of names."""
    if not isinstance(test, ast.Compare) or len(test.ops) != 1:
        return None
    if not (isinstance(test.left, ast.Name) and test.left.id == key):
        return None
    op = test.ops[0]
    if isinstance(op, (ast.In, ast.Eq)):
        return "allow"
    if isinstance(op, (ast.NotIn, ast.NotEq)):
        return "deny"
    return None


def _exits(body: list[ast.stmt]) -> bool:
    return bool(body) and isinstance(body[-1], (ast.Continue, ast.Return, ast.Raise))


def _setattr_calls(body: list[ast.stmt], key: str):
    """Yields (setattr call, guards on the key) for setattr(obj, key, ...) in a loop body."""

    def visit(stmts: list[ast.stmt], guards: list[tuple[str, str]]):
        guards = list(guards)
        for stmt in stmts:
            if isinstance(stmt, ast.If):
                kind = _key_comparison(stmt.test, key)
                if kind and _exits(stmt.body):
                    # `if k not in ALLOWED: continue` guards what follows (and flips meaning)
                    guards.append(("allow" if kind == "deny" else "deny", _text(stmt.test)))
                    continue
                inner = guards + ([(kind, _text(stmt.test))] if kind else [])
                yield from visit(stmt.body, inner)
                yield from visit(stmt.orelse, guards)
                continue
            if isinstance(stmt, (ast.For, ast.While, ast.With, ast.Try)):
                for field in ("body", "orelse", "finalbody"):
                    yield from visit(getattr(stmt, field, []) or [], guards)
                for handler in getattr(stmt, "handlers", []):
                    yield from visit(handler.body, guards)
                continue
            for node in ast.walk(stmt):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "setattr"
                    and len(node.args) >= 2
                    and isinstance(node.args[1], ast.Name)
                    and node.args[1].id == key
                ):
                    yield node, guards

    yield from visit(body, [])


def _judge_guards(guards: list[tuple[str, str]]) -> tuple[str, str | None]:
    if any(kind == "allow" for kind, _ in guards):
        return "allow", None
    deny = [text for kind, text in guards if kind == "deny"]
    return ("deny", "denylist: " + "; ".join(deny)) if deny else ("none", None)


def _filtered_by_allowlist(comp: ast.DictComp) -> bool:
    return any(
        isinstance(cond, ast.Compare) and isinstance(cond.ops[0], (ast.In, ast.Eq))
        for generator in comp.generators
        for cond in generator.ifs
    )


def _is_entity_store(receiver: ast.expr) -> bool:
    """Receivers whose .update(mapping) writes an entity, not a scratch dict."""
    text = _text(receiver)
    if isinstance(receiver, ast.Attribute) and receiver.attr == "__dict__":
        return True
    if isinstance(receiver, ast.Subscript):
        return True
    return bool(re.search(r"\b(?:query|objects|filter|filter_by|where)\b", text))


def _python_endpoint(func: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    for decorator in func.decorator_list:
        call = decorator if isinstance(decorator, ast.Call) else None
        target = call.func if call else decorator
        match = PY_ROUTE_DECORATOR.search(_text(target))
        if not match or not call or not call.args:
            continue
        path_node = call.args[0]
        if not (isinstance(path_node, ast.Constant) and isinstance(path_node.value, str)):
            continue
        kind = match.group(1).upper()
        if kind in {"ROUTE", "API_ROUTE"}:
            methods = next((kw.value for kw in call.keywords if kw.arg == "methods"), None)
            names = re.findall(r"['\"](\w+)['\"]", _text(methods)) if methods else ["GET"]
            kind = "|".join(sorted(n.upper() for n in names))
        return f"{kind} {path_node.value}"
    if func.name in PY_HTTP_METHOD_NAMES:  # class-based views (DRF APIView, Django View)
        return func.name.upper()
    return None


def _drf_all_fields_serializers(tree: ast.Module) -> list[dict]:
    """ModelSerializer subclasses exposing every model field for writing."""
    results = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        if not any(_text(base).endswith("ModelSerializer") for base in node.bases):
            continue
        meta = next(
            (n for n in node.body if isinstance(n, ast.ClassDef) and n.name == "Meta"), None
        )
        if meta is None:
            continue
        values = {
            t.id: stmt.value
            for stmt in meta.body
            if isinstance(stmt, ast.Assign)
            for t in stmt.targets
            if isinstance(t, ast.Name)
        }
        fields = values.get("fields")
        if not (isinstance(fields, ast.Constant) and fields.value == "__all__"):
            continue
        if "read_only_fields" in values:
            continue
        model = values.get("model")
        results.append(
            {
                "line": node.lineno,
                "source": "serializer input (request.data)",
                "confidence": CONFIDENCE_SERIALIZER,
                "sink": f'{node.name}.Meta.fields = "__all__"',
                "entity": _text(model) if model is not None else None,
                "guard": None,
                "function": node.name,
                "endpoint": None,
            }
        )
    return results


def scan_python_file(path: Path) -> list[dict]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
    except SyntaxError:
        return []
    results: list[dict] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            results.extend(_FunctionScanner(node, str(path)).run())
    results.extend(_drf_all_fields_serializers(tree))
    unique = {(r["line"], r["sink"]): r for r in results}  # nested loops can report twice
    return list(unique.values())


# ---------------------------------------------------------------------------
# JavaScript / TypeScript
# ---------------------------------------------------------------------------

_JS_BODY = r"(?:req|request|ctx\.request)\.body"
# The whole body: not followed by a property access (req.body.name, req.body["x"])
_JS_WHOLE = r"(?![\w$]|\s*(?:\.|\?\.|\[))"
_JS_ROUTE = re.compile(r"\b\w+\.(get|post|put|patch|delete)\(\s*[\"'`]([^\"'`]+)")
_JS_SANITIZERS = re.compile(r"\b(?:pick|only|allowlist|whitelist)\s*\(")


def _js_patterns(body: str) -> list[re.Pattern]:
    whole = f"(?:{body}){_JS_WHOLE}"
    return [
        re.compile(rf"Object\.assign\(\s*([\w$.\[\]'\"]+)\s*,\s*(?:\{{\s*\.\.\.)?\s*({whole})"),
        re.compile(rf"new\s+([A-Z][\w$]*)\(\s*(?:\{{\s*\.\.\.)?\s*({whole})"),
        re.compile(
            r"([\w$.]+)\.(?:create|update|updateOne|updateMany|findByIdAndUpdate|"
            r"findOneAndUpdate|insert|insertOne|build|merge|upsert|save)"
            rf"\((?:[^;()]*,)?\s*(?:\{{\s*)?(?:\.\.\.)?\s*({whole})"
        ),
    ]


_JS_RECEIVER_NOISE = {"this", "prisma", "db", "models", "repository", "repo"}


def _js_entity(receiver: str) -> str | None:
    """User.create -> User, this.userRepository.save -> user, db.users.insert -> users."""
    parts = [p for p in re.split(r"[.\[\]'\"]+", receiver) if p]
    parts = [p for p in parts if p.lower() not in _JS_RECEIVER_NOISE] or parts
    if not parts:
        return None
    return re.sub(r"(?:Repository|Repo|Collection|Service|Model)$", "", parts[-1]) or parts[-1]


def scan_js_file(path: Path) -> list[dict]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    results: list[dict] = []
    # Variables holding the whole body: const data = req.body;
    aliases = {
        m.group(1)
        for line in lines
        for m in [re.search(rf"(?:const|let|var)\s+([\w$]+)\s*=\s*{_JS_BODY}\s*;?\s*$", line)]
        if m
    }
    patterns = [p for src in [_JS_BODY, *map(re.escape, aliases)] for p in _js_patterns(src)]
    route = None
    for number, line in enumerate(lines, 1):
        route_match = _JS_ROUTE.search(line)
        if route_match:
            route = f"{route_match.group(1).upper()} {route_match.group(2)}"
        if _JS_SANITIZERS.search(line):
            continue
        for pattern in patterns:
            match = pattern.search(line)
            if not match:
                continue
            results.append(
                {
                    "line": number,
                    "source": match.group(2),
                    "confidence": CONFIDENCE_REGEX,
                    "sink": line.strip(),
                    "entity": _js_entity(match.group(1)),
                    "guard": None,
                    "function": None,
                    "endpoint": route,
                }
            )
            break
    return results


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------

_GO_BIND = re.compile(
    r"(?:json\.NewDecoder\(\s*\w+\.Body\s*\)\.Decode|\.(?:ShouldBindJSON|BindJSON|ShouldBind|Bind))"
    r"\(\s*&(\w+)\s*\)"
)
_GO_SAVE = r"\.(?:Save|Create|Updates|Update|InsertOne|ReplaceOne|UpdateOne)\([^\n]*?&?\b{var}\b"
_GO_WINDOW = 60


def scan_go_file(path: Path) -> list[dict]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    results: list[dict] = []
    for number, line in enumerate(lines, 1):
        bind = _GO_BIND.search(line)
        if not bind:
            continue
        var = bind.group(1)
        save = re.compile(_GO_SAVE.format(var=re.escape(var)))
        for offset, later in enumerate(lines[number : number + _GO_WINDOW], number + 1):
            if save.search(later):
                entity = None
                decl = re.compile(rf"\b(?:var\s+{var}\s+\*?|{var}\s*:?=\s*&?)([\w.]+)")
                for previous in lines[max(0, number - _GO_WINDOW) : number]:
                    found = decl.search(previous)
                    if found:
                        entity = found.group(1).split(".")[-1]
                results.append(
                    {
                        "line": offset,
                        "source": bind.group(0),
                        "confidence": CONFIDENCE_REGEX,
                        "sink": later.strip(),
                        "entity": entity or var,
                        "guard": None,
                        "function": None,
                        "endpoint": None,
                    }
                )
                break
    return results


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_SCANNERS = {
    "python": scan_python_file,
    "javascript": scan_js_file,
    "typescript": scan_js_file,
    "go": scan_go_file,
}


def canonical_entity(name: str | None) -> str | None:
    if not name:
        return None
    cleaned = PropertyDiscoveryEngine.clean_object_name(name)
    # users -> User, reuse the path singularization
    return PropertyDiscoveryEngine.get_object_name_from_path(f"/{cleaned}") or cleaned


def scan_mass_assignment(
    repo_path: str, evidences: list[PropertyEvidence] | None = None
) -> list[StaticPropertyFinding]:
    """
    Runs BOPLA-S01 on every supported source file of the repository. Properties inferred as
    protected for the bound entity are listed as at risk and raise the severity to HIGH.
    """
    protected: dict[str, list[str]] = {}
    for ev in evidences or []:
        # S01 is about writing: a contract writeOnly (e.g. password) is legitimately sent
        if PropertyAuthorizationInferenceEngine.is_protected_property(ev, direction="write"):
            protected.setdefault(ev.object_name.lower(), []).append(ev.property)

    findings: list[StaticPropertyFinding] = []
    root = Path(repo_path)
    for file_path, language in collect_source_files(repo_path):
        try:
            raw = _SCANNERS[language](file_path)
        except Exception as exc:
            logger.warning(f"BOPLA-S01: analisi fallita su {file_path}: {exc}")
            continue
        for item in raw:
            entity = canonical_entity(item["entity"])
            at_risk = sorted(protected.get((entity or "").lower(), []))
            evidence = [
                f"Il corpo della richiesta ({item['source']}) è legato all'entità "
                f"{entity or 'non risolta'} senza una lista dei campi ammessi."
            ]
            if item["guard"]:
                evidence.append(
                    f"Solo una denylist sulle chiavi ({item['guard']}): i campi non elencati "
                    "restano scrivibili."
                )
            if at_risk:
                evidence.append(
                    f"Proprietà inferite come protette esposte alla scrittura: {', '.join(at_risk)}."
                )
            findings.append(
                StaticPropertyFinding(
                    rule_id=RULE_ID,
                    kind="mass_assignment",
                    file_path=str(file_path.relative_to(root)),
                    line=item["line"],
                    language=language,
                    endpoint=item["endpoint"],
                    entity=entity,
                    source=item["source"],
                    sink=item["sink"],
                    guard=item["guard"],
                    properties_at_risk=at_risk,
                    severity="HIGH" if at_risk else "MEDIUM",
                    confidence=item["confidence"],
                    evidence=evidence,
                )
            )
    return findings
