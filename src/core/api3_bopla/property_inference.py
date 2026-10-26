import contextlib
import json
import re
from typing import Any

from loguru import logger

from src.core.api2_broken_auth.discovery import StackInfo
from src.core.api3_bopla import access_patterns, auth_idioms, contract
from src.core.api3_bopla.discovery import (
    PropertyDiscoveryEngine,
    collect_source_files,
    get_installed_parser,
)

# Import models
from src.core.api3_bopla.models import (
    ObjectGraphNode,
    PropertyAuthorizationGraph,
    PropertyEvidence,
    PropertyGraphNode,
    PropertyInventory,
)
from src.normalization.normalizer import APIEndpointNormalizer


class PropertyAuthorizationInferenceEngine:
    """
    PropertyAuthorizationInferenceEngine infers which properties are subject to
    authorization checks. It analyzes source files (AST & regex), OpenAPI specs,
    and runtime traffic to build PropertyEvidence and a PropertyAuthorizationGraph.
    """

    # Matched against whole identifiers of the condition, not substrings: generic words such as
    # "user" or "can" would turn every `if user is None` into an authorization context.
    # Authorization terms only. Authentication words (current_user, auth, token, identity) are
    # left out: `if current_user:` or `if credentials.get("token")` only say the request has an
    # identity, and every authenticated user sees the same properties. `scope` in the singular
    # is also the ASGI request dictionary (`scope["type"] == "http"`); OAuth scopes are plural.
    AUTH_KEYWORDS = {
        "role",
        "roles",
        "admin",
        "is_admin",
        "is_staff",
        "is_superuser",
        "superuser",
        "staff",
        "permissions",
        "permission",
        "perm",
        "perms",
        "scopes",
        "hasrole",
        "rbac",
        "acl",
    }

    # An ownership check (`current_user.id != user.id`) protects the object, not its properties:
    # the owner passes it and reads every field.
    IDENTITY_CHECK = re.compile(
        r"\b(?:id|owner|owner_id|user_id|pk)\b\s*(?:!=|==)"
        r"|(?:!=|==)\s*[\w.]*\b(?:id|owner|owner_id|user_id|pk)\b"
    )
    # Calls that end the request (Flask/Werkzeug abort, Django/DRF helpers)
    EXIT_CALLS = {"abort", "abort_with", "permission_denied", "forbidden"}
    EXIT_STATEMENTS = {
        "return_statement",
        "raise_statement",
        "throw_statement",
        "continue_statement",
    }
    # A guard denies access when its condition is negated or its body refuses the request
    NEGATED_CONDITION = re.compile(
        r"^\(?\s*(?:not\b|!)|!=|\bnot\s+in\b|\bis\s+None\b|===?\s*false\b|==\s*False\b"
    )
    DENIAL_BODY = re.compile(
        r"\b40[13]\b|forbidden|unauthori[sz]ed|permission\s*denied|PermissionDenied|"
        r"access\s*denied|StatusForbidden|StatusUnauthorized",
        re.IGNORECASE,
    )

    # Exits that refuse the request without producing a result
    REFUSING_EXIT = re.compile(
        r"^(?:raise\b|throw\b|continue\b|(?:[\w.]+\.)?(?:abort|abort_with|permission_denied|"
        r"forbidden)\s*\(|return\s*(?:None|null|nil|false|False|undefined)?\s*;?$)"
    )
    # Regex fallback: a statement that leaves the function, and the start of a new function
    REGEX_EXIT = re.compile(
        r"^(?:return\b|raise\b|throw\b|continue\b|(?:[\w.]+\.)?(?:abort|abort_with|"
        r"permission_denied|forbidden)\s*\()"
    )
    FUNCTION_START = re.compile(
        r"^\s*(?:export\s+)?(?:async\s+)?(?:def|function|func)\b"
        r"|^\s*(?:export\s+)?(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*=>"
    )

    # Minimum confidence for a property with an authorization context to be tested dynamically.
    PROTECTED_CONFIDENCE_THRESHOLD = 0.4

    # Kept for callers of the class attribute; the idioms live in auth_idioms.py
    DECORATOR_PATTERN = auth_idioms.DECORATOR_PATTERN

    @classmethod
    def _is_auth_expression(cls, expr: str) -> bool:
        """
        Helper to determine if an expression contains authorization-related identifiers.
        Whole identifiers are compared; camelCase ones also by their words (`isAdmin`,
        `IsAdmin`, `hasRole` in JS/Go); snake_case ones also by their last word
        (`has_permission`, `user_role`), so that `user_role_id` does not turn into `role`.
        """
        tokens: set[str] = set()
        for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", expr):
            tokens.add(tok.lower())
            if "_" in tok:
                # snake_case counts by its last word: has_permission, user_role, but not
                # user_role_id
                tokens.add(tok.rstrip("_").rsplit("_", 1)[-1].lower())
            else:
                tokens.update(
                    w.lower() for w in re.findall(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])", tok)
                )
        return bool(tokens & cls.AUTH_KEYWORDS)

    @classmethod
    def is_protected_property(
        cls,
        evidence: PropertyEvidence,
        threshold: float | None = None,
        direction: str | None = None,
    ) -> bool:
        """
        A property is inferred as protected when the code shows an authorization context around
        it and its confidence reaches the threshold. Confidence alone rewards how documented and
        used a property is, so without a context even an ordinary field would qualify.

        `direction` ("read" or "write") keeps only the contexts that reserve that direction:
        a contract readOnly reserves writing (the value is legitimately returned), a contract
        writeOnly reserves reading (the client legitimately sends it). Without a direction
        every context counts.
        """
        limit = cls.PROTECTED_CONFIDENCE_THRESHOLD if threshold is None else threshold
        contexts = evidence.authorization_contexts
        if direction == "read":
            contexts = [c for c in contexts if c != "contract(readOnly)"]
        elif direction == "write":
            contexts = [c for c in contexts if c != "contract(writeOnly)"]
        return bool(contexts) and evidence.confidence >= limit

    @classmethod
    def analyze_ast_authorization_contexts(
        cls,
        repo_path: str,
        lang_name: str | None,
        discovered_props: dict[str, set[str]],
    ) -> dict[str, dict[str, list[str]]]:
        """
        Scans source files using tree-sitter or regex fallback to locate properties
        accessed within authorization checks (if conditions or decorated functions).
        Each file is read with the grammar of its own language; `lang_name` restricts
        the scan to one language.
        Returns a dict: {object_name: {property_name: [contexts]}}
        """
        results = {obj: {prop: [] for prop in props} for obj, props in discovered_props.items()}
        language = lang_name.lower().strip() if lang_name else None

        for file_path, file_lang in collect_source_files(repo_path, language):
            try:
                bytes_content = file_path.read_bytes()
                tree_sitter_succeeded = False

                # 1. Try tree-sitter parsing first
                parser = get_installed_parser(file_lang)
                if parser is not None:
                    try:
                        tree = parser.parse(bytes_content)
                        cls._traverse_ast_for_auth(
                            tree.root_node, discovered_props, results, file_lang
                        )
                        tree_sitter_succeeded = True
                    except Exception as ts_err:
                        logger.debug(
                            f"Tree-sitter auth scan failed for {file_path} ({ts_err}). "
                            "Fallback to regex..."
                        )

                # 2. Fallback to regex line-by-line scanning
                if not tree_sitter_succeeded:
                    content_str = bytes_content.decode("utf-8", errors="replace")
                    cls._scan_text_for_auth_regex(
                        content_str, file_path.suffix, discovered_props, results
                    )

            except Exception as e:
                logger.warning(f"Error scanning auth context in {file_path}: {e}")

        # Deduplicate and clean up empty lists
        cleaned_results = {}
        for obj, props in results.items():
            cleaned_results[obj] = {}
            for prop, contexts in props.items():
                if contexts:
                    cleaned_results[obj][prop] = sorted(set(contexts))
        return cleaned_results

    @staticmethod
    def _same_node(a, b) -> bool:
        return b is not None and (a.start_byte, a.end_byte, a.type) == (
            b.start_byte,
            b.end_byte,
            b.type,
        )

    @classmethod
    def _block_exits(cls, block) -> bool:
        """The block (or single statement) leaves the function on its last statement."""
        if block is None:
            return False
        last = block
        # Descend through block wrappers: Go nests the statements in a statement_list
        while last.type.endswith("block") or last.type == "statement_list":
            statements = [c for c in last.children if c.is_named]
            if not statements:
                return False
            last = statements[-1]
        if last.type in cls.EXIT_STATEMENTS:
            return True
        if last.type == "expression_statement":
            text = last.text.decode("utf-8", errors="replace").strip()
            call = re.match(r"^([\w.]+)\s*\(", text)
            return bool(call) and call.group(1).split(".")[-1] in cls.EXIT_CALLS
        return False

    @classmethod
    def is_denying_guard(cls, cond_text: str, body_text: str, exits: bool) -> bool:
        """
        An authorization guard with early exit that denies access, so what follows it is
        reserved: `if not current_user.is_admin: abort(403)`. The branch must refuse the
        request (401/403, forbidden, raise, abort, empty return). Excluded: ownership checks
        (they let the owner through) and positive checks such as
        `if current_user.is_admin: return full_record` (what follows is the ordinary path).
        """
        if not exits or not cls._is_auth_expression(cond_text):
            return False
        if cls.IDENTITY_CHECK.search(cond_text):
            return False
        if cls.DENIAL_BODY.search(body_text):
            return True
        # Without an explicit denial, a negated condition counts only if the branch does
        # nothing but refuse: a lone raise/abort or an empty return. An ASGI middleware's
        # `if scope["type"] != "http": await self.app(...); return` passes the request on.
        lines = [ln.strip().strip("{}").strip() for ln in body_text.splitlines()]
        statements = [ln for ln in lines if ln and not ln.startswith(("#", "//"))]
        return bool(
            cls.NEGATED_CONDITION.search(cond_text)
            and len(statements) == 1
            and cls.REFUSING_EXIT.match(statements[0])
        )

    @classmethod
    def _guard_context(cls, if_node) -> str | None:
        condition = if_node.child_by_field_name("condition")
        consequence = if_node.child_by_field_name("consequence")
        if condition is None or consequence is None:
            return None
        cond_text = condition.text.decode("utf-8", errors="replace").strip()
        body_text = consequence.text.decode("utf-8", errors="replace")
        if cls.is_denying_guard(cond_text, body_text, cls._block_exits(consequence)):
            return f"guard({cond_text.strip('()').strip()})"
        return None

    CLASS_NODES = {"class_definition", "class_declaration", "class"}
    FUNCTION_NODES = {
        "function_definition",
        "function_declaration",
        "method_definition",
        "method_declaration",
        "arrow_function",
        "function_expression",
        "function",
    }
    # `name = Model(...)`, `name = Model.objects.get(...)`, `name := &models.User{}`,
    # `const name = await User.findById(...)`
    LOCAL_ASSIGNMENT = re.compile(
        r"(?m)^\s*(?:const\s+|let\s+|var\s+)?([A-Za-z_]\w*)\s*(?::=|=)\s*(?:await\s+)?"
        r"(?:new\s+)?&?(?:[a-z_]\w*\.)?([A-Z]\w*)"
    )
    # Typed parameters: `user: User`, `u *User`, `u models.User`
    TYPED_PARAMETER = re.compile(r"([A-Za-z_]\w*)\s*(?::\s*|\s+\*?)(?:[a-z_]\w*\.)?([A-Z]\w*)")

    @classmethod
    def _scope_of(cls, node, parent: tuple[str | None, dict[str, str]]):
        """New (class, local variables) scope opened by a class or function node, else None."""
        class_name, variables = parent
        if node.type in cls.CLASS_NODES:
            name = node.child_by_field_name("name")
            return (name.text.decode("utf-8", errors="replace") if name else class_name, {})
        if node.type in cls.FUNCTION_NODES:
            local = dict(variables)
            parameters = node.child_by_field_name("parameters")
            if parameters is not None:
                text = parameters.text.decode("utf-8", errors="replace")
                local.update(dict(cls.TYPED_PARAMETER.findall(text)))
            body = node.child_by_field_name("body")
            if body is not None:
                text = body.text.decode("utf-8", errors="replace")
                local.update(dict(cls.LOCAL_ASSIGNMENT.findall(text)))
            # Go methods: func (u *User) Salary() -> u is a User
            receiver = node.child_by_field_name("receiver")
            if receiver is not None:
                text = receiver.text.decode("utf-8", errors="replace")
                local.update(dict(cls.TYPED_PARAMETER.findall(text)))
            return (class_name, local)
        return None

    @classmethod
    def _traverse_ast_for_auth(
        cls,
        node,
        discovered_props: dict[str, set[str]],
        results: dict[str, dict[str, list[str]]],
        lang_key: str,
    ):
        """Recursively traverses the tree-sitter AST to extract properties in auth contexts."""
        # Scopes met on the way down: (enclosing class, {local variable: class}) used to tie an
        # access to the object it reads (B.8) instead of every object with that property name.
        scopes: list[tuple[str | None, dict[str, str]]] = [(None, {})]

        def owner_of(receiver: str | None) -> str | None:
            """Inventory object named by the receiver of an access, if it can be told."""
            if not receiver:
                return None
            class_name, variables = scopes[-1]
            segments = re.findall(r"[A-Za-z_]\w*", receiver)
            for segment in (segments[-1:] + segments[:1]) if segments else []:
                if segment in ("self", "this", "cls"):
                    candidate = class_name
                else:
                    candidate = variables.get(segment, segment)
                if not candidate:
                    continue
                name = PropertyDiscoveryEngine.clean_object_name(candidate)
                if name in discovered_props:
                    return name
            return None

        def walk(n, active_decorators: list[str], active_conditions: list[str]):
            # 1. Authorization contexts opened by this node for its subtree (decorators and
            # the other framework idioms of auth_idioms.py)
            # A decorator guards the function it decorates (propagated by its parent), not its own
            # arguments: in @user_passes_test(lambda u: u.is_superuser) the predicate is not data.
            opened = (
                []
                if n.type in ("decorator", "annotation")
                else auth_idioms.node_auth_contexts(n, lang_key)
            )
            current_decorators = active_decorators + opened

            # 2. Conditional statements: the condition guards only its own consequence, never
            # the elif/else branches (they run when it is false) nor the condition itself
            # (an ownership test such as `current_user.id != user.id` would mark `id`).
            if n.type in ("if_statement", "elif_clause"):
                condition = n.child_by_field_name("condition")
                consequence = n.child_by_field_name("consequence")
                context = None
                if condition is not None:
                    cond_text = condition.text.decode("utf-8", errors="replace").strip()
                    # The refusing branch of a guard holds the denial (`{"message":
                    # UNAUTHORIZED}`), not reserved data: the guard protects what follows it.
                    if cls._is_auth_expression(cond_text) and not (
                        n.type == "if_statement" and cls._guard_context(n)
                    ):
                        context = f"if({cond_text})"
                for child in n.children:
                    guarded = context is not None and cls._same_node(child, consequence)
                    walk(
                        child,
                        current_decorators,
                        [*active_conditions, context] if guarded else active_conditions,
                    )
                return

            current_conditions = list(active_conditions)

            # 3. Property accesses of this node (forms recognized in access_patterns.py). When the
            # receiver names an inventory object that has the property, only that object gets the
            # context; otherwise (dictionary keys, unknown receivers) every candidate does.
            accessed = access_patterns.node_property_accesses(n, lang_key)
            all_contexts = current_decorators + current_conditions
            if accessed and all_contexts:
                owner = owner_of(access_patterns.node_receiver(n, lang_key))
                for prop_name in accessed:
                    candidates = [o for o, props in discovered_props.items() if prop_name in props]
                    if owner in candidates:
                        candidates = [owner]
                    for obj_name in candidates:
                        results[obj_name][prop_name].extend(all_contexts)

            # Entering a class or a function opens a scope for the receivers below it
            scope = cls._scope_of(n, scopes[-1])
            if scope is not None:
                scopes.append(scope)

            # Traverse children in order: an authorization guard with early exit
            # (`if not current_user.is_admin: abort(403)`) protects the statements after it.
            guards: list[str] = []
            for child in n.children:
                # Decorators do not inherit the context their own definition opens
                inherited = (
                    active_decorators
                    if child.type in ("decorator", "annotation")
                    else current_decorators
                )
                walk(child, inherited, current_conditions + guards)
                if child.type == "if_statement":
                    guard = cls._guard_context(child)
                    if guard:
                        guards.append(guard)
            if scope is not None:
                scopes.pop()

        walk(node, [], [])

    @classmethod
    def _scan_text_for_auth_regex(
        cls,
        content: str,
        suffix: str,
        discovered_props: dict[str, set[str]],
        results: dict[str, dict[str, list[str]]],
    ):
        """
        Fallback regex scanning for authorization checks block proximity. A denying guard
        with early exit (`if (!user.isAdmin) { return res.status(403)... }`) keeps its
        context until the next function starts.
        """
        lines = content.split("\n")
        active_contexts = []
        context_countdown = 0
        guard_contexts: list[str] = []

        for index, line in enumerate(lines):
            line_strip = line.strip()
            if not line_strip:
                continue

            # A new function ends the guards of the previous one
            if cls.FUNCTION_START.match(line):
                guard_contexts = []

            # Update countdown of context relevance
            if context_countdown > 0:
                context_countdown -= 1
                if context_countdown == 0:
                    active_contexts = []

            # 1. Match decorators
            line_context = auth_idioms.line_auth_context(line_strip)
            if line_context:
                active_contexts = [line_context]
                context_countdown = 5  # active for the next 5 lines of the function definition
                continue

            # 2. Match if statement conditions
            if line_strip.startswith("if ") or line_strip.startswith("if("):
                # Extract condition
                cond_text = ""
                rest = ""
                if ":" in line_strip:
                    cond_text = line_strip[2 : line_strip.index(":")].strip()
                    rest = line_strip[line_strip.index(":") + 1 :]
                elif "{" in line_strip:
                    cond_text = line_strip[2 : line_strip.index("{")].strip()
                    rest = line_strip[line_strip.index("{") + 1 :]
                else:
                    cond_text = line_strip[2:].strip()

                cond_text = cond_text.strip("()")
                if cls._is_auth_expression(cond_text):
                    body = rest.strip() or next(
                        (
                            following.strip()
                            for following in lines[index + 1 :]
                            if following.strip()
                        ),
                        "",
                    )
                    exits = bool(cls.REGEX_EXIT.match(body))
                    if cls.is_denying_guard(cond_text, body, exits):
                        guard_contexts.append(f"guard({cond_text})")
                        continue
                    active_contexts = [f"if({cond_text})"]
                    context_countdown = 4  # active for the next 4 lines of the if statement body
                    continue

            # 3. Check for properties in the current line if active context exists
            contexts = active_contexts + guard_contexts
            if contexts:
                for obj_name, props in discovered_props.items():
                    for prop in props:
                        if access_patterns.line_mentions_property(line_strip, prop) or (
                            prop in line_strip and cls._is_auth_expression(line_strip)
                        ):
                            results[obj_name][prop].extend(contexts)

    @classmethod
    def build_cross_model_occurrences(
        cls,
        repo_path: str,
        lang_name: str | None,
        discovered_props: dict[str, set[str]],
    ) -> dict[str, dict[str, list[str]]]:
        """
        Analyzes original models to verify in which AST-derived DTOs/Entities/Models
        the properties are found. Each file is read with the grammar of its own language.
        """
        results = {obj: {prop: [] for prop in props} for obj, props in discovered_props.items()}
        language = lang_name.lower().strip() if lang_name else None

        for file_path, file_lang in collect_source_files(repo_path, language):
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
                parsed_classes = PropertyDiscoveryEngine.extract_properties_via_regex(
                    content, file_path.suffix
                )

                # Enrich with tree-sitter when the grammar is installed
                parser = get_installed_parser(file_lang)
                if parser is not None:
                    with contextlib.suppress(Exception):
                        source = content.encode("utf-8")
                        tree = parser.parse(source)
                        existing = {c[0] for c in parsed_classes}
                        for name, props in PropertyDiscoveryEngine.parse_models(
                            file_lang, tree.root_node, source
                        ):
                            if name not in existing:
                                parsed_classes.append((name, props))

                for raw_name, props in parsed_classes:
                    cleaned_name = PropertyDiscoveryEngine.clean_object_name(raw_name)
                    if cleaned_name in results:
                        for prop in props:
                            if prop in results[cleaned_name]:
                                results[cleaned_name][prop].append(raw_name)

            except Exception:
                pass

        # Deduplicate raw class name lists
        for obj, props in results.items():
            for prop in props:
                results[obj][prop] = sorted(set(results[obj][prop]))

        return results

    @classmethod
    def calculate_confidence(cls, evidence: PropertyEvidence) -> float:
        """
        Dynamically calculates the confidence score of a property being an authorized attribute.
        Formula sum:
        - 0.20 if found_in_ast
        - 0.20 if found_in_openapi
        - 0.20 if found_runtime
        - 0.10 if read_endpoints is not empty
        - 0.10 if write_endpoints is not empty
        - 0.20 if authorization_contexts is not empty
        - 0.10 if cross_model_occurrences has length >= 2
        Total max: 1.0 (capped at 1.0)
        """
        score = 0.0
        if evidence.found_in_ast:
            score += 0.20
        if evidence.found_in_openapi:
            score += 0.20
        if evidence.found_runtime:
            score += 0.20
        if evidence.read_endpoints:
            score += 0.10
        if evidence.write_endpoints:
            score += 0.10
        if evidence.authorization_contexts:
            score += 0.20
        if len(evidence.cross_model_occurrences) >= 2:
            score += 0.10

        return min(1.0, round(score, 2))

    @classmethod
    def run_inference(
        cls,
        repo_path: str,
        inventory: PropertyInventory,
        openapi_spec: dict[str, Any] | None = None,
        runtime_traffic: list[dict[str, Any]] | None = None,
        stack: StackInfo | None = None,
    ) -> list[PropertyEvidence]:
        """
        Runs the full Property Authorization Inference workflow.
        Collects AST auth contexts, read/write contexts, documentation issues,
        cross-model correlations, and computes the confidence for each property.
        """
        logger.info("Avvio BOPLA Property Authorization Inference Engine...")

        # 1. Get discovered properties structure
        # inventory contains root model mapping Dict[str, ObjectProperties]
        inventory_dict = inventory.root
        discovered_props = {}
        for obj, obj_props in inventory_dict.items():
            discovered_props[obj] = {p.name for p in obj_props.properties}

        # 2. Extract AST auth contexts: every supported language present in the repository,
        # each file with its own grammar (the stack guess would silence mixed repositories).
        logger.info("BOPLA Inference: Analisi contesti autorizzativi AST (linguaggio per file)...")
        ast_auth_contexts = cls.analyze_ast_authorization_contexts(
            repo_path, None, discovered_props
        )

        # 3. Extract Cross-Model Correlation
        logger.info("BOPLA Inference: Analisi cross-model (DTO/Entities/Models)...")
        cross_models = cls.build_cross_model_occurrences(repo_path, None, discovered_props)

        # 4. Extract Read/Write Contexts from OpenAPI & Runtime
        # Dict structure: {object_name: {property_name: set(endpoints)}}
        read_ops = {obj: {p: set() for p in props} for obj, props in discovered_props.items()}
        write_ops = {obj: {p: set() for p in props} for obj, props in discovered_props.items()}

        # 4a. Process OpenAPI operations: each operation reads (GET, success response) or
        # writes (request body) the properties of the schema that describes it, `$ref`
        # resolved, so /staff/{id} described by Employee reads and writes Employee (B.6).
        # Without a body schema the operation falls back to every contract property of the
        # object it is about (its named schema, else the object of the path).
        contract_props: dict[str, set[str]] = {}
        flags: dict[tuple[str, str], set[str]] = {}
        if openapi_spec:
            logger.info("BOPLA Inference: Parsing rotte OpenAPI per operazioni Read/Write...")
            contract_props = PropertyDiscoveryEngine.extract_openapi_properties(openapi_spec)
            flags = contract.contract_flags(openapi_spec)
            for operation in contract.iter_operations(openapi_spec):
                if operation.method == "GET":
                    target, bodies = read_ops, operation.response_objects()
                elif operation.method in contract.WRITE_METHODS:
                    target, bodies = write_ops, operation.request_objects()
                else:
                    continue
                if not bodies:
                    # A write without a body (DELETE) acts on the resource of the path; its
                    # response, if any, may be a generic envelope.
                    obj = (
                        operation.path_object
                        if operation.method != "GET" and operation.path_object in target
                        else operation.resource_object
                    )
                    bodies = [(obj, dict.fromkeys(contract_props.get(obj, set())))]
                for obj_name, props in bodies:
                    known = target.get(obj_name)
                    if known is None:
                        continue
                    for prop in props:
                        if prop in known:
                            known[prop].add(operation.label)

        # 4b. Process Runtime Traffic: the object of each body is the schema the contract
        # associates with the operation, else the object of the path. Nested keys are dotted.
        if runtime_traffic:
            logger.info(
                f"BOPLA Inference: Parsing traffico runtime ({len(runtime_traffic)} entry) per Read/Write..."
            )
            for entry in runtime_traffic:
                path = entry.get("path")
                method = entry.get("method", "GET").upper()
                if not path:
                    continue

                normalized_path = APIEndpointNormalizer.normalize_path(path)
                op_label = f"{method} {normalized_path}"

                if method == "GET":
                    direction, target = "read", read_ops
                    body = (
                        entry.get("response_body")
                        or entry.get("response")
                        or entry.get("response_params")
                    )
                elif method in ("POST", "PUT", "PATCH", "DELETE"):
                    direction, target = "write", write_ops
                    body = entry.get("body_params")
                else:
                    continue
                if not body:
                    continue
                if isinstance(body, str):
                    with contextlib.suppress(Exception):
                        body = json.loads(body)
                obj_name = PropertyDiscoveryEngine.traffic_object(
                    openapi_spec, method, path, direction
                )
                known = target.get(obj_name)
                if known is None:
                    continue
                for k in PropertyDiscoveryEngine.extract_keys_from_json_recursive(body):
                    if k in known:
                        known[k].add(op_label)

        # 5. Compile Evidence list
        evidences = []
        for obj, obj_props in inventory_dict.items():
            for p in obj_props.properties:
                p_name = p.name

                found_ast = "ast" in p.sources
                found_openapi = "openapi" in p.sources
                found_runtime = "runtime" in p.sources

                # Check documentation correlation warnings
                doc_issues = []
                if found_runtime and not found_openapi:
                    doc_issues.append(
                        "Property observed at runtime but absent from API specification."
                    )

                read_list = sorted(read_ops[obj][p_name])
                write_list = sorted(write_ops[obj][p_name])
                auth_contexts = list(ast_auth_contexts.get(obj, {}).get(p_name, []))
                # The contract's own readOnly/writeOnly declaration is an authorization
                # expectation of the application: writing (readOnly) or reading (writeOnly)
                # the property is reserved, and the dynamic phase proves it in that direction.
                declared = sorted(flags.get((obj, p_name), set()))
                auth_contexts.extend(f"contract({flag})" for flag in declared)
                cross_list = cross_models.get(obj, {}).get(p_name, [])

                evidence = PropertyEvidence(
                    object_name=obj,
                    property=p_name,
                    found_in_ast=found_ast,
                    found_in_openapi=found_openapi,
                    found_runtime=found_runtime,
                    read_endpoints=read_list,
                    write_endpoints=write_list,
                    authorization_contexts=auth_contexts,
                    cross_model_occurrences=cross_list,
                    documentation_issues=doc_issues,
                    contract_flags=declared,
                    confidence=0.0,
                )
                # Compute confidence score
                evidence.confidence = cls.calculate_confidence(evidence)
                evidences.append(evidence)

        # Sort evidences by object_name then by confidence descending, then by property name
        evidences.sort(key=lambda x: (x.object_name, -x.confidence, x.property))
        return evidences

    @classmethod
    def build_authorization_graph(
        cls, evidences: list[PropertyEvidence]
    ) -> PropertyAuthorizationGraph:
        """
        Builds the PropertyAuthorizationGraph hierarchy from inferred property evidences.
        """
        graph = PropertyAuthorizationGraph(objects={})
        for ev in evidences:
            obj = ev.object_name
            prop = ev.property

            if obj not in graph.objects:
                graph.objects[obj] = ObjectGraphNode(object_name=obj, properties={})

            node = PropertyGraphNode(
                property_name=prop,
                read_operations=ev.read_endpoints,
                write_operations=ev.write_endpoints,
                authorization_contexts=ev.authorization_contexts,
            )
            graph.objects[obj].properties[prop] = node

        return graph
