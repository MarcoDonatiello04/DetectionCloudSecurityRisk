import contextlib
import json
import os
import re
from pathlib import Path
from typing import Any

from loguru import logger

from src.core.api2_broken_auth.ast_parser import (
    EXTENSION_MAP,
    IGNORE_DIRS,
    get_parser_for_language,
    is_text_file,
)
from src.core.api2_broken_auth.discovery import StackInfo
from src.core.api3_bopla.discovery import PropertyDiscoveryEngine

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

    AUTH_KEYWORDS = {
        "current_user",
        "user",
        "role",
        "admin",
        "auth",
        "token",
        "caller",
        "identity",
        "permissions",
        "permission",
        "scope",
        "can",
        "hasrole",
        "is_admin",
    }

    DECORATOR_PATTERN = re.compile(
        r"@\s*(?:roles_required|require_role|permission_required|secured|PreAuthorize|HasRole|Can|Authorize|check_auth)\b.*",
        re.IGNORECASE,
    )

    @classmethod
    def _is_auth_expression(cls, expr: str) -> bool:
        """Helper to determine if an expression contains authorization-related terms."""
        expr_lower = expr.lower()
        return any(kw in expr_lower for kw in cls.AUTH_KEYWORDS)

    @classmethod
    def analyze_ast_authorization_contexts(
        cls, repo_path: str, lang_name: str, discovered_props: dict[str, set[str]]
    ) -> dict[str, dict[str, list[str]]]:
        """
        Scans source files using tree-sitter or regex fallback to locate properties
        accessed within authorization checks (if conditions or decorated functions).
        Returns a dict: {object_name: {property_name: [contexts]}}
        """
        results = {obj: {prop: [] for prop in props} for obj, props in discovered_props.items()}
        path = Path(repo_path)
        if not path.is_dir():
            return results

        lang_key = lang_name.lower().strip()
        extensions = EXTENSION_MAP.get(lang_key)
        if not extensions:
            return results

        source_files = []

        def collect(current_dir: Path):
            try:
                for item in current_dir.iterdir():
                    if item.is_dir():
                        if item.name not in IGNORE_DIRS:
                            collect(item)
                    elif item.is_file() and item.suffix in extensions:
                        if is_text_file(item):
                            source_files.append(item)
            except Exception:
                pass

        collect(path)

        for file_path in source_files:
            rel_path = str(file_path.relative_to(path))
            try:
                with open(file_path, "rb") as f:
                    bytes_content = f.read()

                tree_sitter_succeeded = False

                # 1. Try tree-sitter parsing first
                try:
                    parser = get_parser_for_language(lang_key)
                    tree = parser.parse(bytes_content)
                    if tree and tree.root_node:
                        cls._traverse_ast_for_auth(
                            tree.root_node, discovered_props, results, lang_key
                        )
                        tree_sitter_succeeded = True
                except Exception as ts_err:
                    logger.debug(
                        f"Tree-sitter auth scan failed for {rel_path} ({ts_err}). Fallback to regex..."
                    )

                # 2. Fallback to regex line-by-line scanning
                if not tree_sitter_succeeded:
                    content_str = bytes_content.decode("utf-8", errors="replace")
                    cls._scan_text_for_auth_regex(
                        content_str, file_path.suffix, discovered_props, results
                    )

            except Exception as e:
                logger.warning(f"Error scanning auth context in {rel_path}: {e}")

        # Deduplicate and clean up empty lists
        cleaned_results = {}
        for obj, props in results.items():
            cleaned_results[obj] = {}
            for prop, contexts in props.items():
                if contexts:
                    cleaned_results[obj][prop] = sorted(set(contexts))
        return cleaned_results

    @classmethod
    def _traverse_ast_for_auth(
        cls,
        node,
        discovered_props: dict[str, set[str]],
        results: dict[str, dict[str, list[str]]],
        lang_key: str,
    ):
        """Recursively traverses the tree-sitter AST to extract properties in auth contexts."""

        def walk(n, active_decorators: list[str], active_conditions: list[str]):
            # 1. Update decorator context
            current_decorators = list(active_decorators)
            if n.type in ("decorator", "annotation"):
                dec_text = n.text.decode("utf-8", errors="replace").strip()
                if cls.DECORATOR_PATTERN.match(dec_text):
                    current_decorators.append(dec_text)

            # 2. Update conditional statement context
            current_conditions = list(active_conditions)
            if n.type == "if_statement":
                # Find the condition node (first child or named child)
                condition_node = None
                for child in n.children:
                    # In python, condition is often the first child after 'if'
                    # In JS/TS/Go, it is typically wrapped in parentheses or specific types
                    if child.type not in ("if", "elif", "(", ")", ":", "{"):
                        condition_node = child
                        break
                if condition_node:
                    cond_text = condition_node.text.decode("utf-8", errors="replace").strip()
                    if cls._is_auth_expression(cond_text):
                        current_conditions.append(f"if({cond_text})")

            # 3. Check for attribute/member access matching discovered properties
            # E.g., user.salary or self.is_admin
            is_prop_access = False
            prop_name = None

            if lang_key == "python" and n.type == "attribute":
                # Python attribute has children: identifier at the end
                for child in reversed(n.children):
                    if child.type == "identifier":
                        prop_name = child.text.decode("utf-8", errors="replace")
                        is_prop_access = True
                        break
            elif lang_key in ("javascript", "typescript") and n.type == "member_expression":
                # JS/TS member_expression has property_identifier child
                for child in n.children:
                    if child.type == "property_identifier":
                        prop_name = child.text.decode("utf-8", errors="replace")
                        is_prop_access = True
                        break
            elif lang_key == "go" and n.type == "selector_expression":
                # Go selector_expression has field_identifier child
                for child in n.children:
                    if child.type == "field_identifier":
                        prop_name = child.text.decode("utf-8", errors="replace")
                        is_prop_access = True
                        break

            if is_prop_access and prop_name:
                # Add context to any matching discovered property
                for obj_name, props in discovered_props.items():
                    if prop_name in props:
                        all_contexts = current_decorators + current_conditions
                        if all_contexts:
                            results[obj_name][prop_name].extend(all_contexts)

            # Traverse children
            for child in n.children:
                walk(child, current_decorators, current_conditions)

        walk(node, [], [])

    @classmethod
    def _scan_text_for_auth_regex(
        cls,
        content: str,
        suffix: str,
        discovered_props: dict[str, set[str]],
        results: dict[str, dict[str, list[str]]],
    ):
        """Fallback regex scanning for authorization checks block proximity."""
        lines = content.split("\n")
        active_contexts = []
        context_countdown = 0

        for line in lines:
            line_strip = line.strip()
            if not line_strip:
                continue

            # Update countdown of context relevance
            if context_countdown > 0:
                context_countdown -= 1
                if context_countdown == 0:
                    active_contexts = []

            # 1. Match decorators
            dec_match = cls.DECORATOR_PATTERN.match(line_strip)
            if dec_match:
                active_contexts = [line_strip]
                context_countdown = 5  # active for the next 5 lines of the function definition
                continue

            # 2. Match if statement conditions
            if line_strip.startswith("if ") or line_strip.startswith("if("):
                # Extract condition
                cond_text = ""
                if ":" in line_strip:
                    cond_text = line_strip[2 : line_strip.index(":")].strip()
                elif "{" in line_strip:
                    cond_text = line_strip[2 : line_strip.index("{")].strip()
                else:
                    cond_text = line_strip[2:].strip()

                cond_text = cond_text.strip("()")
                if cls._is_auth_expression(cond_text):
                    active_contexts = [f"if({cond_text})"]
                    context_countdown = 4  # active for the next 4 lines of the if statement body
                    continue

            # 3. Check for properties in the current line if active context exists
            if active_contexts:
                for obj_name, props in discovered_props.items():
                    for prop in props:
                        # Match property access, e.g. .prop_name or ->prop_name or just prop_name
                        pattern = r"[\.\-\>\b]" + re.escape(prop) + r"\b"
                        if re.search(pattern, line_strip) or (
                            prop in line_strip and cls._is_auth_expression(line_strip)
                        ):
                            results[obj_name][prop].extend(active_contexts)

    @classmethod
    def build_cross_model_occurrences(
        cls, repo_path: str, lang_name: str, discovered_props: dict[str, set[str]]
    ) -> dict[str, dict[str, list[str]]]:
        """
        Analyzes original models to verify in which AST-derived DTOs/Entities/Models
        the properties are found.
        """
        results = {obj: {prop: [] for prop in props} for obj, props in discovered_props.items()}
        path = Path(repo_path)
        if not path.is_dir():
            return results

        lang_key = lang_name.lower().strip()
        extensions = EXTENSION_MAP.get(lang_key)
        if not extensions:
            return results

        source_files = []

        def collect(current_dir: Path):
            try:
                for item in current_dir.iterdir():
                    if item.is_dir():
                        if item.name not in IGNORE_DIRS:
                            collect(item)
                    elif item.is_file() and item.suffix in extensions:
                        if is_text_file(item):
                            source_files.append(item)
            except Exception:
                pass

        collect(path)

        for file_path in source_files:
            try:
                with open(file_path, encoding="utf-8", errors="replace") as f:
                    content = f.read()

                parsed_classes = PropertyDiscoveryEngine.extract_properties_via_regex(
                    content, file_path.suffix
                )

                # Check tree-sitter if regex returned nothing or to enrich
                try:
                    parser = get_parser_for_language(lang_key)
                    tree = parser.parse(content.encode("utf-8"))
                    if tree and tree.root_node:
                        if lang_key == "python":
                            ast_classes = PropertyDiscoveryEngine._parse_python_ast(
                                tree.root_node, content.encode("utf-8")
                            )
                        elif lang_key in ("javascript", "typescript"):
                            ast_classes = PropertyDiscoveryEngine._parse_typescript_ast(
                                tree.root_node, content.encode("utf-8")
                            )
                        elif lang_key == "go":
                            ast_classes = PropertyDiscoveryEngine._parse_go_ast(
                                tree.root_node, content.encode("utf-8")
                            )

                        if ast_classes:
                            # Merge keeping unique
                            existing = {c[0] for c in parsed_classes}
                            for name, props in ast_classes:
                                if name not in existing:
                                    parsed_classes.append((name, props))
                except Exception:
                    pass

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

        # 2. Extract AST auth contexts
        lang = "python"
        if stack and stack.linguaggio:
            lang = stack.linguaggio
        else:
            # guess language
            for _root, dirs, files in os.walk(repo_path):
                dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
                for file in files:
                    if file.endswith(".go"):
                        lang = "go"
                        break
                    elif file.endswith(".ts") or file.endswith(".tsx"):
                        lang = "typescript"
                        break
                    elif file.endswith(".js"):
                        lang = "javascript"
                        break

        logger.info(f"BOPLA Inference: Analisi contesti autorizzativi AST per {lang}...")
        ast_auth_contexts = cls.analyze_ast_authorization_contexts(
            repo_path, lang, discovered_props
        )

        # 3. Extract Cross-Model Correlation
        logger.info("BOPLA Inference: Analisi cross-model (DTO/Entities/Models)...")
        cross_models = cls.build_cross_model_occurrences(repo_path, lang, discovered_props)

        # 4. Extract Read/Write Contexts from OpenAPI & Runtime
        # Dict structure: {object_name: {property_name: set(endpoints)}}
        read_ops = {obj: {p: set() for p in props} for obj, props in discovered_props.items()}
        write_ops = {obj: {p: set() for p in props} for obj, props in discovered_props.items()}

        # 4a. Process OpenAPI schemas & paths
        if openapi_spec:
            logger.info("BOPLA Inference: Parsing rotte OpenAPI per operazioni Read/Write...")
            # We map OpenAPI request/response schemas to endpoints
            # For simplicity, if we find a GET endpoint returning a component reference,
            # we link that component's properties to the path
            paths = openapi_spec.get("paths", {})
            for path, path_info in paths.items():
                for method, _op_info in path_info.items():
                    method_upper = method.upper()
                    op_label = f"{method_upper} {APIEndpointNormalizer.normalize_path(path)}"
                    obj_name = PropertyDiscoveryEngine.get_object_name_from_path(path)

                    if obj_name in discovered_props:
                        # For GET request, all properties defined in the OpenAPI schema for this object
                        # are marked as read_endpoints
                        if method_upper == "GET":
                            for prop in discovered_props[obj_name]:
                                # check if property is documented in components/schemas for this object
                                openapi_objects = (
                                    PropertyDiscoveryEngine.extract_openapi_properties(openapi_spec)
                                )
                                if prop in openapi_objects.get(obj_name, set()):
                                    read_ops[obj_name][prop].add(op_label)
                        # For write request (POST, PUT, PATCH, DELETE)
                        elif method_upper in ("POST", "PUT", "PATCH", "DELETE"):
                            for prop in discovered_props[obj_name]:
                                openapi_objects = (
                                    PropertyDiscoveryEngine.extract_openapi_properties(openapi_spec)
                                )
                                if prop in openapi_objects.get(obj_name, set()):
                                    write_ops[obj_name][prop].add(op_label)

        # 4b. Process Runtime Traffic
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
                obj_name = PropertyDiscoveryEngine.get_object_name_from_path(path)

                if obj_name in discovered_props:
                    if method == "GET":
                        resp_body = (
                            entry.get("response_body")
                            or entry.get("response")
                            or entry.get("response_params")
                        )
                        if resp_body:
                            if isinstance(resp_body, str):
                                with contextlib.suppress(Exception):
                                    resp_body = json.loads(resp_body)
                            keys = PropertyDiscoveryEngine.extract_keys_from_json_recursive(
                                resp_body
                            )
                            for k in keys:
                                if k in read_ops[obj_name]:
                                    read_ops[obj_name][k].add(op_label)
                    elif method in ("POST", "PUT", "PATCH", "DELETE"):
                        body_params = entry.get("body_params")
                        if body_params:
                            if isinstance(body_params, str):
                                with contextlib.suppress(Exception):
                                    body_params = json.loads(body_params)
                            keys = PropertyDiscoveryEngine.extract_keys_from_json_recursive(
                                body_params
                            )
                            for k in keys:
                                if k in write_ops[obj_name]:
                                    write_ops[obj_name][k].add(op_label)

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
                auth_contexts = ast_auth_contexts.get(obj, {}).get(p_name, [])
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
