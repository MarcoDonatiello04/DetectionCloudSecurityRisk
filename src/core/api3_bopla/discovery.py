import contextlib
import importlib.util
import json
import re
from functools import cache
from pathlib import Path
from typing import Any

from loguru import logger

# Reuse AST utilities from api2_broken_auth
from src.core.api2_broken_auth.ast_parser import (
    EXTENSION_MAP,
    GRAMMAR_MAP,
    IGNORE_DIRS,
    get_parser_for_language,
    is_text_file,
)
from src.core.api2_broken_auth.discovery import StackInfo
from src.core.api3_bopla import contract

# Import models
from src.core.api3_bopla.models import (
    ObjectProperties,
    PropertyInfo,
    PropertyInventory,
)

# Reuse normalizer and object reference engine from normalizer and BOLA
from src.normalization.normalizer import APIEndpointNormalizer

# Languages whose models and property accesses BOPLA can read (tree-sitter or regex fallback).
SUPPORTED_LANGUAGES = ("python", "javascript", "typescript", "go")
EXTENSION_TO_LANGUAGE = {ext: lang for lang in SUPPORTED_LANGUAGES for ext in EXTENSION_MAP[lang]}

# --- Canonical object names (B.9) ---------------------------------------------------------
# The same object must get the same name whether it comes from a class (`ApplyCouponView`
# cleaned), a schema (`ApplyCouponRequest`) or a path (`/shop/apply_coupon`). No inflection
# library: regular rules plus the irregular and invariable words met in API paths.
IRREGULAR_PLURALS = {
    "people": "person",
    "children": "child",
    "men": "man",
    "women": "woman",
    "mice": "mouse",
    "geese": "goose",
    "teeth": "tooth",
    "feet": "foot",
    "indices": "index",
    "matrices": "matrix",
    "vertices": "vertex",
    "criteria": "criterion",
    "phenomena": "phenomenon",
    "leaves": "leaf",
    "knives": "knife",
    "lives": "life",
    "wives": "wife",
    "wolves": "wolf",
    "halves": "half",
    "shelves": "shelf",
    "movies": "movie",
    "cookies": "cookie",
    "heroes": "hero",
    "potatoes": "potato",
    "tomatoes": "tomato",
    "statuses": "status",
    "buses": "bus",
    "viruses": "virus",
    "bonuses": "bonus",
    "campuses": "campus",
    "analyses": "analysis",
    "caches": "cache",
}
INVARIABLE_WORDS = {
    "news",
    "data",
    "metadata",
    "media",
    "series",
    "species",
    "info",
    "information",
    "equipment",
    "canvas",
    "alias",
    "atlas",
    "bias",
    "gas",
    "chassis",
    "sms",
    "dns",
    "aws",
    "https",
    "os",
}


def singularize(word: str) -> str:
    """Singular of an English lower-case word (rules plus IRREGULAR_PLURALS)."""
    lower = word.lower()
    if lower in IRREGULAR_PLURALS:
        return IRREGULAR_PLURALS[lower]
    if lower in INVARIABLE_WORDS or len(lower) <= 3:
        return word
    if lower.endswith(("ss", "us", "is")):
        return word  # address, status, analysis
    if lower.endswith("ies"):
        return word[:-3] + "y"
    if lower.endswith(("sses", "xes", "ches", "shes", "zzes")):
        return word[:-2]
    if lower.endswith("s"):
        return word[:-1]
    return word


def canonical_object_name(name: str) -> str:
    """
    Canonical object name: PascalCase words (separators `_`, `-`, `.` and spaces removed,
    inner capitals kept), the last word in the singular.
    Examples: apply_coupon -> ApplyCoupon, Change-email -> ChangeEmail, status -> Status,
    news -> News, people -> Person, Comments -> Comment.
    """
    parts = [p for p in re.split(r"[^A-Za-z0-9]+", name or "") if p]
    if not parts:
        return (name or "").strip()
    words = [p[0].upper() + p[1:] for p in parts]
    # Singularize only the last camel-case word, and only when it is written in lower case
    # after its capital (an acronym such as CRAPI or URLs stays as it is).
    match = re.match(r"^(.*?)([A-Z][a-z]+|[a-z]+)$", words[-1])
    if match:
        head, last = match.groups()
        singular = singularize(last.lower())
        if singular != last.lower():
            words[-1] = head + singular[0].upper() + singular[1:]
    return "".join(words)


def collect_source_files(repo_path: str, language: str | None = None) -> list[tuple[Path, str]]:
    """
    Returns (file, language) for every supported source file of the repository. The language
    is decided per file from its extension, so a mixed repository (a Python backend with a
    JavaScript frontend, Go and Python services side by side) is analyzed in all its parts.
    `language` restricts the result to one language.
    """
    root = Path(repo_path)
    if not root.is_dir():
        return []
    files: list[tuple[Path, str]] = []

    def collect(current_dir: Path):
        try:
            for item in sorted(current_dir.iterdir()):
                if item.is_dir():
                    if item.name not in IGNORE_DIRS:
                        collect(item)
                elif item.is_file():
                    lang = EXTENSION_TO_LANGUAGE.get(item.suffix)
                    if lang and (language is None or lang == language) and is_text_file(item):
                        files.append((item, lang))
        except OSError:
            pass

    collect(root)
    return files


TEST_DIRECTORIES = {"tests", "test", "__tests__", "testing"}
TEST_FILE = re.compile(r"^(?:test_.*\.py|.*_test\.(?:py|go)|tests\.py|.*\.(?:test|spec)\.[jt]sx?)$")


def is_test_file(path: Path) -> bool:
    """Test modules and fixtures: their classes are not data models of the API."""
    return bool(TEST_FILE.match(path.name)) or any(p in TEST_DIRECTORIES for p in path.parts)


@cache
def get_installed_parser(language: str):
    """
    Tree-sitter parser for `language`, or None when its grammar is not installed. Unlike
    get_parser_for_language it never installs packages during a scan: callers fall back to
    the regex extractors instead.
    """
    package = GRAMMAR_MAP.get(language)
    if not package or importlib.util.find_spec(package.replace("-", "_")) is None:
        logger.debug(f"Grammatica tree-sitter per '{language}' non installata: uso delle regex.")
        return None
    try:
        return get_parser_for_language(language)
    except Exception as exc:
        logger.debug(f"Parser tree-sitter per '{language}' non disponibile ({exc}).")
        return None


class PropertyDiscoveryEngine:
    """
    PropertyDiscoveryEngine is the main engine responsible for FASE 1 of BOPLA: Property Discovery.
    It builds a unified PropertyInventory by extracting properties from:
    1. OpenAPI / Swagger specs (components.schemas and definitions).
    2. AST Analysis of source code (detecting DTO, Request/Response, Entity, and ORM Models).
    3. Runtime Traffic logs (request and response JSON bodies mapped to objects via normalized paths).
    """

    @classmethod
    def clean_object_name(cls, name: str) -> str:
        """
        Cleans and normalizes object/class names by removing common suffixes
        (e.g., DTO, Request, Response, Model, Entity, Schema) to enable correlation, then
        returns the canonical form (see canonical_object_name).
        Example: UserDTO -> User, UserRequest -> User, apply_coupon -> ApplyCoupon.
        """
        cleaned = name.strip()
        suffixes = ["DTO", "Request", "Response", "Model", "Entity", "Schema", "class", "struct"]
        for suffix in suffixes:
            if cleaned.endswith(suffix) or cleaned.lower().endswith(suffix.lower()):
                cleaned = cleaned[: -len(suffix)]

        # Clean any leading/trailing underscores/spaces. A name made only of a suffix (a class
        # called "Response" or "Model") keeps its original name.
        cleaned = cleaned.strip("_- ").strip() or name.strip("_- ").strip()
        return canonical_object_name(cleaned)

    @classmethod
    def get_object_name_from_path(cls, path: str) -> str:
        """
        Infers the object name from a REST endpoint path, in canonical form.
        Example: /api/orders/{id} -> Order, /users -> User, /people/{id} -> Person.
        """
        normalized = APIEndpointNormalizer.normalize_path(path)
        segments = [s for s in normalized.split("/") if s]
        if not segments:
            return "Unknown"

        # Find the last segment that is not a placeholder/ID. A singular segment right after a
        # plural collection (/users/alice, /users/me) is an identifier the normalizer could not
        # recognise (not numeric nor UUID), so it is skipped as well.
        resource = "Unknown"
        for idx in range(len(segments) - 1, -1, -1):
            segment = segments[idx]
            if segment.startswith("{") or segment.endswith("}"):
                continue
            previous = segments[idx - 1] if idx > 0 else ""
            if (
                previous.endswith("s")
                and not previous.startswith("{")
                and not segment.endswith("s")
                and singularize(previous) != previous
            ):
                continue
            resource = segment
            break

        return canonical_object_name(resource) or "Unknown"

    @classmethod
    def extract_openapi_properties(cls, openapi_spec: dict[str, Any]) -> dict[str, set[str]]:
        """
        Extracts properties from OpenAPI schemas (components.schemas), Swagger definitions and
        schemas declared inline in the operations (attributed to the object the operation is
        about: its named response/request schema, else the object of the path). `$ref`,
        allOf/oneOf/anyOf and arrays are resolved; nested properties get a dotted path
        (`address.city`).
        Returns a dict: {object_name: {property_names}}
        """
        if not openapi_spec:
            return {}
        return {
            obj: set(props)
            for obj, props in contract.contract_properties(openapi_spec).items()
            if props
        }

    @classmethod
    def extract_keys_from_json_recursive(cls, data: Any, prefix: str = "") -> set[str]:
        """
        Extracts the property keys of a JSON dict or list of dicts. First-level keys are kept
        as they are; keys of nested objects get a dotted path (`manager.salary`), so the
        properties of a related object are not merged into the outer one. The elements of a
        list share the path of the list.
        """
        keys = set()
        if isinstance(data, dict):
            for k, v in data.items():
                key = f"{prefix}{k}"
                keys.add(key)
                keys.update(cls.extract_keys_from_json_recursive(v, f"{key}."))
        elif isinstance(data, list):
            for item in data:
                keys.update(cls.extract_keys_from_json_recursive(item, prefix))
        return keys

    @classmethod
    def traffic_object(
        cls, openapi_spec: dict[str, Any] | None, method: str, path: str, direction: str
    ) -> str:
        """
        Object of an observed request ("write": its body) or response ("read"): the schema
        the contract associates with the matching operation when there is one (so /me and
        /profile read the object of their response schema), else the object of the path.
        """
        operation = contract.operation_for(openapi_spec, method, path)
        if operation is not None:
            return operation.object_for(direction)
        return cls.get_object_name_from_path(path)

    @classmethod
    def extract_runtime_properties(
        cls,
        runtime_traffic: list[dict[str, Any]],
        openapi_spec: dict[str, Any] | None = None,
    ) -> dict[str, set[str]]:
        """
        Extracts observed properties from request and response bodies in runtime traffic logs,
        mapping them to the object of the matching contract operation (when a contract is
        given) or to the object inferred from the endpoint path. Nested keys get a dotted path.
        """
        results: dict[str, set[str]] = {}
        if not runtime_traffic:
            return results

        for entry in runtime_traffic:
            path = entry.get("path")
            if not path:
                continue
            method = entry.get("method", "GET")

            # Request body params
            body_params = entry.get("body_params")
            if isinstance(body_params, str):
                with contextlib.suppress(Exception):
                    body_params = json.loads(body_params)
            # Response body (often has more detailed properties)
            resp_body = (
                entry.get("response_body") or entry.get("response") or entry.get("response_params")
            )
            if isinstance(resp_body, str):
                with contextlib.suppress(Exception):
                    resp_body = json.loads(resp_body)

            for direction, body in (("write", body_params), ("read", resp_body)):
                if not body:
                    continue
                obj_name = cls.traffic_object(openapi_spec, method, path, direction)
                if obj_name == "Unknown":
                    continue
                keys = cls.extract_keys_from_json_recursive(body)
                if keys:
                    results.setdefault(obj_name, set()).update(keys)

        return results

    # Classes that hold code, configuration or constants, not API data (B.10)
    NON_MODEL_NAMES = re.compile(r"^(?:Meta|Config)$|(?:TestCase|Tests?|Exception|Error)$")
    NON_MODEL_BASES = re.compile(
        r"\b(?:Enum|IntEnum|StrEnum|Flag|Exception|\w+Error|TestCase|APITestCase|"
        r"BaseSettings|AppConfig)\b"
    )

    @classmethod
    def is_non_model_class(cls, name: str, bases: str = "") -> bool:
        return bool(cls.NON_MODEL_NAMES.search(name) or cls.NON_MODEL_BASES.search(bases))

    @classmethod
    def _parse_python_ast(cls, node, source_bytes: bytes) -> list[tuple[str, list[str]]]:
        """Traverses Python tree-sitter AST nodes to find classes and their attributes."""
        classes = []

        def traverse(n):
            if n.type == "class_definition":
                name_node = None
                for child in n.children:
                    if child.type == "identifier":
                        name_node = child
                        break
                superclasses = n.child_by_field_name("superclasses")
                bases = superclasses.text.decode("utf-8", errors="replace") if superclasses else ""
                if name_node and not cls.is_non_model_class(
                    name_node.text.decode("utf-8", errors="replace"), bases
                ):
                    class_name = name_node.text.decode("utf-8", errors="replace")
                    properties = []

                    # Look for properties inside block
                    block_node = None
                    for child in n.children:
                        if child.type == "block":
                            block_node = child
                            break

                    if block_node:
                        for stmt in block_node.children:
                            # 1. Annotated assignment (name: str)
                            if stmt.type == "annotated_assignment":
                                for sub in stmt.children:
                                    if sub.type == "identifier":
                                        properties.append(
                                            sub.text.decode("utf-8", errors="replace")
                                        )
                                        break
                            # 2. Assignment (name = value)
                            elif stmt.type == "expression_statement":
                                for sub in stmt.children:
                                    if sub.type == "assignment":
                                        for ssub in sub.children:
                                            if ssub.type == "identifier":
                                                properties.append(
                                                    ssub.text.decode("utf-8", errors="replace")
                                                )
                                                break
                    if properties:
                        classes.append((class_name, properties))

            for child in n.children:
                traverse(child)

        traverse(node)
        return classes

    @classmethod
    def _parse_typescript_ast(cls, node, source_bytes: bytes) -> list[tuple[str, list[str]]]:
        """Traverses TS/JS tree-sitter AST nodes to find classes/interfaces and properties."""
        objects = []

        def traverse(n):
            if n.type in ("class_declaration", "interface_declaration", "type_alias_declaration"):
                name_node = None
                for child in n.children:
                    if child.type == "identifier":
                        name_node = child
                        break
                if name_node:
                    obj_name = name_node.text.decode("utf-8", errors="replace")
                    properties = []

                    body_node = None
                    for child in n.children:
                        if child.type in ("class_body", "object_type", "interface_body"):
                            body_node = child
                            break

                    if body_node:
                        for member in body_node.children:
                            if member.type in (
                                "property_signature",
                                "public_field_definition",
                                "property_definition",
                                "method_definition",
                            ):
                                for sub in member.children:
                                    if sub.type == "property_identifier":
                                        properties.append(
                                            sub.text.decode("utf-8", errors="replace")
                                        )
                                        break
                    if properties:
                        objects.append((obj_name, properties))

            for child in n.children:
                traverse(child)

        traverse(node)
        return objects

    @classmethod
    def _parse_go_ast(cls, node, source_bytes: bytes) -> list[tuple[str, list[str]]]:
        """Traverses Go tree-sitter AST nodes to find struct types and properties."""
        objects = []

        def traverse(n):
            if n.type == "type_spec":
                name_node = None
                struct_node = None
                for child in n.children:
                    if child.type == "type_identifier":
                        name_node = child
                    elif child.type == "struct_type":
                        struct_node = child
                if name_node and struct_node:
                    obj_name = name_node.text.decode("utf-8", errors="replace")
                    properties = []

                    fields_node = None
                    for child in struct_node.children:
                        if child.type == "field_declaration_list":
                            fields_node = child
                            break
                    if fields_node:
                        for member in fields_node.children:
                            if member.type == "field_declaration":
                                for sub in member.children:
                                    if sub.type == "field_identifier":
                                        prop_name = sub.text.decode("utf-8", errors="replace")
                                        # Look for json tag override
                                        json_tag = re.search(
                                            r'json:"([^",]+)',
                                            member.text.decode("utf-8", errors="replace"),
                                        )
                                        if json_tag:
                                            prop_name = json_tag.group(1)
                                        properties.append(prop_name)
                                        break
                    if properties:
                        objects.append((obj_name, properties))

            for child in n.children:
                traverse(child)

        traverse(node)
        return objects

    @classmethod
    def extract_properties_via_regex(
        cls, content: str, file_ext: str
    ) -> list[tuple[str, list[str]]]:
        """
        Regex-based parsing fallback for Python, JS/TS, and Go models.
        """
        results = []
        if file_ext == ".py":
            # Match Python classes
            chunks = content.split("class ")
            for chunk in chunks[1:]:
                lines = chunk.split("\n")
                if not lines:
                    continue
                header = lines[0]
                match = re.match(r"^([a-zA-Z0-9_]+)", header)
                if not match:
                    continue
                class_name = match.group(1)
                properties = []

                for line in lines[1:]:
                    if (
                        line.strip()
                        and not line.startswith(" ")
                        and not line.startswith("\t")
                        and not line.startswith("#")
                    ):
                        break
                    field_match = re.match(
                        r"^\s+([a-zA-Z0-9_]+)\s*(?::\s*[^=]+)?\s*(?:=\s*.+)?$", line
                    )
                    if field_match:
                        name = field_match.group(1)
                        if name not in (
                            "def",
                            "class",
                            "pass",
                            "return",
                            "import",
                            "from",
                            "logger",
                        ):
                            properties.append(name)
                if properties:
                    results.append((class_name, properties))

        elif file_ext in (".ts", ".tsx", ".js", ".mjs", ".cjs"):
            # Match TypeScript/JavaScript classes, interfaces, type aliases
            chunks = re.split(r"\b(interface|class|type)\s+", content)
            for i in range(1, len(chunks), 2):
                body = chunks[i + 1]
                lines = body.split("\n")
                if not lines:
                    continue
                header = lines[0]
                name_match = re.match(r"^([a-zA-Z0-9_]+)", header)
                if not name_match:
                    continue
                obj_name = name_match.group(1)
                properties = []

                brace_count = 0
                started = False
                for line in lines:
                    if "{" in line:
                        brace_count += line.count("{")
                        started = True
                    if "}" in line:
                        brace_count -= line.count("}")

                    field_match = re.search(r"^\s*([a-zA-Z0-9_]+)\s*\??\s*:", line)
                    if field_match:
                        properties.append(field_match.group(1))

                    if started and brace_count <= 0:
                        break
                if properties:
                    results.append((obj_name, properties))

        elif file_ext == ".go":
            # Match Go structs
            chunks = content.split("type ")
            for chunk in chunks[1:]:
                lines = chunk.split("\n")
                if not lines:
                    continue
                header = lines[0]
                struct_match = re.match(r"^([a-zA-Z0-9_]+)\s+struct\b", header)
                if not struct_match:
                    continue
                obj_name = struct_match.group(1)
                properties = []

                for line in lines[1:]:
                    if "}" in line:
                        break
                    field_match = re.match(
                        r"^\s*([a-zA-Z0-9_]+)\s+([a-zA-Z0-9_\[\]\*\{\}]+)", line.strip()
                    )
                    if field_match:
                        prop_name = field_match.group(1)
                        json_tag = re.search(r'json:"([^",]+)', line)
                        if json_tag:
                            prop_name = json_tag.group(1)
                        properties.append(prop_name)
                if properties:
                    results.append((obj_name, properties))

        return results

    @classmethod
    def parse_models(cls, language: str, root_node, source: bytes) -> list[tuple[str, list[str]]]:
        """Dispatches a tree-sitter tree to the model extractor of its language."""
        if language == "python":
            return cls._parse_python_ast(root_node, source)
        if language in ("javascript", "typescript"):
            return cls._parse_typescript_ast(root_node, source)
        if language == "go":
            return cls._parse_go_ast(root_node, source)
        return []

    @classmethod
    def extract_file_models(cls, file_path: Path, language: str) -> list[tuple[str, list[str]]]:
        """Models (class/struct name, properties) of one file: tree-sitter, then regex."""
        source = file_path.read_bytes()
        parser = get_installed_parser(language)
        if parser is not None:
            try:
                tree = parser.parse(source)
                models = cls.parse_models(language, tree.root_node, source)
                if models:
                    return models
            except Exception as exc:
                logger.debug(f"Tree-sitter fallito su {file_path} ({exc}). Fallback a regex...")
        return cls.extract_properties_via_regex(
            source.decode("utf-8", errors="replace"), file_path.suffix
        )

    @classmethod
    def extract_ast_properties(
        cls, repo_path: str, lang_name: str | None = None
    ) -> dict[str, set[str]]:
        """
        Scans source files in the repository to extract properties of classes/structs
        representing models/DTOs. Every file is parsed with the grammar of its own language
        (tree-sitter with a regex fallback); `lang_name` restricts the scan to one language.
        """
        results: dict[str, set[str]] = {}
        language = lang_name.lower().strip() if lang_name else None
        for file_path, file_lang in collect_source_files(repo_path, language):
            if is_test_file(file_path.relative_to(repo_path)):
                continue  # fixtures and test cases are not API data models
            try:
                for obj_name, props in cls.extract_file_models(file_path, file_lang):
                    if cls.is_non_model_class(obj_name):
                        continue
                    results.setdefault(cls.clean_object_name(obj_name), set()).update(props)
            except Exception as e:
                logger.warning(f"Errore durante la scansione AST di {file_path}: {e}")
        return results

    @classmethod
    def discover_properties(
        cls,
        repo_path: str,
        openapi_spec: dict[str, Any] | None = None,
        runtime_traffic: list[dict[str, Any]] | None = None,
        stack: StackInfo | None = None,
    ) -> PropertyInventory:
        """
        Orchestrates property discovery across OpenAPI, AST, and Runtime traffic,
        correlates the findings, and constructs a PropertyInventory.
        """
        logger.info("Avvio BOPLA Property Discovery Engine...")

        # 1. Run OpenAPI Discovery
        openapi_props = {}
        if openapi_spec:
            logger.info("BOPLA: Esecuzione scansione proprietà OpenAPI...")
            openapi_props = cls.extract_openapi_properties(openapi_spec)

        # 2. Run AST Discovery: every supported language present in the repository, each file
        # with its own grammar. The stack guess is not used to pick a single language, since
        # on mixed repositories it would silence all the other parts.
        logger.info("BOPLA: Esecuzione scansione AST (linguaggio deciso per file)...")
        ast_props = cls.extract_ast_properties(repo_path)

        # 3. Run Runtime Traffic Discovery
        runtime_props = {}
        if runtime_traffic:
            logger.info(
                f"BOPLA: Esecuzione scansione traffico runtime ({len(runtime_traffic)} entry)..."
            )
            runtime_props = cls.extract_runtime_properties(runtime_traffic, openapi_spec)

        # 4. Correlation & Inventory Building
        inventory_dict = {}

        # Combine all found objects
        all_objects = set(openapi_props.keys()) | set(ast_props.keys()) | set(runtime_props.keys())

        for obj in all_objects:
            obj_props_dict = {}

            # Gather all properties for this object across all sources
            o_props = openapi_props.get(obj, set())
            a_props = ast_props.get(obj, set())
            r_props = runtime_props.get(obj, set())

            all_props = o_props | a_props | r_props

            for prop in all_props:
                sources = []
                if prop in o_props:
                    sources.append("openapi")
                if prop in a_props:
                    sources.append("ast")
                if prop in r_props:
                    sources.append("runtime")

                obj_props_dict[prop] = PropertyInfo(name=prop, sources=sorted(sources))

            # Build list of PropertyInfo sorted by name
            prop_list = [obj_props_dict[p] for p in sorted(obj_props_dict.keys())]
            inventory_dict[obj] = ObjectProperties(properties=prop_list)

        return PropertyInventory(inventory_dict)
