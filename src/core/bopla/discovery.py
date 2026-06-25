import os
import re
import json
import yaml
from pathlib import Path
from typing import Dict, List, Set, Any, Optional, Tuple

from loguru import logger

# Import models
from src.core.bopla.models import PropertyInventory, ObjectProperties, PropertyInfo

# Reuse AST utilities from broken_authentication
from src.core.broken_authentication.ast_parser import (
    get_parser_for_language, UnsupportedLanguageException, IGNORE_DIRS, is_text_file,
    GRAMMAR_MAP, EXTENSION_MAP
)
from src.core.broken_authentication.discovery import StackInfo

# Reuse normalizer and object reference engine from normalizer and BOLA
from src.normalization.normalizer import APIEndpointNormalizer
from src.core.bola.discovery.object_discovery import ObjectReferenceDiscoveryEngine


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
        (e.g., DTO, Request, Response, Model, Entity) to enable correlation.
        Example: UserDTO -> User, UserRequest -> User.
        """
        cleaned = name.strip()
        suffixes = ["DTO", "Request", "Response", "Model", "Entity", "class", "struct"]
        for suffix in suffixes:
            if cleaned.endswith(suffix):
                cleaned = cleaned[:-len(suffix)]
            elif cleaned.lower().endswith(suffix.lower()):
                cleaned = cleaned[:-len(suffix)]
        
        # Capitalize and clean any leading/trailing underscores/spaces
        cleaned = cleaned.strip("_ ").strip()
        if cleaned:
            # Capitalize first letter
            cleaned = cleaned[0].upper() + cleaned[1:]
        return cleaned

    @classmethod
    def get_object_name_from_path(cls, path: str) -> str:
        """
        Infers the object name from a REST endpoint path.
        Example: /api/orders/{id} -> Order, /users -> User.
        """
        normalized = APIEndpointNormalizer.normalize_path(path)
        segments = [s for s in normalized.split("/") if s]
        if not segments:
            return "Unknown"
        
        # Find the last segment that is not a placeholder/ID
        resource = "Unknown"
        for segment in reversed(segments):
            if segment != "{id}" and not segment.startswith("{") and not segment.endswith("}"):
                resource = segment
                break
                
        # Singularize and capitalize
        name = resource.capitalize()
        if name.endswith("ies"):
            name = name[:-3] + "y"
        elif name.endswith("sses"):
            name = name[:-2]  # Classes -> Class
        elif name.endswith("s") and not name.endswith("ss"):
            if name.endswith("es") and any(name.endswith(x) for x in ["ches", "shes", "xes"]):
                name = name[:-2]
            else:
                name = name[:-1]
            
        return name

    @classmethod
    def extract_openapi_properties(cls, openapi_spec: Dict[str, Any]) -> Dict[str, Set[str]]:
        """
        Extracts properties from OpenAPI schemas (components.schemas) and Swagger definitions.
        Returns a dict: {object_name: {property_names}}
        """
        results = {}
        if not openapi_spec:
            return results

        # 1. OpenAPI 3 schemas
        schemas = openapi_spec.get("components", {}).get("schemas", {})
        for name, schema in schemas.items():
            cleaned_name = cls.clean_object_name(name)
            props = schema.get("properties", {})
            if props:
                if cleaned_name not in results:
                    results[cleaned_name] = set()
                results[cleaned_name].update(props.keys())

        # 2. Swagger 2.0 definitions
        definitions = openapi_spec.get("definitions", {})
        for name, schema in definitions.items():
            cleaned_name = cls.clean_object_name(name)
            props = schema.get("properties", {})
            if props:
                if cleaned_name not in results:
                    results[cleaned_name] = set()
                results[cleaned_name].update(props.keys())

        return results

    @classmethod
    def extract_keys_from_json_recursive(cls, data: Any) -> Set[str]:
        """
        Recursively extracts all property keys from a JSON dict or list of dicts.
        """
        keys = set()
        if isinstance(data, dict):
            for k, v in data.items():
                keys.add(k)
                keys.update(cls.extract_keys_from_json_recursive(v))
        elif isinstance(data, list):
            for item in data:
                keys.update(cls.extract_keys_from_json_recursive(item))
        return keys

    @classmethod
    def extract_runtime_properties(cls, runtime_traffic: List[Dict[str, Any]]) -> Dict[str, Set[str]]:
        """
        Extracts observed properties from request and response bodies in runtime traffic logs,
        mapping them to inferred objects based on endpoint paths.
        """
        results = {}
        if not runtime_traffic:
            return results

        for entry in runtime_traffic:
            path = entry.get("path")
            if not path:
                continue

            obj_name = cls.get_object_name_from_path(path)
            if obj_name == "Unknown":
                continue

            observed_keys = set()

            # Process request body params
            body_params = entry.get("body_params")
            if body_params:
                if isinstance(body_params, str):
                    try:
                        body_params = json.loads(body_params)
                    except Exception:
                        pass
                observed_keys.update(cls.extract_keys_from_json_recursive(body_params))

            # Process response body (often has more detailed properties)
            resp_body = entry.get("response_body") or entry.get("response") or entry.get("response_params")
            if resp_body:
                if isinstance(resp_body, str):
                    try:
                        resp_body = json.loads(resp_body)
                    except Exception:
                        pass
                observed_keys.update(cls.extract_keys_from_json_recursive(resp_body))

            if observed_keys:
                if obj_name not in results:
                    results[obj_name] = set()
                results[obj_name].update(observed_keys)

        return results

    @classmethod
    def _parse_python_ast(cls, node, source_bytes: bytes) -> List[Tuple[str, List[str]]]:
        """Traverses Python tree-sitter AST nodes to find classes and their attributes."""
        classes = []

        def traverse(n):
            if n.type == "class_definition":
                name_node = None
                for child in n.children:
                    if child.type == "identifier":
                        name_node = child
                        break
                if name_node:
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
                                        properties.append(sub.text.decode("utf-8", errors="replace"))
                                        break
                            # 2. Assignment (name = value)
                            elif stmt.type == "expression_statement":
                                for sub in stmt.children:
                                    if sub.type == "assignment":
                                        for ssub in sub.children:
                                            if ssub.type == "identifier":
                                                properties.append(ssub.text.decode("utf-8", errors="replace"))
                                                break
                    if properties:
                        classes.append((class_name, properties))

            for child in n.children:
                traverse(child)

        traverse(node)
        return classes

    @classmethod
    def _parse_typescript_ast(cls, node, source_bytes: bytes) -> List[Tuple[str, List[str]]]:
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
                            if member.type in ("property_signature", "public_field_definition", "property_definition", "method_definition"):
                                for sub in member.children:
                                    if sub.type == "property_identifier":
                                        properties.append(sub.text.decode("utf-8", errors="replace"))
                                        break
                    if properties:
                        objects.append((obj_name, properties))

            for child in n.children:
                traverse(child)

        traverse(node)
        return objects

    @classmethod
    def _parse_go_ast(cls, node, source_bytes: bytes) -> List[Tuple[str, List[str]]]:
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
                                        json_tag = re.search(r'json:"([^",]+)', member.text.decode("utf-8", errors="replace"))
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
    def extract_properties_via_regex(cls, content: str, file_ext: str) -> List[Tuple[str, List[str]]]:
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
                match = re.match(r'^([a-zA-Z0-9_]+)', header)
                if not match:
                    continue
                class_name = match.group(1)
                properties = []
                
                for line in lines[1:]:
                    if line.strip() and not line.startswith(" ") and not line.startswith("\t") and not line.startswith("#"):
                        break
                    field_match = re.match(r'^\s+([a-zA-Z0-9_]+)\s*(?::\s*[^=]+)?\s*(?:=\s*.+)?$', line)
                    if field_match:
                        name = field_match.group(1)
                        if name not in ("def", "class", "pass", "return", "import", "from", "logger"):
                            properties.append(name)
                if properties:
                    results.append((class_name, properties))

        elif file_ext in (".ts", ".tsx", ".js", ".mjs", ".cjs"):
            # Match TypeScript/JavaScript classes, interfaces, type aliases
            chunks = re.split(r'\b(interface|class|type)\s+', content)
            for i in range(1, len(chunks), 2):
                body = chunks[i+1]
                lines = body.split("\n")
                if not lines:
                    continue
                header = lines[0]
                name_match = re.match(r'^([a-zA-Z0-9_]+)', header)
                if not name_match:
                    continue
                obj_name = name_match.group(1)
                properties = []
                
                brace_count = 0
                started = False
                for line in lines:
                    if '{' in line:
                        brace_count += line.count('{')
                        started = True
                    if '}' in line:
                        brace_count -= line.count('}')
                    
                    field_match = re.search(r'^\s*([a-zA-Z0-9_]+)\s*\??\s*:', line)
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
                struct_match = re.match(r'^([a-zA-Z0-9_]+)\s+struct\b', header)
                if not struct_match:
                    continue
                obj_name = struct_match.group(1)
                properties = []
                
                for line in lines[1:]:
                    if '}' in line:
                        break
                    field_match = re.match(r'^\s*([a-zA-Z0-9_]+)\s+([a-zA-Z0-9_\[\]\*\{\}]+)', line.strip())
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
    def extract_ast_properties(cls, repo_path: str, lang_name: str) -> Dict[str, Set[str]]:
        """
        Scans source files in the repository to extract properties of classes/structs
        representing models/DTOs. Uses tree-sitter with a regex fallback.
        """
        results = {}
        path = Path(repo_path)
        if not path.is_dir():
            return results

        lang_key = lang_name.lower().strip()
        extensions = EXTENSION_MAP.get(lang_key)
        if not extensions:
            logger.warning(f"Linguaggio '{lang_name}' non ha estensioni associate. Scansione AST saltata.")
            return results

        # 1. Collect all source files
        source_files = []
        def collect(current_dir: Path):
            try:
                for item in current_dir.iterdir():
                    if item.is_dir():
                        if item.name not in IGNORE_DIRS:
                            collect(item)
                    elif item.is_file():
                        if item.suffix in extensions:
                            if is_text_file(item):
                                source_files.append(item)
            except Exception:
                pass
        
        collect(path)

        # 2. Parse each file
        for file_path in source_files:
            rel_path = str(file_path.relative_to(path))
            try:
                with open(file_path, "rb") as f:
                    bytes_content = f.read()

                parsed_models = []
                tree_sitter_succeeded = False

                # Try tree-sitter parsing first
                try:
                    parser = get_parser_for_language(lang_key)
                    tree = parser.parse(bytes_content)
                    if tree and tree.root_node:
                        if lang_key == "python":
                            parsed_models = cls._parse_python_ast(tree.root_node, bytes_content)
                        elif lang_key in ("javascript", "typescript"):
                            parsed_models = cls._parse_typescript_ast(tree.root_node, bytes_content)
                        elif lang_key == "go":
                            parsed_models = cls._parse_go_ast(tree.root_node, bytes_content)
                        
                        if parsed_models:
                            tree_sitter_succeeded = True
                except Exception as ast_err:
                    logger.debug(f"Tree-sitter fallito o non configurato per {rel_path} ({ast_err}). Fallback a regex...")

                # Fallback to regex if tree-sitter produced nothing or failed
                if not tree_sitter_succeeded:
                    content_str = bytes_content.decode("utf-8", errors="replace")
                    parsed_models = cls.extract_properties_via_regex(content_str, file_path.suffix)

                for obj_name, props in parsed_models:
                    cleaned_name = cls.clean_object_name(obj_name)
                    if cleaned_name not in results:
                        results[cleaned_name] = set()
                    results[cleaned_name].update(props)

            except Exception as e:
                logger.warning(f"Errore durante la scansione AST di {rel_path}: {e}")

        return results

    @classmethod
    def discover_properties(
        cls,
        repo_path: str,
        openapi_spec: Optional[Dict[str, Any]] = None,
        runtime_traffic: Optional[List[Dict[str, Any]]] = None,
        stack: Optional[StackInfo] = None
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

        # 2. Run AST Discovery
        ast_props = {}
        # Infer language from files if stack is missing
        lang = "python"
        if stack and stack.linguaggio:
            lang = stack.linguaggio
        else:
            # simple guess
            for root, dirs, files in os.walk(repo_path):
                # ignore common directories
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

        logger.info(f"BOPLA: Esecuzione scansione AST per {lang}...")
        ast_props = cls.extract_ast_properties(repo_path, lang)

        # 3. Run Runtime Traffic Discovery
        runtime_props = {}
        if runtime_traffic:
            logger.info(f"BOPLA: Esecuzione scansione traffico runtime ({len(runtime_traffic)} entry)...")
            runtime_props = cls.extract_runtime_properties(runtime_traffic)

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
