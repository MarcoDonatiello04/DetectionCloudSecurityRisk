"""
Broken Authentication - AST Parser Module (Fase 2).
Parses project source files using tree-sitter, extracts security signals,
and ranks files according to an authentication-related score.
"""

import contextlib
import importlib
import re
import subprocess
import sys
from pathlib import Path

from loguru import logger
from pydantic import BaseModel
from tree_sitter import Language, Node, Parser

from src.core.api2_broken_auth.discovery import Config, StackInfo


# --- Custom Exceptions ---
class UnsupportedLanguageException(Exception):
    """Raised when the requested language is not supported or grammar cannot be loaded."""

    pass


class ASTParsingException(Exception):
    """Raised when parsing fails for a specific file."""

    pass


# --- Output Model ---
class FileScore(BaseModel):
    file: str
    imports_auth: list[str]
    route_auth: list[str]
    env_vars_auth: list[str]
    chiamate_auth: list[str]
    score: int
    auth_functions: list[str] = []
    jwt_claims: list[str] = []
    auth_decorators: dict[str, str] = {}
    auth_middlewares: list[str] = []


# --- Constants & Mapping ---
GRAMMAR_MAP = {
    "python": "tree-sitter-python",
    "javascript": "tree-sitter-javascript",
    "typescript": "tree-sitter-typescript",
    "java": "tree-sitter-java",
    "go": "tree-sitter-go",
    "ruby": "tree-sitter-ruby",
    "php": "tree-sitter-php",
    "rust": "tree-sitter-rust",
}

EXTENSION_MAP = {
    "python": [".py"],
    "javascript": [".js", ".mjs", ".cjs"],
    "typescript": [".ts", ".tsx"],
    "java": [".java"],
    "go": [".go"],
    "ruby": [".rb"],
    "php": [".php"],
    "rust": [".rs"],
}

# Directories to exclude from source file collection
IGNORE_DIRS = {
    "node_modules",
    ".git",
    "__pycache__",
    "dist",
    "build",
    "vendor",
    "venv",
    ".venv",
    ".pytest_cache",
    ".terraform",
}

# Keywords to match in signals
ROUTE_KEYWORDS = {
    "login",
    "logout",
    "token",
    "oauth",
    "refresh",
    "signin",
    "signout",
    "auth",
    "password",
    "reset",
    "verify",
    "mfa",
    "2fa",
    "otp",
    "totp",
}

ENV_KEYWORDS = {
    "SECRET",
    "TOKEN",
    "AUTH",
    "KEY",
    "JWT",
    "PASSWORD",
    "CREDENTIAL",
    "CERT",
    "PRIVATE",
    "KEYCLOAK",
    "OAUTH",
    "SAMESITE",
    "MFA",
    "REFRESH",
}


# --- Grammar Loader ---
def get_parser_for_language(language_name: str) -> Parser:
    """
    Dynamically installs and loads the tree-sitter grammar package for the given language.
    """
    lang_key = language_name.lower().strip()
    grammar_package = GRAMMAR_MAP.get(lang_key)
    if not grammar_package:
        raise UnsupportedLanguageException(
            f"Linguaggio '{language_name}' non è supportato dal parser tree-sitter."
        )

    module_name = grammar_package.replace("-", "_")

    try:
        module = importlib.import_module(module_name)
    except ImportError:
        logger.info(
            f"Grammar package {grammar_package} non trovato. Installazione dinamica tramite pip..."
        )
        try:
            # Run pip install dynamically within the current virtualenv
            subprocess.run(
                [sys.executable, "-m", "pip", "install", grammar_package],
                check=True,
                capture_output=True,
            )
            # Invalidate caches to make sure importlib sees the new package
            importlib.invalidate_caches()
            module = importlib.import_module(module_name)
            logger.info(f"Grammar {grammar_package} installato ed importato con successo.")
        except Exception as e:
            raise UnsupportedLanguageException(
                f"Impossibile installare o importare il grammar {grammar_package} per {language_name}: {e}"
            ) from e

    try:
        language = Language(module.language())
        return Parser(language)
    except Exception as e:
        raise UnsupportedLanguageException(
            f"Errore durante l'inizializzazione del Parser/Language per {language_name}: {e}"
        ) from e


# --- File Utilities ---
def is_text_file(file_path: Path) -> bool:
    """Checks if a file is a text file by trying to read the first block."""
    try:
        with open(file_path, encoding="utf-8", errors="ignore") as f:
            f.read(1024)
            return True
    except Exception:
        return False


# --- Helper to clean library names for call checks ---
def _clean_library_name(lib_name: str) -> str:
    name = lib_name.lower()
    for prefix in [
        "python-",
        "flask-",
        "django-",
        "node-",
        "express-",
        "go-",
        "ruby-",
        "php-",
        "rust-",
    ]:
        if name.startswith(prefix):
            name = name[len(prefix) :]
    for suffix in ["-node", "-express", "-go", "-ruby", "-php", "-rust"]:
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    return name


# --- AST Node Traversal & Signals Collector ---
class ASTSignalCollector:
    def __init__(self, lang_name: str, auth_libraries: list[str]):
        self.lang_name = lang_name.lower()
        self.auth_libraries = auth_libraries
        self.clean_libs = [_clean_library_name(lib) for lib in auth_libraries]

        # Collections of signals found
        self.imports_auth: set[str] = set()
        self.route_auth: set[str] = set()
        self.env_vars_auth: set[str] = set()
        self.chiamate_auth: set[str] = set()

        # New Authentication Intelligence Engine signals
        self.auth_functions: set[str] = set()
        self.jwt_claims: set[str] = set()
        self.auth_decorators: dict[str, str] = {}
        self.auth_middlewares: set[str] = set()

    def collect(self, node: Node):
        """Recursively traverses the nodes and extracts security signals."""
        node_type = node.type

        # Safe decode helper
        node_text = ""
        with contextlib.suppress(Exception):
            node_text = (node.text or b"").decode("utf-8", errors="replace").strip()

        if node_text:
            # 1. Imports Auth
            is_import_node = node_type in (
                "import_statement",
                "import_from_statement",
                "import_declaration",
                "import_spec",
                "use_declaration",
                "use_clause",
            )
            # JS require call check
            is_require_call = (
                self.lang_name in ("javascript", "typescript")
                and node_type == "call_expression"
                and node_text.startswith("require(")
            )

            if is_import_node or is_require_call:
                for lib in self.auth_libraries:
                    if lib.lower() in node_text.lower():
                        self.imports_auth.add(node_text)
                        logger.debug(f"[AST Signal: Import] {node_text}")

            # 2. Route Auth
            # Python Decorator route detection (FastAPI/Flask)
            is_py_route = (
                self.lang_name == "python"
                and node_type == "decorator"
                and (
                    node_text.startswith("@app.")
                    or node_text.startswith("@router.")
                    or node_text.startswith("@blueprint.")
                )
            )
            # JS Express call route detection
            is_js_route = (
                self.lang_name in ("javascript", "typescript")
                and node_type == "call_expression"
                and any(
                    prefix in node_text
                    for prefix in [
                        "app.get(",
                        "app.post(",
                        "app.put(",
                        "app.delete(",
                        "router.get(",
                        "router.post(",
                        "router.put(",
                        "router.delete(",
                    ]
                )
            )
            # Java Spring annotation route detection
            is_java_route = (
                self.lang_name == "java"
                and node_type == "annotation"
                and any(
                    ann in node_text
                    for ann in [
                        "RequestMapping",
                        "GetMapping",
                        "PostMapping",
                        "PutMapping",
                        "DeleteMapping",
                    ]
                )
            )
            # General fallback check if node text has HTTP methods/route mappings in other languages
            is_general_route = (
                self.lang_name not in ("python", "javascript", "typescript", "java")
                and node_type
                in (
                    "call_expression",
                    "method_invocation",
                    "function_declaration",
                    "macro_definition",
                )
                and any(
                    term in node_text.lower()
                    for term in [".get(", ".post(", ".route(", "handlefunc("]
                )
            )

            if is_py_route or is_js_route or is_java_route or is_general_route:
                # Check path keywords
                node_text_lower = node_text.lower()
                for keyword in ROUTE_KEYWORDS:
                    if keyword in node_text_lower:
                        self.route_auth.add(node_text)
                        logger.debug(f"[AST Signal: Route] {node_text}")
                        break

            # 3. Env Vars Auth
            is_env_access = False
            if self.lang_name == "python":
                is_env_access = (
                    "os.environ" in node_text or "os.getenv" in node_text or "getenv(" in node_text
                )
            elif self.lang_name in ("javascript", "typescript"):
                is_env_access = "process.env" in node_text
            elif self.lang_name == "java":
                is_env_access = "System.getenv" in node_text
            else:
                # General environment keywords check
                is_env_access = any(
                    pattern in node_text for pattern in ["std::env", "getenv", "ENV["]
                )

            if is_env_access:
                for key_word in ENV_KEYWORDS:
                    if key_word in node_text:
                        self.env_vars_auth.add(node_text)
                        logger.debug(f"[AST Signal: Env Var] {node_text}")
                        break

            # 4. Chiamate Auth
            is_call_node = node_type in ("call", "call_expression", "method_invocation")
            if is_call_node:
                # Get the caller identifier/method name (first part of call, e.g. jwt.encode)
                func_name = node_text.split("(")[0].strip()
                func_name_lower = func_name.lower()
                for clean_lib in self.clean_libs:
                    if clean_lib in func_name_lower:
                        self.chiamate_auth.add(node_text)
                        logger.debug(f"[AST Signal: Call] {node_text}")
                        break

            # 5. Advanced AST: Auth Functions
            is_func_def = node_type in (
                "function_definition",
                "function_declaration",
                "method_definition",
                "method_declaration",
                "def_statement",
            )
            is_call = node_type in ("call", "call_expression", "method_invocation")

            if is_func_def or is_call:
                func_part = node_text.split("(")[0].strip()
                for prefix in ["def ", "function ", "func "]:
                    if func_part.startswith(prefix):
                        func_part = func_part[len(prefix) :].strip()
                func_clean_name = func_part.split(".")[-1].split(" ")[0].strip()

                auth_fn_keywords = {
                    "login",
                    "signin",
                    "authenticate",
                    "verify_token",
                    "decode_token",
                    "refresh_token",
                    "logout",
                    "verify_mfa",
                    "mfa",
                    "otp",
                    "totp",
                    "two_factor",
                    "twofactor",
                }
                if any(kw in func_clean_name.lower() for kw in auth_fn_keywords):
                    self.auth_functions.add(func_clean_name)
                    logger.debug(f"[AST Signal: Auth Fn] {func_clean_name}")

            # 6. Advanced AST: JWT Claims
            is_literal = node_type in (
                "string",
                "string_literal",
                "identifier",
                "property_identifier",
                "shorthand_property_identifier",
            )
            if is_literal:
                clean_literal = node_text.strip("'\"` ")
                jwt_claim_keywords = {
                    "sub",
                    "id",
                    "user_id",
                    "role",
                    "roles",
                    "groups",
                    "permissions",
                    "scope",
                    "email",
                    "samesite",
                    "httponly",
                    "secure",
                    "mfa",
                    "amr",
                    "acr",
                }
                if clean_literal in jwt_claim_keywords:
                    self.jwt_claims.add(clean_literal)
                    logger.debug(f"[AST Signal: JWT Claim] {clean_literal}")

            # 7. Advanced AST: Authorization Decorators & Annotations
            is_decorator = False
            decorator_text = ""
            if node_type in ("decorator", "annotation") or (
                node_text.startswith("@") and node_type in ("identifier", "call_expression")
            ):
                is_decorator = True
                decorator_text = node_text

            if is_decorator:
                dec_lower = decorator_text.lower()
                decorator_keywords = [
                    "roles_required",
                    "require_role",
                    "permission_required",
                    "secured",
                    "preauthorize",
                ]
                matched_keyword = None
                for kw in decorator_keywords:
                    if kw.lower() in dec_lower:
                        matched_keyword = kw
                        break

                if matched_keyword:
                    role_matches = re.findall(r'["\']([^"\']+)["\']', decorator_text)
                    role_val = ""
                    if role_matches:
                        role_val = role_matches[0]
                    else:
                        paren_match = re.search(r"\(([^)]+)\)", decorator_text)
                        if paren_match:
                            role_val = paren_match.group(1).strip()

                    func_name = ""
                    parent = node.parent
                    if parent:
                        for child in parent.children:
                            if (
                                child.type
                                in (
                                    "function_definition",
                                    "function_declaration",
                                    "method_declaration",
                                    "method_definition",
                                )
                                or "function" in child.type
                                or "method" in child.type
                            ):
                                for subchild in child.children:
                                    if subchild.type == "identifier":
                                        func_name = (
                                            (subchild.text or b"")
                                            .decode("utf-8", errors="replace")
                                            .strip()
                                        )
                                        break
                                if func_name:
                                    break
                    if not func_name and parent:
                        try:
                            idx = parent.children.index(node)
                            for i in range(idx + 1, len(parent.children)):
                                sibling = parent.children[i]
                                if (
                                    sibling.type
                                    in (
                                        "function_definition",
                                        "function_declaration",
                                        "method_declaration",
                                        "method_definition",
                                    )
                                    or "function" in sibling.type
                                    or "method" in sibling.type
                                ):
                                    for subchild in sibling.children:
                                        if subchild.type == "identifier":
                                            func_name = (
                                                (subchild.text or b"")
                                                .decode("utf-8", errors="replace")
                                                .strip()
                                            )
                                            break
                                    if func_name:
                                        break
                        except ValueError:
                            pass

                    if not func_name:
                        func_name = "decorated_route"

                    self.auth_decorators[func_name] = role_val
                    logger.debug(f"[AST Signal: Decorator] {func_name} -> {role_val}")

            # 8. Advanced AST: Middleware
            middleware_keywords = {
                "jwtmiddleware",
                "authenticationmiddleware",
                "bearertokenmiddleware",
                "keycloakmiddleware",
                "mfamiddleware",
                "ratelimitmiddleware",
                "limiter",
                "samesitemiddleware",
                "samesite",
            }
            node_lower = node_text.lower()
            for kw in middleware_keywords:
                if kw in node_lower:
                    words = re.findall(
                        r"\b\w+" + kw[len(kw) - 10 :] + r"\w*\b", node_text, re.IGNORECASE
                    )
                    if words:
                        self.auth_middlewares.add(words[0])
                    else:
                        self.auth_middlewares.add(node_text)
                    logger.debug(f"[AST Signal: Middleware] {node_text}")
                    break

        # Recurse down children
        for child in node.children:
            self.collect(child)


# --- Main Run Function ---
async def run(
    repo_path: str, stack: StackInfo, config: Config, parser: Parser | None = None
) -> list[FileScore]:
    """
    Main entry point for AST Parsing with Tree-sitter (Fase 2).
    Scans source files, parses them, extracts signals, calculates score, and applies limits.
    """
    path = Path(repo_path)
    lang_name = stack.linguaggio.lower().strip()

    logger.info(f"Avvio Fase 2 - AST Parsing su: {path} (Linguaggio: {lang_name})")

    # Step 1 - Initialize Parser
    if not parser:
        parser = get_parser_for_language(lang_name)

    # Step 2 - Gather source files
    extensions = EXTENSION_MAP.get(lang_name)
    if not extensions:
        raise UnsupportedLanguageException(
            f"Estensioni non configurate per il linguaggio: {lang_name}"
        )

    logger.debug(f"Estensioni cercate: {extensions}")
    source_files: list[Path] = []

    def collect_source_files(current_dir: Path):
        try:
            for item in current_dir.iterdir():
                if item.is_dir():
                    if item.name not in IGNORE_DIRS:
                        collect_source_files(item)
                elif item.is_file() and item.suffix in extensions:
                    if is_text_file(item):
                        source_files.append(item)
        except PermissionError:
            logger.warning(f"Permesso negato durante la scansione della cartella: {current_dir}")
        except Exception as e:
            logger.warning(f"Errore scansione cartella {current_dir}: {e}")

    collect_source_files(path)
    logger.info(f"File sorgente validi identificati: {len(source_files)}")

    # Step 3 - Analyze files
    scored_files: list[FileScore] = []

    for file_path in source_files:
        rel_path = str(file_path.relative_to(path))
        try:
            with open(file_path, "rb") as f:
                bytes_content = f.read()

            tree = parser.parse(bytes_content)
            if not tree or not tree.root_node:
                raise ASTParsingException(f"Root node vuoto o non valido per {rel_path}")

            # Collect signals
            collector = ASTSignalCollector(lang_name, stack.librerie_auth)
            collector.collect(tree.root_node)

            # Step 4 - Calculate score
            score = 0
            if collector.imports_auth:
                score += 1
            if collector.route_auth:
                score += 1
            if collector.env_vars_auth:
                score += 1
            if collector.chiamate_auth:
                score += 1

            if score >= config.scanner.score_minimo:
                file_score = FileScore(
                    file=rel_path,
                    imports_auth=sorted(collector.imports_auth),
                    route_auth=sorted(collector.route_auth),
                    env_vars_auth=sorted(collector.env_vars_auth),
                    chiamate_auth=sorted(collector.chiamate_auth),
                    score=score,
                    auth_functions=sorted(collector.auth_functions),
                    jwt_claims=sorted(collector.jwt_claims),
                    auth_decorators=collector.auth_decorators,
                    auth_middlewares=sorted(collector.auth_middlewares),
                )
                scored_files.append(file_score)
                logger.info(f"File {rel_path} analizzato. Score: {score}/4")
            else:
                logger.debug(f"File {rel_path} ignorato per score sotto soglia: {score}/4")

        except Exception as e:
            logger.warning(f"Errore durante l'analisi AST del file {rel_path}: {e}")
            continue

    logger.info(
        f"Totale file analizzati: {len(source_files)}. File sopra la soglia ({config.scanner.score_minimo}): {len(scored_files)}"
    )

    # Sort scored files by score descending
    scored_files.sort(key=lambda x: x.score, reverse=True)

    # Step 5 - Apply limits
    limit = config.scanner.max_file_per_fase
    if len(scored_files) > limit:
        logger.warning(
            f"Raggiunto il limite massimo di file per questa fase ({limit}). "
            f"Prendo i primi {limit} file con score decrescente."
        )
        scored_files = scored_files[:limit]

    return scored_files
