"""
Broken Authentication - Manifest Discovery Module (Fase 1).
Identifies the technological stack and authentication libraries from project manifest and config files
using a local LLM (Ollama) with support for robust parsing and error recovery.
"""

import re
import json
import httpx
import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings
from loguru import logger

# --- Custom Exceptions ---
class ManifestNotFoundException(Exception):
    """Raised when no manifest files are found in the repository root."""
    pass

class LLMResponseException(Exception):
    """Raised when the LLM response cannot be parsed into JSON after retries."""
    pass

class LLMConnectionException(Exception):
    """Raised when the LLM provider is unreachable."""
    pass

# --- Configuration Models ---
class LLMConfig(BaseModel):
    provider: str = "ollama"
    model: str = "llama3.1"
    timeout: float = 30.0
    retry_count: int = 3
    base_url: str = "http://localhost:11434"

class DockerConfig(BaseModel):
    timeout_startup: int = 30

class TargetConfig(BaseModel):
    base_url: str = "http://localhost:5000"
    username: str = "testuser"
    password: str = "testpassword"

class ScannerConfig(BaseModel):
    score_minimo: int = 2
    max_file_per_fase: int = 50
    timeout_http: float = 10.0

class OutputConfig(BaseModel):
    path: str = "output"
    formato: str = "both"  # "json" | "markdown" | "both"

class Config(BaseSettings):
    llm: LLMConfig = Field(default_factory=LLMConfig)
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    docker: DockerConfig = Field(default_factory=DockerConfig)
    target: TargetConfig = Field(default_factory=TargetConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)

    @classmethod
    def load(cls, file_path: Path) -> "Config":
        """Loads configuration from a YAML file or returns default settings."""
        if file_path.is_file():
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                logger.info(f"Configurazione caricata con successo da {file_path}")
                return cls.model_validate(data)
            except Exception as e:
                logger.warning(f"Errore caricamento config da {file_path}: {e}. Uso dei valori di default.")
        return cls()

# --- Pydantic Output Schema ---
class StackInfo(BaseModel):
    linguaggio: str
    framework: str
    librerie_auth: List[str]
    identity_provider: Optional[str] = None
    file_configurazione_rilevanti: List[str]
    discovery_methods: Dict[str, str] = Field(default_factory=dict)
    non_jwt_mechanisms: List[str] = Field(default_factory=list)
    crawled_routes: Dict[str, str] = Field(default_factory=dict)

# --- LLM Client Interface ---
class LLMClient:
    def __init__(self, config: LLMConfig):
        self.config = config

    async def complete(self, system: str, user: str) -> str:
        """Sends system and user messages to the LLM and returns the text response."""
        raise NotImplementedError

class OllamaClient(LLMClient):
    async def complete(self, system: str, user: str) -> str:
        url = f"{self.config.base_url.rstrip('/')}/api/chat"
        payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user}
            ],
            "stream": False,
            "options": {
                "temperature": 0.1
            }
        }
        if "json" in system.lower() or "json" in user.lower():
            payload["format"] = "json"

        logger.debug(f"Chiamata Ollama su {url} con modello {self.config.model}")
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                response = await client.post(url, json=payload)
                response.raise_for_status()
                data = response.json()
                return data["message"]["content"]
        except httpx.HTTPStatusError as e:
            raise LLMConnectionException(
                f"Errore HTTP da Ollama ({e.response.status_code}) per il provider {self.config.provider}: {e}"
            ) from e
        except (httpx.NetworkError, httpx.TimeoutException) as e:
            raise LLMConnectionException(
                f"Impossibile raggiungere Ollama su {url} (errore di rete/timeout) per il provider {self.config.provider}: {e}"
            ) from e
        except Exception as e:
            raise LLMConnectionException(
                f"Errore generico di connessione a Ollama per il provider {self.config.provider}: {e}"
            ) from e

# --- Repository Scanner ---
def find_relevant_files(repo_dir: Path) -> Dict[str, Path]:
    """
    Scans the repository to locate manifests/infra at root level, and configs recursively.
    """
    found = {}

    manifest_names = {
        "package.json", "requirements.txt", "pyproject.toml",
        "pom.xml", "build.gradle", "go.mod", "Gemfile",
        "composer.json", "Cargo.toml"
    }
    infra_names = {
        "docker-compose.yml", "docker-compose.yaml", "Dockerfile"
    }
    config_names = {
        ".env.example", ".env.template", "config.yml", "config.yaml",
        "application.yml", "application.properties", "settings.py"
    }

    # Root level scan for manifests and infra
    for name in manifest_names | infra_names:
        file_path = repo_dir / name
        if file_path.is_file():
            found[name] = file_path

    # Recursive scan for config files (ignoring common build/dependency dirs)
    ignore_dirs = {
        ".git", ".venv", "node_modules", ".terraform", "__pycache__",
        ".pytest_cache", "dist", "build", "target"
    }

    def walk_configs(current_dir: Path):
        try:
            for item in current_dir.iterdir():
                if item.is_dir():
                    if item.name not in ignore_dirs:
                        walk_configs(item)
                elif item.is_file() and item.name in config_names:
                    rel_path = str(item.relative_to(repo_dir))
                    found[rel_path] = item
        except PermissionError:
            logger.warning(f"Permesso negato durante la scansione ricorsiva di: {current_dir}")
        except Exception as e:
            logger.warning(f"Errore durante l'ispezione della cartella {current_dir}: {e}")

    walk_configs(repo_dir)
    return found

def _parse_json_robust(text: str) -> Dict[str, Any]:
    """Robustly extracts and parses JSON from LLM text containing markdown code blocks."""
    clean_text = text.strip()
    if clean_text.startswith("```json"):
        clean_text = clean_text[7:]
    elif clean_text.startswith("```"):
        clean_text = clean_text[3:]
    if clean_text.endswith("```"):
        clean_text = clean_text[:-3]
    clean_text = clean_text.strip()

    try:
        return json.loads(clean_text)
    except json.JSONDecodeError:
        start_idx = clean_text.find("{")
        end_idx = clean_text.rfind("}")
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            return json.loads(clean_text[start_idx:end_idx + 1])
        raise

def run_heuristics(files_context: Dict[str, str]) -> Dict[str, Any]:
    """Runs deterministic heuristics on manifest contents to discover tech stack and auth configurations."""
    inferred = {
        "linguaggio": "",
        "framework": "",
        "librerie_auth": [],
        "identity_provider": None,
        "non_jwt_mechanisms": [],
    }
    
    all_combined = "\n".join(files_context.values()).lower()
    
    # Non-JWT mechanisms detection
    if "basic " in all_combined or "basicauth" in all_combined or "authorizationbasic" in all_combined or "authbasic" in all_combined:
        inferred["non_jwt_mechanisms"].append("Basic Auth")
    if "api_key" in all_combined or "apikey" in all_combined or "x-api-key" in all_combined or "api-key" in all_combined:
        inferred["non_jwt_mechanisms"].append("API Key")
    if any(k in all_combined for k in ["client.crt", "client.key", "mtls", "mutual_tls", "client-cert", "client_cert", "cert.pem", "key.pem"]):
        inferred["non_jwt_mechanisms"].append("mTLS")

    # JavaScript/TypeScript
    if "package.json" in files_context:
        content = files_context["package.json"].lower()
        inferred["linguaggio"] = "TypeScript" if "typescript" in content else "JavaScript"
        if "express" in content:
            inferred["framework"] = "Express"
        elif "next" in content:
            inferred["framework"] = "Next.js"
        elif "nest" in content:
            inferred["framework"] = "NestJS"
            
        for lib in ["jsonwebtoken", "jose", "passport", "next-auth", "auth0", "keycloak-connect", "bcrypt", "passport-saml"]:
            if lib in content:
                inferred["librerie_auth"].append(lib)

    # Python
    python_manifests = ["requirements.txt", "pyproject.toml", "setup.py", "settings.py"]
    has_python = any(k in files_context for k in python_manifests)
    if has_python:
        inferred["linguaggio"] = "Python"
        all_py = "\n".join(files_context[k] for k in python_manifests if k in files_context).lower()
        if "fastapi" in all_py:
            inferred["framework"] = "FastAPI"
        elif "django" in all_py:
            inferred["framework"] = "Django"
        elif "flask" in all_py:
            inferred["framework"] = "Flask"
            
        for lib in ["pyjwt", "python-jose", "passlib", "bcrypt", "cryptography", "auth0", "cognito", "keycloak", "python3-saml", "pysaml2"]:
            if lib in all_py:
                if lib == "pyjwt":
                    inferred["librerie_auth"].append("PyJWT")
                else:
                    inferred["librerie_auth"].append(lib)
        if "jwt" in all_py and "PyJWT" not in inferred["librerie_auth"] and "python-jose" not in inferred["librerie_auth"]:
            inferred["librerie_auth"].append("PyJWT")

    # Go
    if "go.mod" in files_context:
        content = files_context["go.mod"].lower()
        inferred["linguaggio"] = "Go"
        if "gin" in content:
            inferred["framework"] = "Gin"
        elif "fiber" in content:
            inferred["framework"] = "Fiber"
        elif "echo" in content:
            inferred["framework"] = "Echo"
        for lib in ["jwt-go", "golang-jwt", "oauth2"]:
            if lib in content:
                inferred["librerie_auth"].append(lib)

    # Java
    java_manifests = ["pom.xml", "build.gradle"]
    if any(k in files_context for k in java_manifests):
        inferred["linguaggio"] = "Java"
        all_java = "\n".join(files_context[k] for k in java_manifests if k in files_context).lower()
        if "spring-boot" in all_java or "spring-security" in all_java:
            inferred["framework"] = "Spring Boot"
        for lib in ["spring-security", "jjwt", "keycloak", "nimbus-jose-jwt", "spring-security-saml"]:
            if lib in all_java:
                inferred["librerie_auth"].append(lib)

    # PHP
    if "composer.json" in files_context:
        content = files_context["composer.json"].lower()
        inferred["linguaggio"] = "PHP"
        if "laravel" in content:
            inferred["framework"] = "Laravel"
        elif "symfony" in content:
            inferred["framework"] = "Symfony"
        for lib in ["php-jwt", "oauth2-server"]:
            if lib in content:
                inferred["librerie_auth"].append(lib)

    # Rust
    if "Cargo.toml" in files_context:
        content = files_context["Cargo.toml"].lower()
        inferred["linguaggio"] = "Rust"
        if "actix" in content:
            inferred["framework"] = "Actix"
        elif "axum" in content:
            inferred["framework"] = "Axum"
        for lib in ["jsonwebtoken", "oauth2"]:
            if lib in content:
                inferred["librerie_auth"].append(lib)

    # Identity provider
    if "keycloak" in all_combined:
        inferred["identity_provider"] = "Keycloak"
    elif "auth0" in all_combined:
        inferred["identity_provider"] = "Auth0"
    elif "okta" in all_combined:
        inferred["identity_provider"] = "Okta"
    elif "cognito" in all_combined or "aws-amplify" in all_combined:
        inferred["identity_provider"] = "Cognito"

    return inferred

# --- Main Run Function ---
async def run(repo_path: str, config: Config, llm_client: Optional[LLMClient] = None) -> StackInfo:
    """
    Main entry point for Manifest Discovery (Fase 1).
    Scans the repository path, builds context, runs heuristics, asks the LLM, and parses/validates the stack info.
    """
    path = Path(repo_path)
    logger.info(f"Avvio Fase 1 - Manifest Discovery su: {path}")

    # Step 1 - Find files
    found_files = find_relevant_files(path)

    # Validate that at least one manifest exists at root
    manifest_names = {
        "package.json", "requirements.txt", "pyproject.toml",
        "pom.xml", "build.gradle", "go.mod", "Gemfile",
        "composer.json", "Cargo.toml"
    }
    manifests_found = [k for k in found_files.keys() if k in manifest_names]
    if not manifests_found:
        raise ManifestNotFoundException(
            f"Nessun file manifest di dipendenze (es. package.json, requirements.txt, ecc.) "
            f"rilevato nella root della repository: {path}"
        )

    # Step 2 - Read found files with limits and logging
    files_context = {}
    for rel_path, file_path in found_files.items():
        try:
            stat = file_path.stat()
            size = stat.st_size
            
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            if len(content) > 4000:
                content = content[:4000]

            files_context[rel_path] = content
            logger.info(f"Letto file manifest/config: {rel_path} ({size} bytes)")
        except Exception as e:
            logger.warning(f"File {rel_path} non leggibile o accessibile, saltato: {e}")
            continue

    # Step 3 - Context building & heuristics execution
    context_parts = []
    for name, content in files_context.items():
        context_parts.append(f"=== FILE: {name} ===\n{content}")
    user_content = "\n\n".join(context_parts)

    heuristic_results = run_heuristics(files_context)

    # Step 4 - LLM Invocation with Fallback
    system_prompt = (
        "Sei un esperto di sicurezza applicativa e architetture software.\n"
        "Analizza i file di configurazione e manifest forniti e rispondi\n"
        "SOLO con un oggetto JSON valido, senza testo aggiuntivo,\n"
        "senza markdown, senza backtick.\n\n"
        "Il JSON deve avere esattamente questa struttura:\n"
        "{\n"
        '  "linguaggio": "nome del linguaggio principale",\n'
        '  "framework": "nome del framework web principale",\n'
        '  "librerie_auth": ["lista", "delle", "librerie", "di", "autenticazione"],\n'
        '  "identity_provider": "nome provider esterno o null",\n'
        '  "file_configurazione_rilevanti": ["lista", "dei", "file", "trovati"]\n'
        "}\n\n"
        "Per librerie_auth includi qualsiasi libreria che gestisce:\n"
        "autenticazione, autorizzazione, JWT, sessioni, OAuth, OpenID,\n"
        "password hashing, API keys, MFA.\n\n"
        "Per identity_provider indica il nome se trovi riferimenti a\n"
        "Auth0, Cognito, Okta, Keycloak, Firebase Auth o simili,\n"
        "altrimenti null."
    )

    if not llm_client:
        llm_client = OllamaClient(config.llm)

    parsed_data = {}
    llm_succeeded = False
    try:
        logger.info(f"Invio contesto di {len(files_context)} file al client LLM (provider: {config.llm.provider})...")
        response_text = await llm_client.complete(system_prompt, user_content)
        
        # Parsing and double-attempt error recovery
        try:
            parsed_data = _parse_json_robust(response_text)
        except Exception as e:
            logger.warning(
                f"Primo tentativo di parsing fallito: {e}. "
                f"Tentativo di ripristino inviando richiesta di correzione esplicita..."
            )
            retry_system_prompt = (
                f"{system_prompt}\n\n"
                "ATTENZIONE: La tua risposta precedente non era in formato JSON valido. "
                "Assicurati di rispondere ESCLUSIVAMENTE con un oggetto JSON valido, senza spiegazioni, senza markdown o backtick."
            )
            retry_user_content = (
                f"Risposta precedente non valida:\n{response_text}\n\n"
                f"Rianalizza i seguenti file e fornisci il JSON corretto:\n{user_content}"
            )
            try:
                response_text = await llm_client.complete(retry_system_prompt, retry_user_content)
                parsed_data = _parse_json_robust(response_text)
            except Exception as retry_e:
                raise LLMResponseException(
                    f"La risposta dell'LLM (provider: {config.llm.provider}) non è parsabile in JSON dopo i tentativi di recupero: {retry_e}"
                ) from retry_e
            
        llm_succeeded = True
    except (LLMConnectionException, httpx.HTTPError, httpx.NetworkError, httpx.TimeoutException) as conn_err:
        logger.warning(f"Connessione LLM non disponibile (Ollama down/unreachable). Degradazione all'euristica deterministica: {conn_err}")
        parsed_data = {
            "linguaggio": heuristic_results["linguaggio"] or "unknown",
            "framework": heuristic_results["framework"] or "unknown",
            "librerie_auth": heuristic_results["librerie_auth"],
            "identity_provider": heuristic_results["identity_provider"],
            "file_configurazione_rilevanti": list(files_context.keys())
        }

    # Step 5 - Merge & Validation
    try:
        # Validate schema via Pydantic model
        stack_info = StackInfo.model_validate(parsed_data)
        
        # Merge heuristics with LLM inferred values if needed
        # Heuristics take precedence for determinism if they successfully found the values
        final_linguaggio = heuristic_results["linguaggio"] or stack_info.linguaggio
        final_framework = heuristic_results["framework"] or stack_info.framework
        final_idp = heuristic_results["identity_provider"] or stack_info.identity_provider
        
        final_libs_set = set(heuristic_results["librerie_auth"])
        for lib in stack_info.librerie_auth:
            final_libs_set.add(lib)
            
        stack_info.linguaggio = final_linguaggio
        stack_info.framework = final_framework
        stack_info.librerie_auth = sorted(list(final_libs_set))
        stack_info.identity_provider = final_idp
        
        # Populate non_jwt_mechanisms and discovery_methods
        stack_info.non_jwt_mechanisms = heuristic_results["non_jwt_mechanisms"]
        
        stack_info.discovery_methods = {
            "linguaggio": "heuristic" if heuristic_results["linguaggio"] else "llm_inferred",
            "framework": "heuristic" if heuristic_results["framework"] else "llm_inferred",
            "librerie_auth": "heuristic" if heuristic_results["librerie_auth"] else "llm_inferred",
            "identity_provider": "heuristic" if heuristic_results["identity_provider"] else "llm_inferred"
        }
        
        logger.info(f"Discovery completato con successo. Linguaggio: {stack_info.linguaggio}, Framework: {stack_info.framework}")
        
        # Step 6 - Dynamic Crawler (spidering) with safe-crawl policy
        crawled_routes = {}
        target_url = config.target.base_url
        logger.info(f"Avvio crawler su target {target_url}...")
        try:
            # Simple check for robots.txt
            ignored_paths = []
            async with httpx.AsyncClient(timeout=3.0) as crawler_client:
                try:
                    robots_res = await crawler_client.get(f"{target_url.rstrip('/')}/robots.txt")
                    if robots_res.status_code == 200:
                        logger.info("Robots.txt trovato, parsing regole...")
                        for line in robots_res.text.split("\n"):
                            if line.lower().startswith("disallow:"):
                                path_to_ignore = line.split(":")[-1].strip()
                                if path_to_ignore:
                                    ignored_paths.append(path_to_ignore)
                except Exception as robot_err:
                    logger.debug(f"Errore lettura robots.txt: {robot_err}")

                # Crawl implementation
                visited = set()
                queue = ["/"]
                max_depth = 3
                current_depth = 0
                
                # Helper to check robots.txt ignore paths
                def is_disallowed(path: str) -> bool:
                    for ignored in ignored_paths:
                        if path.startswith(ignored):
                            return True
                    return False

                while queue and current_depth < max_depth:
                    next_queue = []
                    for path in queue:
                        if path in visited or is_disallowed(path):
                            continue
                        visited.add(path)
                        full_url = f"{target_url.rstrip('/')}{path}"
                        try:
                            # Safe-crawl policy: GET/HEAD requests only for crawling/state transition
                            logger.debug(f"Crawling GET {full_url}")
                            res = await crawler_client.get(full_url)
                            if res.status_code == 200:
                                crawled_routes[path] = "GET"
                                # Look for links to explore
                                html = res.text
                                links = re.findall(r'href=["\']([^"\']+)["\']', html)
                                for link in links:
                                    if link.startswith("/") and not link.startswith("//"):
                                        if link not in visited:
                                            next_queue.append(link.split("#")[0].split("?")[0])
                                            
                                # Enumerate forms (POST/PUT/DELETE) without executing them
                                form_actions = re.findall(r'<form\s+[^>]*action=["\']([^"\']+)["\'][^>]*method=["\'](post|put|delete)["\']', html, re.IGNORECASE)
                                for action, method in form_actions:
                                    cleaned_action = action.split("?")[0]
                                    if cleaned_action.startswith("/") and not cleaned_action.startswith("//"):
                                        crawled_routes[cleaned_action] = method.upper()
                        except Exception as req_err:
                            logger.debug(f"Errore crawling {path}: {req_err}")
                    queue = next_queue
                    current_depth += 1
        except Exception as crawl_err:
            logger.warning(f"Errore crawler inatteso: {crawl_err}")
            
        stack_info.crawled_routes = crawled_routes
        return stack_info
    except Exception as val_e:
        if isinstance(val_e, LLMResponseException):
            raise
        raise LLMResponseException(
            f"Errore di convalida dei dati JSON rispetto allo schema Pydantic StackInfo per il provider {config.llm.provider}: {val_e}"
        ) from val_e
