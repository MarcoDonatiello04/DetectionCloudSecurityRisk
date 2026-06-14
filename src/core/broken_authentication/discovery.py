"""
Broken Authentication - Manifest Discovery Module (Fase 1).
Identifies the technological stack and authentication libraries from project manifest and config files
using a local LLM (Ollama) with support for robust parsing and error recovery.
"""

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

# --- Main Run Function ---
async def run(repo_path: str, config: Config, llm_client: Optional[LLMClient] = None) -> StackInfo:
    """
    Main entry point for Manifest Discovery (Fase 1).
    Scans the repository path, builds context, asks the LLM, and parses/validates the stack info.
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

    # Step 3 - Context building
    context_parts = []
    for name, content in files_context.items():
        context_parts.append(f"=== FILE: {name} ===\n{content}")
    user_content = "\n\n".join(context_parts)

    # Step 4 - LLM Invocation
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

    logger.info(f"Invio contesto di {len(files_context)} file al client LLM (provider: {config.llm.provider})...")
    response_text = await llm_client.complete(system_prompt, user_content)

    # Step 5 - Parsing and double-attempt error recovery
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

    # Validate schema via Pydantic model
    try:
        stack_info = StackInfo.model_validate(parsed_data)
        logger.info(f"Discovery completato con successo. Linguaggio: {stack_info.linguaggio}, Framework: {stack_info.framework}")
        return stack_info
    except Exception as val_e:
        raise LLMResponseException(
            f"Errore di convalida dei dati JSON rispetto allo schema Pydantic StackInfo per il provider {config.llm.provider}: {val_e}"
        ) from val_e
