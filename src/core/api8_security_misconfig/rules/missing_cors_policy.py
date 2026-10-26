from pathlib import Path

from src.core.api8_security_misconfig.models import MisconfigFinding

API_SIGNALS = [
    "Flask(",
    "FastAPI(",
    "express()",
    "from flask import",
    "from fastapi import",
    "import express",
    "Blueprint(",
    "APIRouter(",
]

CORS_SIGNALS = [
    "CORS(",
    "CORSMiddleware",
    "cors(",
    "CORS_ALLOW_ALL_ORIGINS",
    "CORS_ALLOWED_ORIGINS",
    "flask_cors",
    "cross_origin",
]


def _walk_source_files(target_path: str):
    path = Path(target_path)
    if path.is_file():
        if path.suffix in (".py", ".js", ".ts"):
            yield path
        return
    skip_dirs = {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        "dist",
        "build",
    }
    for p in path.rglob("*"):
        if any(part in skip_dirs for part in p.parts):
            continue
        if p.is_file() and p.suffix in (".py", ".js", ".ts"):
            yield p


def analyze_global(target_path: str) -> list[MisconfigFinding]:
    """
    Rule globale: verifica se l'applicazione API omette completamente
    la configurazione delle policy CORS (CWE-942).
    Emette AL MASSIMO UN finding globale se l'API non dichiara alcuna policy CORS.
    """
    has_api = False
    has_cors = False

    for file_path in _walk_source_files(target_path):
        if "test/" in file_path.as_posix() or "tests/" in file_path.as_posix():
            continue

        try:
            content = file_path.read_text(errors="replace")
        except Exception:
            continue

        if not has_api and any(signal in content for signal in API_SIGNALS):
            has_api = True

        if any(signal in content for signal in CORS_SIGNALS):
            has_cors = True
            break

    # Se non è un'applicazione API, o se CORS è già configurato, nessun finding
    if not has_api or has_cors:
        return []

    return [
        MisconfigFinding(
            rule_id="SC-006",
            cwe_id="CWE-942",
            category="missing_cors_policy",
            severity="MEDIUM",
            file_path=target_path,
            line_number=None,
            evidence="API web framework detected but no CORS middleware or policy configured across codebase",
            missing_guard=(
                "Configure an explicit CORS allowlist policy (e.g., flask_cors.CORS(app, origins=['https://trusted.domain']) "
                "or app.add_middleware(CORSMiddleware, allow_origins=['https://trusted.domain']) for FastAPI)"
            ),
            confidence=0.85,
            layer="ast",
        )
    ]
