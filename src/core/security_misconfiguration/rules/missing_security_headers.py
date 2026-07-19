from pathlib import Path

from src.core.security_misconfiguration.models import MisconfigFinding

SECURITY_HEADER_SIGNALS = [
    "Talisman(",
    "helmet(",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "add_middleware",
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
    Rule globale: cerca segnali di security headers middleware
    in TUTTO il codebase. Emette AL MASSIMO UN finding.
    """
    positive_signals = []

    for file_path in _walk_source_files(target_path):
        # Escludi file di test
        if "test/" in file_path.as_posix() or "tests/" in file_path.as_posix():
            continue

        try:
            content = file_path.read_text(errors="replace")
        except Exception:
            continue

        if any(signal in content for signal in SECURITY_HEADER_SIGNALS):
            positive_signals.append(str(file_path))

    if positive_signals:
        return []  # headers configurati da qualche parte nel codebase

    # Nessun segnale trovato in nessun file → UN SOLO finding globale
    return [
        MisconfigFinding(
            rule_id="SC-004",
            cwe_id="CWE-693",
            category="missing_security_headers",
            severity="MEDIUM",
            file_path=target_path,  # il target, non un file specifico
            line_number=None,
            evidence="No security headers middleware found in codebase",
            missing_guard=(
                "Add flask_talisman.Talisman(app) for Flask, "
                "helmet() middleware for Express, "
                "or a custom @app.after_request that sets "
                "X-Content-Type-Options, X-Frame-Options, "
                "Strict-Transport-Security"
            ),
            confidence=0.70,
            layer="ast",
        )
    ]
