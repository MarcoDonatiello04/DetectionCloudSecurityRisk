import json
import os
import shutil
import subprocess
from pathlib import Path


class SemgrepNotFoundError(Exception):
    """Semgrep non è installato nell'ambiente."""

    pass


class SemgrepTimeoutError(Exception):
    """Semgrep ha superato il timeout configurato."""

    pass


class SemgrepExecutionError(Exception):
    """Semgrep ha ritornato un errore non recuperabile."""

    pass


def _find_semgrep() -> str:
    """Locates Semgrep binary in PATH or in the project's .venv directory."""
    # 1. Check system PATH
    path_semgrep = shutil.which("semgrep")
    if path_semgrep:
        return path_semgrep

    # 2. Check project .venv
    project_root = Path(__file__).resolve().parent.parent.parent.parent
    venv_semgrep = project_root / ".venv" / "bin" / "semgrep"
    if venv_semgrep.exists() and os.access(venv_semgrep, os.X_OK):
        return str(venv_semgrep)

    return ""


def check_semgrep_available() -> str:
    """
    Verifica che semgrep sia installato e ritorna la versione.
    Lancia SemgrepNotFoundError con istruzioni se assente.
    """
    semgrep_path = _find_semgrep()
    if not semgrep_path:
        raise SemgrepNotFoundError(
            "Semgrep non trovato. Installare con: pip install semgrep\n"
            "Documentazione: https://semgrep.dev/docs/getting-started/"
        )
    result = subprocess.run([semgrep_path, "--version"], capture_output=True, text=True)
    return result.stdout.strip()


def run_semgrep(target_path: str, rules_path: str, timeout: int = 60) -> dict:
    """
    Esegue Semgrep e ritorna l'output JSON grezzo.

    Args:
        target_path: directory da analizzare
        rules_path: path al file semgrep_rules.yml del modulo
        timeout: secondi massimi di esecuzione

    Returns:
        dict con la struttura JSON di Semgrep
        {
            "results": [...],
            "errors": [...],
            "version": "...",
            "stats": {...}
        }

    Note:
        - Usa --json per output strutturato
        - Usa --no-git-ignore per analizzare tutto il target
        - Usa --timeout per singolo file (non totale)
        - Semgrep ritorna exit code 1 se trova findings — non è un errore
    """
    semgrep_path = _find_semgrep()
    if not semgrep_path:
        raise SemgrepNotFoundError(
            "Semgrep non trovato. Installare con: pip install semgrep\n"
            "Documentazione: https://semgrep.dev/docs/getting-started/"
        )

    cmd = [
        semgrep_path,
        "--config",
        rules_path,
        "--json",
        "--no-git-ignore",
        "--timeout",
        "30",  # timeout per singolo file
        "--max-memory",
        "1000",  # MB — evita OOM su file grandi
        "--quiet",  # sopprime progress bar
        target_path,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,  # timeout totale del processo
        )
    except subprocess.TimeoutExpired as exc:
        raise SemgrepTimeoutError(
            f"Semgrep ha superato il timeout di {timeout}s su {target_path}"
        ) from exc

    # Exit code 0 = no findings, 1 = findings found, 2+ = error
    if result.returncode >= 2:
        raise SemgrepExecutionError(
            f"Semgrep error (exit {result.returncode}): {result.stderr[:500]}"
        )

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise SemgrepExecutionError(f"Output Semgrep non è JSON valido: {e}") from e
