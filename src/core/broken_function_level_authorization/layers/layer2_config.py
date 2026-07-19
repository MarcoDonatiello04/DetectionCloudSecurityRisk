from __future__ import annotations

import logging
import re
from pathlib import Path

from src.core.broken_function_level_authorization.models import FunctionAuthzFinding
from src.core.broken_function_level_authorization.rules.missing_deny_by_default import (
    MissingDenyByDefaultRule,
)

logger = logging.getLogger(__name__)

SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
    ".mypy_cache",
    ".tox",
    "site-packages",
    "egg-info",
}


def _should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def discover_config_files(target_path: str) -> list[Path]:
    root = Path(target_path)
    if not root.exists():
        return []

    _INTERESTING = re.compile(
        r"^(settings\.py|config\.py|app_config\.py|web\.xml|application\.properties|"
        r"application\.yml|application\.yaml|security\.config|security\-config\.xml|"
        r"app\.py|main\.py|app\.js|server\.js|index\.js)$"
    )

    result: list[Path] = []

    if root.is_file():
        if _INTERESTING.match(root.name):
            result.append(root)
        return result

    for entry in root.rglob("*"):
        if not entry.is_file():
            continue
        if _should_skip(entry):
            continue
        if _INTERESTING.match(entry.name):
            result.append(entry)

    return result


def analyze_configs(target_path: str) -> list[FunctionAuthzFinding]:
    config_files = discover_config_files(target_path)
    if not config_files:
        return []

    all_findings: list[FunctionAuthzFinding] = []

    for cf in config_files:
        try:
            findings = MissingDenyByDefaultRule.analyze_config(cf)
            all_findings.extend(findings)
        except Exception as exc:
            logger.warning("Parser failed on %s: %s", cf, exc)

    return all_findings
