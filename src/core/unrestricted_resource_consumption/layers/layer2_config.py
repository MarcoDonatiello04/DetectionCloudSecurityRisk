"""
Layer 2 — Config File Detection for API4:2023 Unrestricted Resource Consumption.

Analyzes infrastructure configuration files (not source code) for missing
resource consumption guards. Independent from Layer 1 (no tree-sitter used here).

Rules implemented:
  RC-007 — No memory/CPU limits in docker-compose.yml
  RC-008 — No body size limit in nginx.conf / .env / settings.py
  RC-009 — No request timeout in nginx.conf / gunicorn.conf.py

Entry point: analyze_configs(target_path) -> list[ResourceConsumptionFinding]
"""

from __future__ import annotations

import ast
import logging
import re
from pathlib import Path
from typing import Callable, Optional

from src.core.unrestricted_resource_consumption.models import ResourceConsumptionFinding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Skip dirs (mirror layer1 convention)
# ---------------------------------------------------------------------------

SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__",
    ".pytest_cache", "dist", "build", ".mypy_cache", ".tox",
    "site-packages", "egg-info",
}

# Nginx body size over which we warn even if present (bytes)
NGINX_BODY_SIZE_WARN_THRESHOLD = 50 * 1024 * 1024  # 50 MB


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def _safe_read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.warning("Cannot read %s: %s", path, exc)
        return None


def _make_finding(
    *,
    rule_id: str,
    cwe_id: str,
    category: str,
    severity: str,
    file_path: str,
    line_number: Optional[int],
    evidence: str,
    missing_guard: str,
    confidence: float,
) -> ResourceConsumptionFinding:
    return ResourceConsumptionFinding(
        rule_id=rule_id,
        cwe_id=cwe_id,
        category=category,
        severity=severity,
        file_path=file_path,
        line_number=line_number,
        endpoint=None,
        parameter=None,
        evidence=evidence,
        missing_guard=missing_guard,
        confidence=confidence,
        layer="config",
    )


# ===========================================================================
# RC-007 — docker-compose.yml: no memory/CPU limits
# ===========================================================================

def _parse_docker_compose(path: Path) -> list[ResourceConsumptionFinding]:
    """
    Check every service in docker-compose.yml for deploy.resources.limits.memory.
    Falls back gracefully if PyYAML is unavailable.
    """
    text = _safe_read_text(path)
    if text is None:
        return []

    try:
        import yaml  # type: ignore
    except ImportError:
        logger.warning("PyYAML not installed — skipping %s", path)
        return []

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        logger.warning("YAML parse error in %s: %s", path, exc)
        return []

    if not isinstance(data, dict):
        return []

    services = data.get("services") or {}
    if not isinstance(services, dict):
        return []

    findings: list[ResourceConsumptionFinding] = []
    for svc_name, svc_cfg in services.items():
        if not isinstance(svc_cfg, dict):
            continue

        deploy = svc_cfg.get("deploy") or {}
        resources = deploy.get("resources") or {}
        limits = resources.get("limits") or {}

        missing: list[str] = []
        if not limits.get("memory") and not svc_cfg.get("mem_limit"):
            missing.append("memory")
        # cpus is optional — only flag memory

        if missing:
            findings.append(_make_finding(
                rule_id="RC-007",
                cwe_id="CWE-400",
                category="no_container_resource_limit",
                severity="MEDIUM",
                file_path=str(path),
                line_number=None,
                evidence=f"Service '{svc_name}' missing deploy.resources.limits: {', '.join(missing)}",
                missing_guard="deploy.resources.limits.memory (and optionally cpus)",
                confidence=0.9,
            ))

    return findings


# ===========================================================================
# RC-008 — Body size limit: nginx.conf / .env / settings.py
# ===========================================================================

def _parse_nginx_body_size(path: Path) -> list[ResourceConsumptionFinding]:
    """
    Check nginx.conf for client_max_body_size presence.
    Uses regex-based line parsing (no external dependency).
    """
    text = _safe_read_text(path)
    if text is None:
        return []

    findings: list[ResourceConsumptionFinding] = []

    # Look for client_max_body_size directive anywhere in the file
    pattern = re.compile(
        r"client_max_body_size\s+(\d+)([kKmMgG]?)\s*;", re.IGNORECASE
    )
    matches = list(pattern.finditer(text))

    if not matches:
        findings.append(_make_finding(
            rule_id="RC-008",
            cwe_id="CWE-400",
            category="no_body_size_limit",
            severity="HIGH",
            file_path=str(path),
            line_number=None,
            evidence="client_max_body_size not found in nginx config",
            missing_guard="client_max_body_size directive at http{} or server{} level",
            confidence=0.9,
        ))
        return findings

    # Check if any value is excessively large
    _MULTIPLIERS = {"k": 1024, "m": 1024**2, "g": 1024**3}
    for m in matches:
        value = int(m.group(1))
        unit = m.group(2).lower() if m.group(2) else ""
        bytes_val = value * _MULTIPLIERS.get(unit, 1)
        if bytes_val > NGINX_BODY_SIZE_WARN_THRESHOLD:
            line_no = text[: m.start()].count("\n") + 1
            findings.append(_make_finding(
                rule_id="RC-008",
                cwe_id="CWE-400",
                category="no_body_size_limit",
                severity="MEDIUM",
                file_path=str(path),
                line_number=line_no,
                evidence=f"client_max_body_size {m.group(1)}{m.group(2)} exceeds 50 MB threshold",
                missing_guard="Consider reducing client_max_body_size to a business-appropriate limit",
                confidence=0.7,
            ))

    return findings


def _parse_env_body_size(path: Path) -> list[ResourceConsumptionFinding]:
    """Check .env file for MAX_CONTENT_LENGTH."""
    text = _safe_read_text(path)
    if text is None:
        return []

    has_max_content = any(
        line.strip().upper().startswith("MAX_CONTENT_LENGTH=")
        for line in text.splitlines()
        if not line.strip().startswith("#")
    )
    # Also check Django's setting
    has_django_upload = any(
        line.strip().upper().startswith("DATA_UPLOAD_MAX_MEMORY_SIZE=")
        for line in text.splitlines()
        if not line.strip().startswith("#")
    )

    if not has_max_content and not has_django_upload:
        return [_make_finding(
            rule_id="RC-008",
            cwe_id="CWE-400",
            category="no_body_size_limit",
            severity="MEDIUM",
            file_path=str(path),
            line_number=None,
            evidence="MAX_CONTENT_LENGTH not set in environment file",
            missing_guard="MAX_CONTENT_LENGTH=<bytes> or DATA_UPLOAD_MAX_MEMORY_SIZE=<bytes>",
            confidence=0.75,
        )]
    return []


def _parse_settings_body_size(path: Path) -> list[ResourceConsumptionFinding]:
    """
    Parse settings.py / config.py with ast.parse() for MAX_CONTENT_LENGTH assignment.
    """
    text = _safe_read_text(path)
    if text is None:
        return []

    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError as exc:
        logger.warning("AST parse error in %s: %s", path, exc)
        return []

    target_names = {"MAX_CONTENT_LENGTH", "DATA_UPLOAD_MAX_MEMORY_SIZE", "max_content_length"}
    found = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in target_names:
                    found = True
                    break
        if isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name) and node.target.id in target_names:
                found = True

    if not found:
        return [_make_finding(
            rule_id="RC-008",
            cwe_id="CWE-400",
            category="no_body_size_limit",
            severity="MEDIUM",
            file_path=str(path),
            line_number=None,
            evidence=f"MAX_CONTENT_LENGTH not assigned in {path.name}",
            missing_guard="MAX_CONTENT_LENGTH = <bytes>  # Flask upload limit",
            confidence=0.7,
        )]
    return []


# ===========================================================================
# RC-009 — Request timeout: nginx.conf / gunicorn.conf.py
# ===========================================================================

def _parse_nginx_timeout(path: Path) -> list[ResourceConsumptionFinding]:
    """
    Check nginx.conf for proxy_read_timeout in location blocks with proxy_pass.
    Uses a line-based block tracker to handle multi-level nesting.
    """
    text = _safe_read_text(path)
    if text is None:
        return []

    findings: list[ResourceConsumptionFinding] = []
    lines = text.splitlines()

    # State machine: track brace depth and collect blocks
    # We look for location { ... } blocks that contain proxy_pass
    depth = 0
    in_location = False
    location_start_line: Optional[int] = None
    location_name = ""
    block_lines: list[str] = []

    TIMEOUT_RE = re.compile(
        r"proxy_read_timeout|proxy_connect_timeout|proxy_send_timeout",
        re.IGNORECASE,
    )
    LOCATION_RE = re.compile(r"^\s*location\s+([^{]+)\{?", re.IGNORECASE)

    for lineno, line in enumerate(lines, start=1):
        opens = line.count("{")
        closes = line.count("}")

        if not in_location:
            m = LOCATION_RE.match(line)
            if m:
                in_location = True
                location_name = m.group(1).strip()
                location_start_line = lineno
                block_lines = [line]
                depth = opens - closes
            # else: not inside a location block
        else:
            block_lines.append(line)
            depth += opens - closes
            if depth <= 0:
                # Block closed — analyze it
                # Strip comment lines before checking directives (avoid false negatives)
                block_text_no_comments = "\n".join(
                    l for l in block_lines if not l.strip().startswith("#")
                )
                if "proxy_pass" in block_text_no_comments and not TIMEOUT_RE.search(block_text_no_comments):
                    findings.append(_make_finding(
                        rule_id="RC-009",
                        cwe_id="CWE-400",
                        category="no_request_timeout",
                        severity="MEDIUM",
                        file_path=str(path),
                        line_number=location_start_line,
                        evidence=f"location {location_name}: proxy_pass without proxy_read_timeout",
                        missing_guard="proxy_connect_timeout Xs; proxy_read_timeout Xs; proxy_send_timeout Xs;",
                        confidence=0.85,
                    ))
                # Reset state
                in_location = False
                block_lines = []
                depth = 0

    return findings


def _parse_gunicorn_timeout(path: Path) -> list[ResourceConsumptionFinding]:
    """
    Parse gunicorn.conf.py with ast.parse().
    timeout = 0  → HIGH finding
    timeout absent → LOW finding (default 30s is acceptable but worth noting)
    """
    text = _safe_read_text(path)
    if text is None:
        return []

    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError as exc:
        logger.warning("AST parse error in %s: %s", path, exc)
        return []

    timeout_value: Optional[int] = None
    timeout_line: Optional[int] = None

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "timeout":
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, int):
                        timeout_value = node.value.value
                        timeout_line = node.lineno

    if timeout_value is None:
        return [_make_finding(
            rule_id="RC-009",
            cwe_id="CWE-400",
            category="no_request_timeout",
            severity="LOW",
            file_path=str(path),
            line_number=None,
            evidence="gunicorn 'timeout' not explicitly set (default 30s applies)",
            missing_guard="timeout = 30  # Explicit timeout recommended",
            confidence=0.5,
        )]

    if timeout_value == 0:
        return [_make_finding(
            rule_id="RC-009",
            cwe_id="CWE-400",
            category="no_request_timeout",
            severity="HIGH",
            file_path=str(path),
            line_number=timeout_line,
            evidence=f"gunicorn timeout = 0 disables worker watchdog (infinite hang possible)",
            missing_guard="timeout = 30  # Non-zero timeout required",
            confidence=0.98,
        )]

    return []  # timeout > 0 and explicitly set → OK


def _parse_procfile_timeout(path: Path) -> list[ResourceConsumptionFinding]:
    """
    Check Procfile for gunicorn/uvicorn invocations lacking --timeout flag.
    """
    text = _safe_read_text(path)
    if text is None:
        return []

    findings: list[ResourceConsumptionFinding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if "gunicorn" not in line and "uvicorn" not in line:
            continue
        if "--timeout" in line or "-t " in line:
            continue
        findings.append(_make_finding(
            rule_id="RC-009",
            cwe_id="CWE-400",
            category="no_request_timeout",
            severity="LOW",
            file_path=str(path),
            line_number=lineno,
            evidence=f"Procfile: {line.strip()[:100]} — no --timeout flag",
            missing_guard="Add --timeout 30 to gunicorn/uvicorn command",
            confidence=0.6,
        ))
    return findings


# ===========================================================================
# File discovery and dispatcher
# ===========================================================================

# (filename_pattern, parser_function)
_PARSERS: list[tuple[re.Pattern, Callable[[Path], list[ResourceConsumptionFinding]]]] = [
    # RC-007
    (re.compile(r"^docker-compose\.ya?ml$", re.IGNORECASE), _parse_docker_compose),
    # RC-008 nginx
    (re.compile(r"^nginx\.conf$", re.IGNORECASE), _parse_nginx_body_size),
    (re.compile(r".*\.conf$", re.IGNORECASE), _parse_nginx_body_size),
    # RC-008 env
    (re.compile(r"^\.env(\..+)?$"), _parse_env_body_size),
    # RC-008 settings
    (re.compile(r"^(settings|config|app_config)\.py$"), _parse_settings_body_size),
    # RC-009 nginx (same file, different parser)
    (re.compile(r"^nginx\.conf$", re.IGNORECASE), _parse_nginx_timeout),
    (re.compile(r".*\.conf$", re.IGNORECASE), _parse_nginx_timeout),
    # RC-009 gunicorn
    (re.compile(r"^gunicorn\.conf(\.py)?$"), _parse_gunicorn_timeout),
    # RC-009 Procfile
    (re.compile(r"^Procfile$"), _parse_procfile_timeout),
]

# Track which parsers have already been applied per file
# to avoid running the same parser twice on the same file
_NGINX_FILES_SEEN: set[str] = set()


def _get_parsers_for_file(path: Path) -> list[Callable[[Path], list[ResourceConsumptionFinding]]]:
    """Return the list of applicable parsers for a given config file."""
    name = path.name
    matched: list[Callable] = []
    seen_fns: set = set()
    for pattern, fn in _PARSERS:
        if pattern.match(name) and fn not in seen_fns:
            matched.append(fn)
            seen_fns.add(fn)
    return matched


def discover_config_files(target_path: str) -> list[Path]:
    """
    Recursively discover all config files under target_path.
    Excludes common non-application directories.
    """
    root = Path(target_path)
    if not root.exists():
        return []

    # All filenames we care about (patterns)
    _INTERESTING = re.compile(
        r"^(docker-compose\.ya?ml|nginx\.conf|.*\.conf|"
        r"\.env(\..+)?|settings\.py|config\.py|app_config\.py|"
        r"gunicorn\.conf(\.py)?|Procfile|application\.(yml|yaml|properties))$"
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


# ===========================================================================
# Public API
# ===========================================================================

def analyze_configs(target_path: str) -> list[ResourceConsumptionFinding]:
    """
    Walk target_path recursively and analyze all detected config files.

    Does NOT raise on missing or malformed files — logs warning and continues.

    Returns a list of ResourceConsumptionFinding with layer='config'.
    """
    config_files = discover_config_files(target_path)
    if not config_files:
        logger.debug("No config files found under %s", target_path)
        return []

    all_findings: list[ResourceConsumptionFinding] = []

    for cf in config_files:
        parsers = _get_parsers_for_file(cf)
        for parser_fn in parsers:
            try:
                findings = parser_fn(cf)
                all_findings.extend(findings)
            except Exception as exc:
                logger.warning("Parser %s failed on %s: %s", parser_fn.__name__, cf, exc)

    logger.info(
        "Config layer: analyzed %d files — %d findings",
        len(config_files),
        len(all_findings),
    )
    return all_findings
