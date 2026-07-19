"""
Layer 1 — AST-based detection for API4:2023 Unrestricted Resource Consumption.

Orchestrates all six AST rules across Python and JavaScript/TypeScript source files
under a given target path using tree-sitter for structured parsing.

Entry point: analyze_ast(target_path) -> list[ResourceConsumptionFinding]
"""

from __future__ import annotations

import logging
from pathlib import Path

import tree_sitter_javascript as tsjavascript
import tree_sitter_python as tspython
from tree_sitter import Language, Parser

from src.core.unrestricted_resource_consumption.models import ResourceConsumptionFinding
from src.core.unrestricted_resource_consumption.rules.graphql_batching import GraphQLBatchingRule
from src.core.unrestricted_resource_consumption.rules.loop_bounds import LoopBoundsRule
from src.core.unrestricted_resource_consumption.rules.pagination import PaginationRule
from src.core.unrestricted_resource_consumption.rules.third_party_cost import ThirdPartyCostRule
from src.core.unrestricted_resource_consumption.rules.timeout import TimeoutRule
from src.core.unrestricted_resource_consumption.rules.upload import UploadRule

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Language setup (lazy, module-level singletons)
# ---------------------------------------------------------------------------

_PY_LANGUAGE: Language | None = None
_JS_LANGUAGE: Language | None = None


def _get_python_language() -> Language | None:
    global _PY_LANGUAGE
    if _PY_LANGUAGE is None:
        try:
            _PY_LANGUAGE = Language(tspython.language())
        except Exception as exc:
            logger.warning("tree-sitter Python grammar unavailable: %s", exc)
    return _PY_LANGUAGE


def _get_javascript_language() -> Language | None:
    global _JS_LANGUAGE
    if _JS_LANGUAGE is None:
        try:
            _JS_LANGUAGE = Language(tsjavascript.language())
        except Exception as exc:
            logger.warning("tree-sitter JavaScript grammar unavailable: %s", exc)
    return _JS_LANGUAGE


# ---------------------------------------------------------------------------
# File filtering constants
# ---------------------------------------------------------------------------

PYTHON_EXTENSIONS = {".py"}
JS_EXTENSIONS = {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}
SUPPORTED_EXTENSIONS = PYTHON_EXTENSIONS | JS_EXTENSIONS

# Max file size to avoid OOM on generated/minified files (bytes)
MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB

# Directories to skip
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


# ---------------------------------------------------------------------------
# All rules, grouped by language
# ---------------------------------------------------------------------------

_PYTHON_RULES = [
    PaginationRule.analyze_python,
    UploadRule.analyze_python,
    TimeoutRule.analyze_python,
    GraphQLBatchingRule.analyze_python,
    LoopBoundsRule.analyze_python,
    ThirdPartyCostRule.analyze_python,
]

_JS_RULES = [
    PaginationRule.analyze_javascript,
    UploadRule.analyze_javascript,
    TimeoutRule.analyze_javascript,
    GraphQLBatchingRule.analyze_javascript,
    LoopBoundsRule.analyze_javascript,
    ThirdPartyCostRule.analyze_javascript,
]


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------


def _analyze_file(file_path: Path) -> list[ResourceConsumptionFinding]:
    """
    Parse a single file with tree-sitter and run all applicable rules.
    Returns an empty list on any error (skip-and-continue policy).
    """
    ext = file_path.suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        return []

    # Skip large files
    try:
        size = file_path.stat().st_size
    except OSError:
        return []

    if size > MAX_FILE_SIZE:
        logger.warning("Skipping large file (%d bytes): %s", size, file_path)
        return []

    if size == 0:
        return []

    # Read content
    try:
        content = file_path.read_bytes()
    except OSError as exc:
        logger.warning("Cannot read %s: %s", file_path, exc)
        return []

    # Detect if truly binary (heuristic: null bytes in first 8KB)
    if b"\x00" in content[:8192]:
        return []

    # Select language
    if ext in PYTHON_EXTENSIONS:
        language = _get_python_language()
        rules = _PYTHON_RULES
    else:
        language = _get_javascript_language()
        rules = _JS_RULES

    if language is None:
        logger.warning("Grammar unavailable for %s — skipping", file_path)
        return []

    # Parse
    try:
        parser = Parser(language)
        tree = parser.parse(content)
    except Exception as exc:
        logger.warning("Parse error in %s: %s", file_path, exc)
        return []

    root = tree.root_node
    if root.has_error:
        logger.debug("Syntax errors in %s (still analyzing recoverable AST)", file_path)

    # Run all rules
    findings: list[ResourceConsumptionFinding] = []
    str_path = str(file_path)
    for rule_fn in rules:
        try:
            findings.extend(rule_fn(root, str_path))
        except Exception as exc:
            logger.warning("Rule %s failed on %s: %s", rule_fn.__qualname__, file_path, exc)

    return findings


def _walk_files(target_path: Path):
    """Recursively yield all source files under target_path."""
    if target_path.is_file():
        yield target_path
        return

    for entry in target_path.rglob("*"):
        if not entry.is_file():
            continue
        # Skip ignored directories (check all parts of path)
        if any(part in SKIP_DIRS for part in entry.parts):
            continue
        if entry.suffix.lower() in SUPPORTED_EXTENSIONS:
            yield entry


def _dedup(findings: list[ResourceConsumptionFinding]) -> list[ResourceConsumptionFinding]:
    """
    De-duplicate findings by (rule_id, file_path, line_number).
    When duplicates exist, keep the one with the highest confidence.
    """
    seen: dict[tuple, ResourceConsumptionFinding] = {}
    for f in findings:
        key = (f.rule_id, f.file_path, f.line_number)
        if key not in seen or f.confidence > seen[key].confidence:
            seen[key] = f
    return list(seen.values())


_SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def _sort_findings(findings: list[ResourceConsumptionFinding]) -> list[ResourceConsumptionFinding]:
    return sorted(
        findings,
        key=lambda f: (
            _SEVERITY_ORDER.get(f.severity, 9),
            -f.confidence,
            f.file_path,
            f.line_number or 0,
        ),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze_ast(target_path: str) -> list[ResourceConsumptionFinding]:
    """
    Analyzes the source code under target_path using tree-sitter to find
    API4:2023 Unrestricted Resource Consumption risks.

    Workflow:
      1. Recursive walk of all .py, .js, .ts, .jsx, .tsx files under target_path
      2. Per-file: auto-detect language → parse with tree-sitter → run all rules
      3. Aggregate, de-duplicate, and sort by severity
      4. Return list[ResourceConsumptionFinding]

    Error handling:
      - Non-parsable files (syntax error): log warning, skip
      - Binary files: silently skipped
      - Files > 1 MB: log warning, skip
      - Missing grammar: log warning, skip
    """
    root_path = Path(target_path)
    if not root_path.exists():
        logger.error("Target path does not exist: %s", target_path)
        return []

    all_findings: list[ResourceConsumptionFinding] = []
    files_analyzed = 0
    files_skipped = 0

    for file_path in _walk_files(root_path):
        result = _analyze_file(file_path)
        if result is not None:
            all_findings.extend(result)
            files_analyzed += 1
        else:
            files_skipped += 1

    logger.info(
        "AST layer: analyzed %d files, %d skipped — %d findings",
        files_analyzed,
        files_skipped,
        len(all_findings),
    )

    deduped = _dedup(all_findings)
    return _sort_findings(deduped)
