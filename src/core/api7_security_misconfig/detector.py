import ast
import logging
from collections.abc import Generator
from pathlib import Path

from src.core.api7_security_misconfig.models import MisconfigFinding, MisconfigReport
from src.core.api7_security_misconfig.rules import (
    cors_wildcard,
    debug_mode,
    hardcoded_secret,
    missing_security_headers,
    verbose_error_handler,
)
from src.domain.entities import Finding, ScanTarget
from src.domain.interfaces import IVulnerabilityDetector

logger = logging.getLogger(__name__)


def analyze(target_path: str) -> MisconfigReport:
    findings: list[MisconfigFinding] = []

    for file_path in _walk_source_files(target_path):
        try:
            content = file_path.read_text(errors="replace")
        except Exception as e:
            logger.warning(f"Failed to read file {file_path}: {e}")
            continue

        tree = _parse(file_path, content)
        if tree is None and file_path.suffix not in (".js", ".ts"):
            continue

        findings.extend(cors_wildcard.analyze(tree, file_path, content))
        findings.extend(debug_mode.analyze(tree, file_path, content))
        findings.extend(verbose_error_handler.analyze(tree, file_path, content))
        findings.extend(hardcoded_secret.analyze(tree, file_path, content))

    # SC-004 è una rule globale — analizza il target nel suo insieme
    findings.extend(missing_security_headers.analyze_global(target_path))

    # Filtra findings a bassa confidenza (< 0.70)
    findings = [f for f in findings if f.confidence >= 0.70]

    return MisconfigReport(
        target_path=target_path,
        findings=findings,
        coverage_signals=_build_coverage_signals(findings),
        summary=_build_summary(findings),
    )


def _walk_source_files(target_path: str) -> Generator[Path, None, None]:
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


def _parse(file_path: Path, content: str) -> ast.AST | None:
    if file_path.suffix != ".py":
        return None
    try:
        return ast.parse(content)
    except Exception as e:
        logger.warning(f"Failed to parse AST for {file_path}: {e}")
        return None


def _build_coverage_signals(findings: list[MisconfigFinding]) -> dict:
    return {
        rule_id: any(f.rule_id == rule_id for f in findings)
        for rule_id in ["SC-001", "SC-002", "SC-003", "SC-004", "SC-005"]
    }


def _build_summary(findings: list[MisconfigFinding]) -> dict:
    return {
        "total": len(findings),
        "by_severity": {
            sev: len([f for f in findings if f.severity == sev])
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        },
        "by_category": {
            cat: len([f for f in findings if f.category == cat])
            for cat in ("MISCONFIGURATION", "SECRETS")
        },
    }


class Api7SecurityMisconfigDetector(IVulnerabilityDetector):
    """
    Rilevatore di vulnerabilità OWASP API7: Security Misconfiguration.
    """

    @property
    def detector_id(self) -> str:
        return "API7_SECURITY_MISCONFIG"

    @property
    def name(self) -> str:
        return "Security Misconfiguration Detector"

    def analyze(self, target: ScanTarget) -> list[Finding]:
        target_path = target.target_path or "."
        report = analyze(target_path)
        return report.findings
