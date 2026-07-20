import ast
import logging
from collections.abc import Generator
from pathlib import Path

from src.core.api10_unsafe_consumption.models import (
    UnsafeConsumptionFinding,
    UnsafeConsumptionReport,
)
from src.core.api10_unsafe_consumption.rules import (
    blind_redirect_following,
    http_instead_of_https,
    unvalidated_external_data,
)

logger = logging.getLogger(__name__)


def analyze(target_path: str) -> UnsafeConsumptionReport:
    findings: list[UnsafeConsumptionFinding] = []

    for file_path in _walk_source_files(target_path):
        try:
            content = file_path.read_text(errors="replace")
        except Exception as e:
            logger.warning(f"Failed to read file {file_path}: {e}")
            continue

        tree = _parse(file_path, content)
        if tree is None:
            continue

        findings.extend(unvalidated_external_data.analyze(tree, file_path, content))
        findings.extend(http_instead_of_https.analyze(tree, file_path, content))
        findings.extend(blind_redirect_following.analyze(tree, file_path, content))

    findings = [f for f in findings if f.confidence >= 0.70]

    return UnsafeConsumptionReport(
        target_path=target_path,
        findings=findings,
        coverage_signals=_build_coverage_signals(findings),
        summary=_build_summary(findings),
    )


def _walk_source_files(target_path: str) -> Generator[Path, None, None]:
    path = Path(target_path)
    if path.is_file():
        if path.suffix == ".py":
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
        if p.is_file() and p.suffix == ".py":
            yield p


def _parse(file_path: Path, content: str) -> ast.AST | None:
    if file_path.suffix != ".py":
        return None
    try:
        return ast.parse(content)
    except Exception as e:
        logger.warning(f"Failed to parse AST for {file_path}: {e}")
        return None


def _build_coverage_signals(findings: list[UnsafeConsumptionFinding]) -> dict:
    return {
        rule_id: any(f.rule_id == rule_id for f in findings)
        for rule_id in ["UC-001", "UC-002", "UC-003"]
    }


def _build_summary(findings: list[UnsafeConsumptionFinding]) -> dict:
    return {
        "total": len(findings),
        "by_severity": {
            sev: len([f for f in findings if f.severity == sev])
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        },
        "by_category": {
            cat: len([f for f in findings if f.category == cat])
            for cat in {f.category for f in findings}
        },
    }


from src.domain.entities import Finding, ScanTarget
from src.domain.interfaces import IVulnerabilityDetector


class Api10UnsafeConsumptionDetector(IVulnerabilityDetector):
    """
    Rilevatore di vulnerabilità OWASP API10: Unsafe Consumption of APIs.
    """

    @property
    def detector_id(self) -> str:
        return "API10_UNSAFE_CONSUMPTION"

    @property
    def name(self) -> str:
        return "Unsafe Consumption Detector"

    def analyze(self, target: ScanTarget) -> list[Finding]:
        target_path = target.target_path or "."
        report = analyze(target_path)
        return report.findings

