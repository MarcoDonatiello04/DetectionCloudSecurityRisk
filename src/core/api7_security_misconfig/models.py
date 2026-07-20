from dataclasses import dataclass


@dataclass
class MisconfigFinding:
    rule_id: str  # es. "SC-001"
    cwe_id: str
    category: str
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    file_path: str
    line_number: int | None
    evidence: str
    missing_guard: str
    confidence: float
    layer: str  # sempre "ast" per questo modulo


@dataclass
class MisconfigReport:
    target_path: str
    findings: list[MisconfigFinding]
    coverage_signals: dict[str, bool]
    summary: dict
