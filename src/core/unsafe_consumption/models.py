from dataclasses import dataclass


@dataclass
class UnsafeConsumptionFinding:
    rule_id: str  # "UC-001" | "UC-002" | "UC-003"
    cwe_id: str
    category: str
    severity: str
    file_path: str
    line_number: int | None
    third_party_url: str | None  # URL del provider terzo se identificabile
    evidence: str
    missing_guard: str
    confidence: float
    layer: str  # "ast"


@dataclass
class UnsafeConsumptionReport:
    target_path: str
    findings: list[UnsafeConsumptionFinding]
    coverage_signals: dict[str, bool]
    summary: dict
