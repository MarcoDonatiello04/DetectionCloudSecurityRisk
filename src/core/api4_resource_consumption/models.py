from dataclasses import dataclass, field


@dataclass
class ResourceConsumptionFinding:
    rule_id: str  # e.g. "RC-001"
    cwe_id: str  # e.g. "CWE-770"
    category: str  # e.g. "unbounded_pagination"
    severity: str  # "HIGH" | "MEDIUM" | "LOW"
    file_path: str
    line_number: int | None
    endpoint: str | None  # route associated if identifiable
    parameter: str | None  # vulnerable parameter if identifiable
    evidence: str  # textual snippet of the found signal
    missing_guard: str  # description of the absent guard
    confidence: float  # 0.0 - 1.0
    layer: str  # "ast" | "config" | "openapi"


@dataclass
class ResourceConsumptionReport:
    target_path: str
    findings: list[ResourceConsumptionFinding] = field(default_factory=list)
    coverage_signals: dict[str, list[str]] = field(
        default_factory=dict
    )  # signals found per category
    summary: dict[str, dict[str, int]] = field(
        default_factory=dict
    )  # counts per severity and category
