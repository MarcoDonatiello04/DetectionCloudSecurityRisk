from dataclasses import asdict, dataclass, field


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
    # Cross-layer correlation (filled by correlation.correlate):
    #   "corroborated" — the same defect is seen by another layer on the same endpoint
    #   "compensated"  — the defense is enforced by another layer (severity lowered to INFO)
    #   "derived"      — produced by combining layers (e.g. RC-012 proven by RC-006 in code)
    correlation: str | None = None
    correlated_with: list[str] = field(default_factory=list)
    compensated_by: str | None = None
    original_severity: str | None = None

    @property
    def key(self) -> str:
        """Stable reference used to link findings of different layers."""
        where = self.endpoint or f"{self.file_path}:{self.line_number or '-'}"
        return f"{self.rule_id}@{where}" + (f"#{self.parameter}" if self.parameter else "")

    def to_dict(self) -> dict:
        return asdict(self)


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
    correlations: list[dict] = field(default_factory=list)  # cross-layer links
