from dataclasses import dataclass
from typing import Optional, List, Dict

@dataclass
class UnsafeConsumptionFinding:
    rule_id: str              # "UC-001" | "UC-002" | "UC-003"
    cwe_id: str
    category: str
    severity: str
    file_path: str
    line_number: Optional[int]
    third_party_url: Optional[str]   # URL del provider terzo se identificabile
    evidence: str
    missing_guard: str
    confidence: float
    layer: str                # "ast"

@dataclass
class UnsafeConsumptionReport:
    target_path: str
    findings: List[UnsafeConsumptionFinding]
    coverage_signals: Dict[str, bool]
    summary: Dict
