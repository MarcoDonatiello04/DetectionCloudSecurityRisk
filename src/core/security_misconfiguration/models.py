from dataclasses import dataclass
from typing import Optional, List, Dict

@dataclass
class MisconfigFinding:
    rule_id: str              # es. "SC-001"
    cwe_id: str
    category: str
    severity: str             # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    file_path: str
    line_number: Optional[int]
    evidence: str
    missing_guard: str
    confidence: float
    layer: str                # sempre "ast" per questo modulo

@dataclass
class MisconfigReport:
    target_path: str
    findings: List[MisconfigFinding]
    coverage_signals: Dict[str, bool]
    summary: Dict
