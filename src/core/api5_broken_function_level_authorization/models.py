from dataclasses import dataclass, field
from typing import List, Dict, Optional

@dataclass
class FunctionAuthzFinding:
    rule_id: str                  # es. "BF-001"
    cwe_id: str                   # es. "CWE-285"
    category: str                 # es. "privileged_endpoint_no_role_check"
    severity: str                 # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    file_path: str
    line_number: Optional[int]
    endpoint: Optional[str]          # route path se identificabile
    http_methods: List[str]       # metodi HTTP esposti
    required_role: Optional[str]     # ruolo rilevato come necessario (se inferibile)
    found_guard: Optional[str]       # decorator/check trovato (se parziale)
    missing_guard: str            # descrizione della protezione assente
    evidence: str                 # snippet AST del segnale
    confidence: float             # 0.0 - 1.0
    layer: str                    # "ast" | "config" | "openapi"

@dataclass
class FunctionAuthzReport:
    target_path: str
    findings: List[FunctionAuthzFinding] = field(default_factory=list)
    coverage_signals: Dict = field(default_factory=dict)
    summary: Dict = field(default_factory=dict)
