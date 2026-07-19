from dataclasses import dataclass, field


@dataclass
class FunctionAuthzFinding:
    rule_id: str  # es. "BF-001"
    cwe_id: str  # es. "CWE-285"
    category: str  # es. "privileged_endpoint_no_role_check"
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    file_path: str
    line_number: int | None
    endpoint: str | None  # route path se identificabile
    http_methods: list[str]  # metodi HTTP esposti
    required_role: str | None  # ruolo rilevato come necessario (se inferibile)
    found_guard: str | None  # decorator/check trovato (se parziale)
    missing_guard: str  # descrizione della protezione assente
    evidence: str  # snippet AST del segnale
    confidence: float  # 0.0 - 1.0
    layer: str  # "ast" | "config" | "openapi"


@dataclass
class FunctionAuthzReport:
    target_path: str
    findings: list[FunctionAuthzFinding] = field(default_factory=list)
    coverage_signals: dict = field(default_factory=dict)
    summary: dict = field(default_factory=dict)
