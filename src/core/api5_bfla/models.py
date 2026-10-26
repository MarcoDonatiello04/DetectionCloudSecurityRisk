from dataclasses import dataclass, field
from enum import Enum


class RuleID(str, Enum):
    """Identificativi univoci delle regole API5 (il valore e la stringa usata nei finding)."""

    BF_001 = "BF-001"  # privileged_endpoint_no_role_check
    BF_002 = "BF-002"  # auth_without_authz
    BF_003 = "BF-003"  # http_method_override
    BF_004 = "BF-004"  # admin_path_exposure
    BF_005 = "BF-005"  # missing_deny_by_default
    BF_006 = "BF-006"  # shadow_admin_function
    BF_007 = "BF-007"  # privilege_escalation_via_payload


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
