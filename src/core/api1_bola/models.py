"""
Modelli del livello statico del modulo API1:2023 (Broken Object Level Authorization).

Il livello statico legge il codice sorgente (Layer 1, AST) e il contratto OpenAPI
(Layer 3) e produce ``ObjectAuthzFinding``, sullo stesso schema dei finding API5.
Ogni finding porta la chiave di correlazione ``api:METODO:path`` usata anche dal
validatore runtime BOLA (``dynamic_orchestrator.py``): così il Correlation Engine può
unire l'ipotesi statica con la conferma empirica ed elevarne la severità.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

CWE_BOLA = "CWE-639"  # Authorization Bypass Through User-Controlled Key


class RuleID(str, Enum):
    """Identificativi univoci delle regole statiche API1 (il valore è la stringa nei finding)."""

    OA_001 = "OA-001"  # missing_ownership_filter
    OA_002 = "OA-002"  # direct_object_reference_no_check
    OA_003 = "OA-003"  # inconsistent_authz_across_methods
    OA_004 = "OA-004"  # unvalidated_nested_object_reference
    OA_005 = "OA-005"  # serial_id_no_authz_decorator


RULE_CATEGORY: dict[str, str] = {
    RuleID.OA_001.value: "missing_ownership_filter",
    RuleID.OA_002.value: "direct_object_reference_no_check",
    RuleID.OA_003.value: "inconsistent_authz_across_methods",
    RuleID.OA_004.value: "unvalidated_nested_object_reference",
    RuleID.OA_005.value: "serial_id_no_authz_decorator",
}


# ---------------------------------------------------------------------------
# Fatti estratti dal Layer 1 (un handler di rotta e ciò che fa con gli ID)
# ---------------------------------------------------------------------------


@dataclass
class ObjectAccess:
    """Accesso a un oggetto (lookup ORM/DB, subscript su una collezione) guidato da un ID."""

    line_number: int
    text: str
    id_param: str  # parametro di path che guida l'accesso
    object_var: str | None = None  # variabile a cui viene assegnato l'oggetto, se esiste
    scoped_to_identity: bool = False  # l'accesso stesso filtra per il soggetto autenticato
    linked_params: list[str] = field(default_factory=list)  # altri ID nella stessa istruzione


@dataclass
class OwnershipCheck:
    """Evidenza che l'oggetto viene legato al soggetto autenticato."""

    kind: str  # "scoped_query" | "comparison" | "helper" | "decorator"
    line_number: int
    text: str
    id_params: list[str] = field(default_factory=list)  # ID coperti dal controllo


@dataclass
class RouteHandler:
    """Handler di rotta e fatti di autorizzazione estratti dal suo corpo."""

    file_path: str
    line_number: int
    function_name: str
    path: str
    http_methods: list[str]
    language: str  # "python" | "javascript"
    id_params: list[str] = field(default_factory=list)
    numeric_id_params: list[str] = field(default_factory=list)
    guards: list[str] = field(default_factory=list)  # decorator / middleware grezzi
    has_authentication: bool = False  # decorator, middleware, Depends o guardia di file
    auth_evidence: str | None = None
    identity_before_access: bool = False  # identità del chiamante letta prima dell'accesso
    identity_evidence: str | None = None
    object_accesses: list[ObjectAccess] = field(default_factory=list)
    ownership_checks: list[OwnershipCheck] = field(default_factory=list)
    validated_params: list[str] = field(default_factory=list)
    bound_params: list[str] = field(default_factory=list)
    privileged_role_guard: str | None = None

    @property
    def accessed_params(self) -> list[str]:
        """Parametri di path effettivamente usati per accedere a un oggetto, in ordine di path."""
        used = {a.id_param for a in self.object_accesses}
        return [p for p in self.id_params if p in used]

    @property
    def is_authenticated(self) -> bool:
        """Esiste un contesto di identità (guardia esplicita o identità letta prima dell'accesso)."""
        return self.has_authentication or self.identity_before_access

    def first_access(self, param: str | None = None) -> ObjectAccess | None:
        """Primo accesso guidato da ``param`` (o dal primo ID, se None)."""
        for access in self.object_accesses:
            if param is None or access.id_param == param:
                return access
        return None


# ---------------------------------------------------------------------------
# Finding e report (stesso schema di API5)
# ---------------------------------------------------------------------------


@dataclass
class ObjectAuthzFinding:
    rule_id: str  # es. "OA-001"
    cwe_id: str  # "CWE-639"
    category: str  # es. "missing_ownership_filter"
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    file_path: str
    line_number: int | None
    endpoint: str | None  # route path come dichiarata nel codice
    http_methods: list[str]  # un solo metodo per finding: la chiave è per metodo
    id_parameter: str | None  # parametro di path che guida l'accesso all'oggetto
    found_guard: str | None  # protezione trovata (se parziale)
    missing_guard: str  # protezione assente
    evidence: str  # istruzione sorgente del segnale
    confidence: float  # 0.0 - 1.0
    layer: str  # "ast" | "ast+openapi"
    correlation_key: str | None = None  # "api:METODO:/path/{id}"
    contract_status: str | None = (
        None  # "security_declared" | "security_missing" | "not_documented"
    )
    related_rules: list[str] = field(default_factory=list)  # regole assorbite dalla dedup


@dataclass
class ObjectAuthzReport:
    target_path: str
    findings: list[ObjectAuthzFinding] = field(default_factory=list)
    coverage_signals: dict = field(default_factory=dict)
    summary: dict = field(default_factory=dict)
    handlers_analyzed: int = 0
