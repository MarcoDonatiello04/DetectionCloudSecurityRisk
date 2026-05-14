from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


# =============================================================================
# ENUMS
# =============================================================================

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingCategory(Enum):
    # Infrastructure
    IAM = "IAM"
    STORAGE = "STORAGE"
    NETWORK = "NETWORK"
    ENCRYPTION = "ENCRYPTION"
    LOGGING = "LOGGING"
    API_GATEWAY = "API_GATEWAY"

    # API Security
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    RATE_LIMITING = "RATE_LIMITING"
    INPUT_VALIDATION = "INPUT_VALIDATION"
    DATA_EXPOSURE = "DATA_EXPOSURE"
    SECURITY_HEADERS = "SECURITY_HEADERS"
    API_EXPOSURE = "API_EXPOSURE"

    # Application
    INJECTION = "INJECTION"
    SECRETS = "SECRETS"
    MISCONFIGURATION = "MISCONFIGURATION"

    # Runtime
    RUNTIME_EXPOSURE = "RUNTIME_EXPOSURE"
    EXPLOITABILITY = "EXPLOITABILITY"


class FindingSource(Enum):
    CHECKOV = "CHECKOV"
    SPECTRAL = "SPECTRAL"
    SEMGREP = "SEMGREP"
    RUNTIME_VALIDATOR = "RUNTIME_VALIDATOR"
    SHADOW_API = "SHADOW_API"


class ValidationStatus(Enum):
    NOT_VALIDATED = "NOT_VALIDATED"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    PARTIALLY_CONFIRMED = "PARTIALLY_CONFIRMED"
    ERROR = "ERROR"


# =============================================================================
# SUPPORT MODELS
# =============================================================================

@dataclass
class CodeLocation:
    file_path: str
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    code_snippet: Optional[str] = None


@dataclass
class APIContext:
    endpoint: Optional[str] = None
    method: Optional[str] = None
    base_url: Optional[str] = None
    api_version: Optional[str] = None
    requires_authentication: Optional[bool] = None


@dataclass
class RuntimeEvidence:
    tested_url: Optional[str] = None
    http_status: Optional[int] = None
    response_time_ms: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_snippet: Optional[str] = None
    accessible_without_auth: Optional[bool] = None
    rate_limit_detected: Optional[bool] = None


@dataclass
class RiskContext:
    internet_exposed: Optional[bool] = None
    sensitive_data_detected: Optional[bool] = None
    public_resource: Optional[bool] = None
    exploitable: Optional[bool] = None
    attack_complexity: Optional[str] = None
    impact: Optional[str] = None


# =============================================================================
# MAIN FINDING MODEL
# =============================================================================

@dataclass
class Finding:

    # -------------------------------------------------------------------------
    # Core Identity
    # -------------------------------------------------------------------------

    finding_id: str
    source: FindingSource
    category: FindingCategory
    title: str
    description: str

    # -------------------------------------------------------------------------
    # Severity
    # -------------------------------------------------------------------------

    severity: Severity
    confidence: float  # 0.0 -> 1.0

    # -------------------------------------------------------------------------
    # Static Analysis Information
    # -------------------------------------------------------------------------

    rule_id: Optional[str] = None
    rule_name: Optional[str] = None

    # -------------------------------------------------------------------------
    # Resource Information
    # -------------------------------------------------------------------------

    resource_type: Optional[str] = None
    resource_name: Optional[str] = None
    resource_id: Optional[str] = None

    # -------------------------------------------------------------------------
    # Code / IaC Location
    # -------------------------------------------------------------------------

    location: Optional[CodeLocation] = None

    # -------------------------------------------------------------------------
    # API Information
    # -------------------------------------------------------------------------

    api: Optional[APIContext] = None

    # -------------------------------------------------------------------------
    # Runtime Validation
    # -------------------------------------------------------------------------

    validation_status: ValidationStatus = ValidationStatus.NOT_VALIDATED
    runtime_evidence: Optional[RuntimeEvidence] = None

    # -------------------------------------------------------------------------
    # Risk Context
    # -------------------------------------------------------------------------

    risk_context: Optional[RiskContext] = None

    # -------------------------------------------------------------------------
    # Correlation
    # -------------------------------------------------------------------------

    related_findings: List[str] = field(default_factory=list)

    # -------------------------------------------------------------------------
    # Compliance / Standards
    # -------------------------------------------------------------------------

    owasp_api_category: Optional[str] = None
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None

    # -------------------------------------------------------------------------
    # Remediation
    # -------------------------------------------------------------------------

    remediation: Optional[str] = None

    # -------------------------------------------------------------------------
    # Metadata
    # -------------------------------------------------------------------------

    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)

    # -------------------------------------------------------------------------
    # Timestamps
    # -------------------------------------------------------------------------

    detected_at: datetime = field(default_factory=datetime.utcnow)