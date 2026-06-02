from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
import hashlib

# ─── PUNTEGGI DI SEVERITÀ DI DEFAULT ─────────────────────────────────────────

SEVERITY_SCORE_CRITICAL = 9.0
SEVERITY_SCORE_HIGH = 7.0
SEVERITY_SCORE_MEDIUM = 4.5
SEVERITY_SCORE_LOW = 2.0
SEVERITY_SCORE_INFO = 0.0


class Severity(Enum):
    """
    Rappresenta il livello di gravità (Severità) di un Finding di sicurezza.
    """
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def score(self) -> float:
        """
        Ritorna il punteggio di severità numerico standard per il calcolo del rischio.

        Returns:
            float: Punteggio numerico assegnato alla severità.
        """
        mapping = {
            Severity.CRITICAL: SEVERITY_SCORE_CRITICAL,
            Severity.HIGH: SEVERITY_SCORE_HIGH,
            Severity.MEDIUM: SEVERITY_SCORE_MEDIUM,
            Severity.LOW: SEVERITY_SCORE_LOW,
            Severity.INFO: SEVERITY_SCORE_INFO
        }
        return mapping.get(self, 0.0)


class FindingCategory(Enum):
    """
    Specifica la categoria di vulnerabilità o di configurazione rilevata.
    """
    # Infrastructure & IaC
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

    # Code / Application Analysis
    INJECTION = "INJECTION"
    SECRETS = "SECRETS"
    MISCONFIGURATION = "MISCONFIGURATION"

    # Runtime Vulnerability
    RUNTIME_EXPOSURE = "RUNTIME_EXPOSURE"
    EXPLOITABILITY = "EXPLOITABILITY"


class FindingSource(Enum):
    """
    Rappresenta lo scanner o lo strumento sorgente che ha rilevato il Finding.
    """
    CHECKOV = "CHECKOV"
    SPECTRAL = "SPECTRAL"
    SEMGREP = "SEMGREP"
    RUNTIME_VALIDATOR = "RUNTIME_VALIDATOR"
    SHADOW_API = "SHADOW_API"
    ZAP_DAST = "ZAP_DAST"


class ValidationStatus(Enum):
    """
    Rappresenta lo stato di convalida empirica di un Finding.
    """
    NOT_VALIDATED = "NOT_VALIDATED"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    PARTIALLY_CONFIRMED = "PARTIALLY_CONFIRMED"
    ERROR = "ERROR"


@dataclass(frozen=True)
class CodeLocation:
    """
    Rappresenta la localizzazione fisica all'interno dei file sorgente del Finding.
    """
    file_path: str
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    code_snippet: Optional[str] = None


@dataclass(frozen=True)
class APIContext:
    """
    Rappresenta il contesto dell'endpoint API associato al Finding di sicurezza.
    """
    endpoint: Optional[str] = None
    method: Optional[str] = None
    base_url: Optional[str] = None
    api_version: Optional[str] = None
    requires_authentication: Optional[bool] = None


@dataclass(frozen=True)
class RuntimeEvidence:
    """
    Evidenza empirica raccolta a runtime che convalida la vulnerabilità.
    """
    tested_url: Optional[str] = None
    http_status: Optional[int] = None
    response_time_ms: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_snippet: Optional[str] = None
    accessible_without_auth: Optional[bool] = None
    rate_limit_detected: Optional[bool] = None


@dataclass(frozen=True)
class RiskContext:
    """
    Contesto aggiuntivo per determinare il livello complessivo di esposizione al rischio.
    """
    internet_exposed: Optional[bool] = None
    sensitive_data_detected: Optional[bool] = None
    public_resource: Optional[bool] = None
    exploitable: Optional[bool] = None
    attack_complexity: Optional[str] = None
    impact: Optional[str] = None


@dataclass
class Finding:
    """
    Rappresenta l'entità core del Dominio che modella un rischio di sicurezza unificato.
    Mantiene l'idempotenza e l'immutabilità parziale dello stato iniziale.
    """
    finding_id: str
    source: FindingSource
    category: FindingCategory
    title: str
    description: str
    severity: Severity
    confidence: float  # Valore da 0.0 a 1.0

    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    resource_type: Optional[str] = None
    resource_name: Optional[str] = None
    resource_id: Optional[str] = None

    location: Optional[CodeLocation] = None
    api: Optional[APIContext] = None
    
    validation_status: ValidationStatus = ValidationStatus.NOT_VALIDATED
    runtime_evidence: Optional[RuntimeEvidence] = None
    risk_context: Optional[RiskContext] = None

    correlation_key: Optional[str] = None
    related_findings: List[str] = field(default_factory=list)

    owasp_api_category: Optional[str] = None
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    remediation: Optional[str] = None

    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=datetime.utcnow)

    @classmethod
    def create(
        cls,
        source: FindingSource,
        category: FindingCategory,
        title: str,
        description: str,
        severity: Severity,
        confidence: float,
        rule_id: str,
        target_identifier: str,
        **kwargs
    ) -> 'Finding':
        """
        Factory method per istanziare Finding generando un ID deterministico.

        Args:
            source (FindingSource): Sorgente del finding.
            category (FindingCategory): Categoria logica.
            title (str): Titolo descrittivo.
            description (str): Descrizione estesa.
            severity (Severity): Livello di gravità.
            confidence (float): Livello di confidenza (0.0 a 1.0).
            rule_id (str): Identificativo della regola violata.
            target_identifier (str): Identificativo della risorsa target.
            **kwargs: Altri parametri opzionali supportati dalla classe.

        Returns:
            Finding: Istanza di Finding creata con ID univoco.
        """
        finding_id = cls.generate_deterministic_id(source, rule_id, target_identifier)
        return cls(
            finding_id=finding_id,
            source=source,
            category=category,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            rule_id=rule_id,
            **kwargs
        )

    @staticmethod
    def generate_deterministic_id(source: FindingSource, rule_id: str, target_identifier: str) -> str:
        """
        Genera un identificativo stabile e univoco per evitare duplicati in correlazione.

        Args:
            source (FindingSource): Sorgente dello scanner.
            rule_id (str): Identificativo della regola di scansione.
            target_identifier (str): Stringa identificativa della risorsa target.

        Returns:
            str: Identificativo deterministico calcolato in hash.
        """
        raw_key = f"{source.value}|{rule_id}|{target_identifier}".encode('utf-8')
        return f"{source.value.lower()}-{hashlib.md5(raw_key).hexdigest()[:12]}"

    def to_dict(self) -> Dict[str, Any]:
        """
        Serializza il Finding in un dizionario compatibile con JSON.

        Returns:
            Dict[str, Any]: Mappa di attributi serializzati del Finding.
        """
        return {
            "finding_id": self.finding_id,
            "source": self.source.value,
            "category": self.category.value,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "resource_id": self.resource_id,
            "location": {
                "file_path": self.location.file_path,
                "start_line": self.location.start_line,
                "end_line": self.location.end_line,
                "code_snippet": self.location.code_snippet
            } if self.location else None,
            "api": {
                "endpoint": self.api.endpoint,
                "method": self.api.method,
                "base_url": self.api.base_url,
                "api_version": self.api.api_version,
                "requires_authentication": self.api.requires_authentication
            } if self.api else None,
            "validation_status": self.validation_status.value,
            "runtime_evidence": {
                "tested_url": self.runtime_evidence.tested_url,
                "http_status": self.runtime_evidence.http_status,
                "response_time_ms": self.runtime_evidence.response_time_ms,
                "response_headers": self.runtime_evidence.response_headers,
                "response_snippet": self.runtime_evidence.response_snippet,
                "accessible_without_auth": self.runtime_evidence.accessible_without_auth,
                "rate_limit_detected": self.runtime_evidence.rate_limit_detected
            } if self.runtime_evidence else None,
            "risk_context": {
                "internet_exposed": self.risk_context.internet_exposed,
                "sensitive_data_detected": self.risk_context.sensitive_data_detected,
                "public_resource": self.risk_context.public_resource,
                "exploitable": self.risk_context.exploitable,
                "attack_complexity": self.risk_context.attack_complexity,
                "impact": self.risk_context.impact
            } if self.risk_context else None,
            "correlation_key": self.correlation_key,
            "related_findings": self.related_findings,
            "owasp_api_category": self.owasp_api_category,
            "cwe_id": self.cwe_id,
            "cve_id": self.cve_id,
            "remediation": self.remediation,
            "tags": self.tags,
            "references": self.references,
            "raw_data": self.raw_data,
            "detected_at": self.detected_at.isoformat()
        }
