"""
Rappresenta un singolo Finding di sicurezza normalizzato per la visualizzazione nella GUI.
Responsabilità:
- Incapsulare l'entità core Finding del dominio.
- Fornire property di convenienza formattate per le tabelle e i dettagli della GUI.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from src.domain.entities import Finding, Severity, FindingCategory, FindingSource, ValidationStatus

class FindingModel:
    """
    Wrapper model per facilitare l'integrazione tra l'entità di dominio Finding e la GUI.
    """

    def __init__(self, domain_finding: Finding):
        """
        Inizializza il modello a partire da un'entità del dominio.
        """
        self.finding = domain_finding

    @property
    def id(self) -> str:
        return self.finding.finding_id

    @property
    def source(self) -> str:
        return self.finding.source.value if hasattr(self.finding.source, "value") else str(self.finding.source)

    @property
    def category(self) -> str:
        return self.finding.category.value if hasattr(self.finding.category, "value") else str(self.finding.category)

    @property
    def title(self) -> str:
        return self.finding.title

    @property
    def description(self) -> str:
        return self.finding.description

    @property
    def severity(self) -> str:
        return self.finding.severity.value if hasattr(self.finding.severity, "value") else str(self.finding.severity)

    @property
    def severity_score(self) -> float:
        if hasattr(self.finding.severity, "score"):
            return self.finding.severity.score
        return 0.0

    @property
    def confidence(self) -> float:
        return self.finding.confidence

    @property
    def rule_id(self) -> str:
        return self.finding.rule_id or "N/A"

    @property
    def rule_name(self) -> str:
        return self.finding.rule_name or "N/A"

    @property
    def resource(self) -> str:
        res_type = self.finding.resource_type or ""
        res_name = self.finding.resource_name or ""
        if res_type and res_name:
            return f"{res_type} ({res_name})"
        return res_name or res_type or "Global"

    @property
    def file_path(self) -> str:
        if self.finding.location and self.finding.location.file_path:
            return self.finding.location.file_path
        return ""

    @property
    def line_info(self) -> str:
        if not self.finding.location:
            return "N/A"
        start = self.finding.location.start_line
        end = self.finding.location.end_line
        if start and end:
            return f"L{start}-{end}"
        if start:
            return f"L{start}"
        return "N/A"

    @property
    def code_snippet(self) -> str:
        if self.finding.location and self.finding.location.code_snippet:
            return self.finding.location.code_snippet
        return ""

    @property
    def validation_status(self) -> str:
        return self.finding.validation_status.value if hasattr(self.finding.validation_status, "value") else str(self.finding.validation_status)

    @property
    def is_confirmed(self) -> bool:
        return self.finding.validation_status == ValidationStatus.CONFIRMED

    @property
    def endpoint(self) -> str:
        if self.finding.api and self.finding.api.endpoint:
            return self.finding.api.endpoint
        return ""

    @property
    def method(self) -> str:
        if self.finding.api and self.finding.api.method:
            return self.finding.api.method.upper()
        return ""

    @property
    def requires_auth(self) -> bool:
        if self.finding.api and self.finding.api.requires_authentication is not None:
            return self.finding.api.requires_authentication
        return False

    @property
    def cwe(self) -> str:
        return self.finding.cwe_id or ""

    @property
    def cve(self) -> str:
        return self.finding.cve_id or ""

    @property
    def owasp_category(self) -> str:
        return self.finding.owasp_api_category or ""

    @property
    def remediation(self) -> str:
        return self.finding.remediation or "Nessuna mitigazione disponibile."

    @property
    def tags(self) -> List[str]:
        return self.finding.tags or []

    @property
    def detected_at(self) -> str:
        if isinstance(self.finding.detected_at, datetime):
            return self.finding.detected_at.strftime("%Y-%m-%d %H:%M:%S")
        return str(self.finding.detected_at)

    @property
    def risk_score(self) -> float:
        """
        Ritorna il risk score normalizzato memorizzato in raw_data, oppure calcolato.
        """
        if self.finding.raw_data and "correlated_risk_score" in self.finding.raw_data:
            try:
                return float(self.finding.raw_data["correlated_risk_score"])
            except ValueError:
                pass
        # Fallback calcolato
        score = self.severity_score * self.confidence
        if self.is_confirmed:
            score = min(10.0, score * 1.5)
        return round(score, 1)

    @property
    def evidence_details(self) -> Dict[str, Any]:
        """
        Ritorna dettagli relativi alle prove empiriche raccolte a runtime.
        """
        details = {}
        re = self.finding.runtime_evidence
        if re:
            if re.tested_url:
                details["URL Testato"] = re.tested_url
            if re.http_status is not None:
                details["Stato HTTP"] = str(re.http_status)
            if re.response_time_ms is not None:
                details["Latenza"] = f"{re.response_time_ms} ms"
            if re.accessible_without_auth is not None:
                details["Accessibile Senza Autenticazione"] = "Sì" if re.accessible_without_auth else "No"
            if re.rate_limit_detected is not None:
                details["Rate Limit Rilevato"] = "Sì" if re.rate_limit_detected else "No"
            if re.response_snippet:
                details["Risposta (Snippet)"] = re.response_snippet
            if re.response_headers:
                details["Headers Risposta"] = str(re.response_headers)
        return details
