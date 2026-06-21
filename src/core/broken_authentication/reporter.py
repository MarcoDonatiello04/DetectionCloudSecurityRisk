"""
Broken Authentication - Reporter Module (Fase 5).
Serializes scan results into JSON and Markdown reports.
"""

import json
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel
from loguru import logger

from src.core.broken_authentication.discovery import StackInfo, Config
from src.core.broken_authentication.authentication_intelligence import AuthenticationKnowledgeGraph

# --- Pydantic Models for final report ---
class VulnerabilitaStatica(BaseModel):
    file: str
    riga: int
    vulnerabilita: str
    severita: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    cwe: str
    raccomandazione: str

class RisultatoTestDinamico(BaseModel):
    test_id: str
    test_nome: str
    risultato: str  # "PASS" | "FAIL" | "SKIP"
    dettaglio: str
    raccomandazione: str

class ReportFinale(BaseModel):
    timestamp: str
    repository: str
    stack: StackInfo
    vulnerabilita_statiche: List[VulnerabilitaStatica]
    test_dinamici: List[RisultatoTestDinamico]
    auth_intel: Optional[AuthenticationKnowledgeGraph] = None
    request_audit_log: List[dict] = []
    auth_strategy: Optional[str] = None


def generate_markdown(report: ReportFinale) -> str:
    """Generates the Markdown representation of the final report."""
    # Calculate summary metrics dynamically
    static_vulns = report.vulnerabilita_statiche
    dynamic_tests = report.test_dinamici
    
    crit_count = sum(1 for v in static_vulns if v.severita.upper() == "CRITICAL")
    high_count = sum(1 for v in static_vulns if v.severita.upper() == "HIGH")
    med_count = sum(1 for v in static_vulns if v.severita.upper() == "MEDIUM")
    low_count = sum(1 for v in static_vulns if v.severita.upper() == "LOW")
    
    pass_count = sum(1 for t in dynamic_tests if t.risultato.upper() == "PASS")
    fail_count = sum(1 for t in dynamic_tests if t.risultato.upper() == "FAIL")
    skip_count = sum(1 for t in dynamic_tests if t.risultato.upper() in ("SKIP", "SKIPPED"))
    inconclusive_count = sum(1 for t in dynamic_tests if t.risultato.upper() == "INCONCLUSIVE")
    
    librerie = ", ".join(report.stack.librerie_auth) if report.stack.librerie_auth else "Nessuna"
    idp = report.stack.identity_provider if report.stack.identity_provider else "Nessuno"
    
    # Discovery methods
    methods = report.stack.discovery_methods or {}
    lang_method = methods.get("linguaggio", "unknown")
    fw_method = methods.get("framework", "unknown")
    lib_method = methods.get("librerie_auth", "unknown")
    idp_method = methods.get("identity_provider", "unknown")
    
    md = []
    md.append("# Broken Authentication Report")
    md.append(f"Data: {report.timestamp}")
    md.append(f"Repository: {report.repository}\n")
    
    md.append("## Stack Identificato")
    md.append(f"- Linguaggio: {report.stack.linguaggio} (Discovery: {lang_method})")
    md.append(f"- Framework: {report.stack.framework} (Discovery: {fw_method})")
    md.append(f"- Librerie Auth: {librerie} (Discovery: {lib_method})")
    md.append(f"- Identity Provider: {idp} (Discovery: {idp_method})")
    if getattr(report, "auth_strategy", None):
        md.append(f"- Strategia di Login: {report.auth_strategy}")
    md.append("")
    
    md.append("## Sommario")
    md.append(f"- Vulnerabilità CRITICAL: {crit_count}")
    md.append(f"- Vulnerabilità HIGH: {high_count}")
    md.append(f"- Vulnerabilità MEDIUM: {med_count}")
    md.append(f"- Vulnerabilità LOW: {low_count}")
    md.append(f"- Test PASS: {pass_count}")
    md.append(f"- Test FAIL: {fail_count}")
    md.append(f"- Test SKIPPED: {skip_count}")
    md.append(f"- Test INCONCLUSIVE: {inconclusive_count}\n")
    
    if report.auth_intel:
        intel = report.auth_intel
        md.append("## Authentication Intelligence")
        md.append(f"- Tipo Autenticazione: {intel.authentication_type or 'Non rilevato'}")
        md.append(f"- Identity Provider: {intel.identity_provider or 'Non rilevato'}")
        md.append(f"- Login Endpoint: {intel.login_endpoint or 'Non rilevato'}")
        md.append(f"- Logout Endpoint: {intel.logout_endpoint or 'Non rilevato'}")
        md.append(f"- Refresh Endpoint: {intel.refresh_endpoint or 'Non rilevato'}")
        md.append(f"- JWT Claims: {', '.join(intel.jwt_claims) if intel.jwt_claims else 'Nessuno'}")
        md.append(f"- Ruoli Rilevati: {', '.join(intel.roles) if intel.roles else 'Nessuno'}")
        md.append(f"- Permessi Rilevati: {', '.join(intel.permissions) if intel.permissions else 'Nessuno'}")
        md.append(f"- Middleware Rilevati: {', '.join(intel.auth_middlewares) if intel.auth_middlewares else 'Nessuno'}")
        md.append(f"- Funzioni Auth: {', '.join(intel.auth_functions) if intel.auth_functions else 'Nessuno'}")
        md.append(f"- Score di Confidenza: {intel.confidence_score:.2f}")
        md.append(f"- Validazione JWKS: {'Attiva' if intel.jwks_validation_enabled else 'Disattivata/Non rilevata'}")
        md.append(f"- Rotazione Refresh Token: {'Attiva' if intel.refresh_token_rotation else 'Non rilevata'}")
        md.append(f"- Autenticazioni Non-JWT: {', '.join(intel.non_jwt_mechanisms) if intel.non_jwt_mechanisms else 'Nessuno'}")
        md.append(f"- SAML Rilevato: {'Sì' if intel.saml_detected else 'No'}")
        if intel.saml_detected:
            md.append(f"  - Entity ID: {intel.idp_metadata.get('entity_id', 'Nessuno')}")
            md.append(f"  - ACS URL: {intel.idp_metadata.get('acs_url', 'Nessuno')}")
            md.append(f"  - Certificati trovati: {intel.idp_metadata.get('certificates_found', 0)}")
        
        oidc_meta = []
        if intel.oauth_flows_metadata:
            for k, v in intel.oauth_flows_metadata.items():
                oidc_meta.append(f"{k}: {'Sì' if v else 'No'}")
        md.append(f"- OAuth2/OIDC Flow Details: {', '.join(oidc_meta) if oidc_meta else 'Nessuno'}")
        
        if intel.protected_endpoints:
            md.append("\n### Endpoint Protetti")
            for endpoint, detail in intel.protected_endpoints.items():
                roles_str = ", ".join(detail.get("required_roles", [])) if detail.get("required_roles") else "Nessuno"
                md.append(f"- `{endpoint}`: Ruoli richiesti = [{roles_str}] (Sorgente: {detail.get('source')})")
        md.append("")

    md.append("## Vulnerabilità Statiche")
    if not static_vulns:
        md.append("Nessuna vulnerabilità statica rilevata.\n")
    else:
        for v in static_vulns:
            md.append(f"### {v.severita} - {v.cwe}")
            md.append(f"- File: {v.file} (riga {v.riga})")
            md.append(f"- Descrizione: {v.vulnerabilita}")
            md.append(f"- Raccomandazione: {v.raccomandazione}\n")
            
    md.append("## Risultati Test Dinamici")
    if not dynamic_tests:
        md.append("Nessun test dinamico eseguito.\n")
    else:
        for t in dynamic_tests:
            status_text = t.risultato
            if "basso confidence" in t.dettaglio.lower():
                status_text = "SKIPPED (Basso Confidence Score)"
            md.append(f"### {t.test_id} - {t.test_nome}: {status_text}")
            md.append(f"- Dettaglio: {t.dettaglio}")
            md.append(f"- Raccomandazione: {t.raccomandazione}\n")
            
    if report.request_audit_log:
        md.append("## Audit Log Richieste")
        for i, req in enumerate(report.request_audit_log, 1):
            md.append(f"{i}. **{req.get('method')}** `{req.get('url')}`")
        md.append("")

    return "\n".join(md)


async def run(report: ReportFinale, config: Config) -> None:
    """
    Main entry point for Fase 5: Reporter.
    Serializes report into JSON and/or Markdown based on config formatting.
    """
    output_dir = Path(config.output.path)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Clean timestamp for filename: replace chars that are not filesystem-friendly
    safe_ts = report.timestamp.replace(":", "-").replace(" ", "_")
    
    formato = config.output.formato.lower().strip()
    
    if formato in ("json", "both"):
        json_path = output_dir / f"report_{safe_ts}.json"
        try:
            # Pydantic v2 dict/model_dump serialization
            data = report.model_dump()
        except AttributeError:
            # Pydantic v1 fallback dict
            data = report.dict()
            
        json_content = json.dumps(data, indent=2, ensure_ascii=False)
        json_path.write_text(json_content, encoding="utf-8")
        logger.info(f"Report JSON generato con successo in: {json_path}")
        
    if formato in ("markdown", "both"):
        md_path = output_dir / f"report_{safe_ts}.md"
        md_content = generate_markdown(report)
        md_path.write_text(md_content, encoding="utf-8")
        logger.info(f"Report Markdown generato con successo in: {md_path}")
