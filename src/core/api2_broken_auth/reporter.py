"""
Broken Authentication - Reporter Module (Fase 5).
Serializes scan results into JSON and Markdown reports.
"""

import json
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import BaseModel

from src.core.api2_broken_auth.authentication_intelligence import AuthenticationKnowledgeGraph
from src.core.api2_broken_auth.discovery import Config, StackInfo, VulnerabilityCategory


# --- Pydantic Models for final report ---
class VulnerabilitaStatica(BaseModel):
    file: str
    riga: int
    vulnerabilita: str
    severita: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    cwe: str
    raccomandazione: str
    category: VulnerabilityCategory | None = None


class RisultatoTestDinamico(BaseModel):
    test_id: str
    test_nome: str
    risultato: str  # "PASS" | "FAIL" | "SKIP"
    dettaglio: str
    raccomandazione: str
    category: VulnerabilityCategory | None = None
    dettagli_quantitativi: dict[str, Any] | None = None


class ReportFinale(BaseModel):
    timestamp: str
    repository: str
    stack: StackInfo
    vulnerabilita_statiche: list[VulnerabilitaStatica]
    test_dinamici: list[RisultatoTestDinamico]
    auth_intel: AuthenticationKnowledgeGraph | None = None
    request_audit_log: list[dict] = []
    auth_strategy: str | None = None


def generate_markdown(report: ReportFinale) -> str:
    """Generates the Markdown representation of the final report."""
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

    TEST_CATEGORY_MAP = {
        "T01": "Authentication",
        "T02": "Authentication",
        "T03": "Authentication",
        "T04": "Authorization",
        "T05": "Authentication",
        "T06": "Authentication",
        "T07": "Authentication",
        "T08": "Authorization",
        "T09": "Security Misconfiguration",
        "T10": "Information Disclosure",
        "T11": "Authentication",
        "T12": "Authentication",
        "T13": "Authentication",
        "T14": "Authentication",
        "T15": "Authentication",
        "T16": "Authentication",
        "T17": "Authentication",
        "T18": "Authentication",
        "T19": "Authentication",
        "T20": "Authentication",
        "T21": "Authentication",
        "T22": "Authentication",
    }

    def _get_static_category(v: VulnerabilitaStatica) -> str:
        if v.category:
            return v.category.value if hasattr(v.category, "value") else str(v.category)
        desc = v.vulnerabilita.lower()
        cwe = v.cwe.lower()
        if any(
            k in desc or k in cwe
            for k in [
                "role",
                "privilege",
                "authorization",
                "scope",
                "audience",
                "cwe-285",
                "cwe-269",
            ]
        ):
            return "Authorization"
        if any(
            k in desc or k in cwe for k in ["httponly", "secure", "samesite", "cookie", "cwe-16"]
        ):
            return "Security Misconfiguration"
        if any(
            k in desc or k in cwe
            for k in ["stacktrace", "leak", "disclosure", "error", "cwe-200", "cwe-209"]
        ):
            return "Information Disclosure"
        return "Authentication"

    def _get_dynamic_category(t: RisultatoTestDinamico) -> str:
        if t.category:
            return t.category.value if hasattr(t.category, "value") else str(t.category)
        return TEST_CATEGORY_MAP.get(t.test_id, "Authentication")

    # Determine Resilience Score
    score_data = None
    if report.auth_intel and report.auth_intel.authentication_score:
        score_data = report.auth_intel.authentication_score
    else:
        score = 100
        deductions = {
            "T01": 15,
            "T02": 10,
            "T03": 10,
            "T05": 10,
            "T06": 10,
            "T07": 10,
            "T08": 10,
            "T09": 10,
            "T12": 10,
            "T13": 10,
            "T14": 5,
            "T15": 5,
            "T17": 10,
            "T20": 5,
            "T21": 10,
        }
        for t in dynamic_tests:
            if t.risultato.upper() == "FAIL" and t.test_id in deductions:
                score -= deductions[t.test_id]
        if report.auth_intel and not report.auth_intel.mfa_detected:
            score -= 10
        score = max(0, min(100, score))
        if score >= 90:
            grade, risk = "A", "Low"
        elif score >= 80:
            grade, risk = "B", "Medium"
        elif score >= 70:
            grade, risk = "C", "Medium"
        elif score >= 60:
            grade, risk = "D", "High"
        else:
            grade, risk = "F", "Critical"
        score_data = {"score": score, "grade": grade, "risk": risk}

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

    # Authentication Resilience Score section
    md.append("## Authentication Resilience Score")
    md.append(f"- **Punteggio**: {score_data.get('score')}/100")
    md.append(f"- **Classe**: {score_data.get('grade')}")
    md.append(f"- **Livello di Rischio**: {score_data.get('risk')}\n")

    md.append("## Sommario")
    md.append(f"- Vulnerabilità CRITICAL: {crit_count}")
    md.append(f"- Vulnerabilità HIGH: {high_count}")
    md.append(f"- Vulnerabilità MEDIUM: {med_count}")
    md.append(f"- Vulnerabilità LOW: {low_count}")
    md.append(f"- Test PASS: {pass_count}")
    md.append(f"- Test FAIL: {fail_count}")
    md.append(f"- Test SKIPPED: {skip_count}")
    md.append(f"- Test INCONCLUSIVE: {inconclusive_count}\n")

    # Final summary table
    md.append("### Sintesi dei Test Dinamici")
    md.append("| Test | Status | Severity | Category |")
    md.append("| ---- | ------ | -------- | -------- |")
    for t in dynamic_tests:
        sev = "HIGH"
        if t.test_id in ("T01", "T06", "T07", "T17", "T21"):
            sev = "CRITICAL"
        elif t.test_id in ("T09", "T11", "T14", "T19"):
            sev = "MEDIUM"
        elif t.test_id in ("T02", "T10"):
            sev = "INFO"
        cat = _get_dynamic_category(t)
        md.append(f"| {t.test_id} - {t.test_nome} | {t.risultato} | {sev} | {cat} |")
    md.append("")

    # MFA Summary
    mfa_det = "Non rilevato"
    mfa_type = "N/D"
    mfa_conf = "0.0"
    if report.auth_intel:
        if report.auth_intel.mfa_detected is True:
            mfa_det = "Sì"
        elif report.auth_intel.mfa_detected is False:
            mfa_det = "No"
        mfa_type = report.auth_intel.mfa_type or "N/D"
        mfa_conf = f"{report.auth_intel.mfa_confidence:.2f}"

    md.append("## MFA Summary")
    md.append(f"- **MFA Rilevato**: {mfa_det}")
    md.append(f"- **Tipo MFA**: {mfa_type}")
    md.append(f"- **Confidenza Rilevamento**: {mfa_conf}\n")

    # Refresh Token Summary
    rt_supported = "No"
    rt_rotation = "Inattiva/Non rilevata"
    rt_lifetime = "Non rilevata"
    rt_reuse = "Non rilevata"
    rt_parallel = "Non rilevata"

    if report.auth_intel and report.auth_intel.refresh_token_supported:
        rt_supported = "Sì"

    for t in dynamic_tests:
        if t.test_id == "T12":
            rt_reuse = (
                "Vulnerabile (Riutilizzo consentito)"
                if t.risultato.upper() == "FAIL"
                else "Sicuro (Riutilizzo bloccato)"
                if t.risultato.upper() == "PASS"
                else "Non determinato"
            )
        elif t.test_id == "T13":
            rt_rotation = (
                "Attiva (Vecchio token invalidato)"
                if t.risultato.upper() == "PASS"
                else "Inattiva (Rotazione fallita/mancante)"
                if t.risultato.upper() == "FAIL"
                else "Non determinato"
            )
        elif t.test_id == "T14":
            rt_lifetime = (
                "Vulnerabile (Scadenza infinita o >30 giorni)"
                if t.risultato.upper() == "FAIL"
                else "Sicuro (Scadenza definita e corretta)"
                if t.risultato.upper() == "PASS"
                else "Non determinato"
            )
        elif t.test_id == "T15":
            rt_parallel = (
                "Vulnerabile (Race condition presente)"
                if t.risultato.upper() == "FAIL"
                else "Sicuro (Richieste parallele gestite)"
                if t.risultato.upper() == "PASS"
                else "Non determinato"
            )

    md.append("## Refresh Token Security Summary")
    md.append(f"- **Refresh Token Supportati**: {rt_supported}")
    md.append(f"- **Rotazione Refresh Token**: {rt_rotation}")
    md.append(f"- **Configurazione Lifetime**: {rt_lifetime}")
    md.append(f"- **Protezione da Riuso**: {rt_reuse}")
    md.append(f"- **Abuso Richieste Parallele**: {rt_parallel}\n")

    # Rate Limiting Summary
    rl_detected = "No"
    attempts_before_block = "N/D"
    block_duration = "N/D"
    ip_spoof_bypass = "N/D"

    if report.auth_intel and report.auth_intel.rate_limiting_detected:
        rl_detected = "Sì"
        if report.auth_intel.rate_limit_threshold:
            attempts_before_block = str(report.auth_intel.rate_limit_threshold)

    for t in dynamic_tests:
        if t.test_id == "T03" and t.dettagli_quantitativi:
            rl_detected = "Sì"
            attempts_before_block = str(
                t.dettagli_quantitativi.get("attempts_before_block", attempts_before_block)
            )
            block_duration = f"{t.dettagli_quantitativi.get('block_duration_seconds', 0)}s"
            ip_spoof_bypass = (
                "Sì (Vulnerabile)"
                if t.dettagli_quantitativi.get("ip_spoof_bypass")
                else "No (Protetto)"
            )

    md.append("## Rate Limiting Analysis")
    md.append(f"- **Rate Limiting Rilevato**: {rl_detected}")
    md.append(f"- **Richieste prima del Blocco**: {attempts_before_block}")
    md.append(f"- **Durata del Blocco**: {block_duration}")
    md.append(f"- **Bypass via IP Spoofing**: {ip_spoof_bypass}\n")

    if report.auth_intel:
        intel = report.auth_intel
        md.append("## Authentication Intelligence Details")
        md.append(f"- Tipo Autenticazione: {intel.authentication_type or 'Non rilevato'}")
        md.append(f"- Identity Provider: {intel.identity_provider or 'Non rilevato'}")
        md.append(f"- Login Endpoint: {intel.login_endpoint or 'Non rilevato'}")
        md.append(f"- Logout Endpoint: {intel.logout_endpoint or 'Non rilevato'}")
        md.append(f"- Refresh Endpoint: {intel.refresh_endpoint or 'Non rilevato'}")
        md.append(f"- JWT Claims: {', '.join(intel.jwt_claims) if intel.jwt_claims else 'Nessuno'}")
        md.append(f"- Ruoli Rilevati: {', '.join(intel.roles) if intel.roles else 'Nessuno'}")
        md.append(
            f"- Permessi Rilevati: {', '.join(intel.permissions) if intel.permissions else 'Nessuno'}"
        )
        md.append(
            f"- Middleware Rilevati: {', '.join(intel.auth_middlewares) if intel.auth_middlewares else 'Nessuno'}"
        )
        md.append(
            f"- Funzioni Auth: {', '.join(intel.auth_functions) if intel.auth_functions else 'Nessuno'}"
        )
        md.append(f"- Score di Confidenza: {intel.confidence_score:.2f}")
        md.append(
            f"- Validazione JWKS: {'Attiva' if intel.jwks_validation_enabled else 'Disattivata/Non rilevata'}"
        )
        md.append(
            f"- Rotazione Refresh Token: {'Attiva' if intel.refresh_token_rotation else 'Non rilevata'}"
        )
        md.append(
            f"- Autenticazioni Non-JWT: {', '.join(intel.non_jwt_mechanisms) if intel.non_jwt_mechanisms else 'Nessuno'}"
        )
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
                roles_str = (
                    ", ".join(detail.get("required_roles", []))
                    if detail.get("required_roles")
                    else "Nessuno"
                )
                md.append(
                    f"- `{endpoint}`: Ruoli richiesti = [{roles_str}] (Sorgente: {detail.get('source')})"
                )
        md.append("")

    # Map categories to lists of findings
    categories = {
        "Authentication": {"static": [], "dynamic": []},
        "Authorization": {"static": [], "dynamic": []},
        "Security Misconfiguration": {"static": [], "dynamic": []},
        "Information Disclosure": {"static": [], "dynamic": []},
    }

    for v in static_vulns:
        cat = _get_static_category(v)
        if cat in categories:
            categories[cat]["static"].append(v)

    for t in dynamic_tests:
        cat = _get_dynamic_category(t)
        if cat in categories:
            categories[cat]["dynamic"].append(t)

    # Output categorized findings
    for cat_name, findings in categories.items():
        md.append(f"## {cat_name} Findings")
        if not findings["static"] and not findings["dynamic"]:
            md.append(f"Nessun finding rilevato per la categoria {cat_name}.\n")
            continue

        if findings["static"]:
            md.append("### Analisi Statica")
            for v in findings["static"]:
                md.append(f"#### {v.severita} - {v.cwe}")
                md.append(f"- File: {v.file} (riga {v.riga})")
                md.append(f"- Descrizione: {v.vulnerabilita}")
                md.append(f"- Raccomandazione: {v.raccomandazione}\n")

        if findings["dynamic"]:
            md.append("### Test Dinamici")
            for t in findings["dynamic"]:
                md.append(f"#### {t.test_id} - {t.test_nome}: {t.risultato}")
                md.append(f"- Dettaglio: {t.dettaglio}")
                md.append(
                    f"- Raccomandazione: {t.raccomandazione or 'Verificare la configurazione di sicurezza.'}\n"
                )

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
