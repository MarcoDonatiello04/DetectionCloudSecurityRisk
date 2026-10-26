"""
Entry point del rilevatore statico API1:2023 (Broken Object Level Authorization).

Esegue il Layer 1 (AST degli handler) e, se è disponibile un contratto, il Layer 3
(OpenAPI); deduplica per endpoint e metodo secondo la priorità delle regole e restituisce
un ``ObjectAuthzReport``. Ogni finding porta la chiave ``api:METODO:path`` condivisa con il
validatore runtime BOLA: ``to_domain_findings`` li converte nel ``Finding`` di dominio, così
il Correlation Engine può elevare l'ipotesi statica quando l'attacco dinamico la conferma.

Il livello statico copre la componente strutturale di BOLA (manca un legame tra oggetto e
chiamante); la correttezza semantica di un legame presente resta verificabile solo a
runtime (vedi ``docs/owasp_api1_coverage.md``).
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

import yaml

from src.core.api1_bola.layers.layer1_ast import analyze_ast_with_handlers
from src.core.api1_bola.layers.layer3_openapi import SECURITY_DECLARED, analyze_openapi
from src.core.api1_bola.models import (
    ObjectAuthzFinding,
    ObjectAuthzReport,
    RouteHandler,
    RuleID,
)
from src.domain.entities import (
    APIContext,
    CodeLocation,
    Finding,
    FindingCategory,
    FindingNature,
    FindingSource,
    Severity,
)

# A parità di endpoint e metodo vince la regola con il segnale più specifico.
RULE_PRIORITY = {
    RuleID.OA_003.value: 4,  # incoerenza tra metodi: l'ownership era un requisito noto
    RuleID.OA_004.value: 3,
    RuleID.OA_001.value: 2,
    RuleID.OA_002.value: 1,
}

# Misura una dimensione distinta (predicibilità dell'ID): si affianca al vincitore.
NON_EXCLUSIVE_RULES = {RuleID.OA_005.value}


def deduplicate_findings(findings: list[ObjectAuthzFinding]) -> list[ObjectAuthzFinding]:
    """
    Per ogni handler (file + chiave di correlazione, cioè metodo + path normalizzato) tiene
    il finding con la regola a priorità più alta; le regole assorbite restano in
    ``related_rules``. Il file entra nella chiave perché due servizi della stessa repo
    possono esporre lo stesso path: sono implementazioni distinte, non duplicati.
    """
    non_exclusive = [f for f in findings if f.rule_id in NON_EXCLUSIVE_RULES]
    winners: dict[tuple[str, str], ObjectAuthzFinding] = {}
    for finding in findings:
        if finding.rule_id in NON_EXCLUSIVE_RULES:
            continue
        key = (finding.file_path, finding.correlation_key or str(finding.line_number))
        current = winners.get(key)
        if current is None:
            winners[key] = finding
            continue
        if RULE_PRIORITY.get(finding.rule_id, 0) > RULE_PRIORITY.get(current.rule_id, 0):
            finding.related_rules = sorted(
                (set(current.related_rules) | {current.rule_id}) - {finding.rule_id}
            )
            winners[key] = finding
        elif finding.rule_id != current.rule_id:
            current.related_rules = sorted(set(current.related_rules) | {finding.rule_id})
    return list(winners.values()) + non_exclusive


def _build_coverage_signals(findings: list[ObjectAuthzFinding]) -> dict[str, list[str]]:
    signals: dict[str, list[str]] = {}
    for f in findings:
        signals.setdefault(f.category, [])
        if f.rule_id not in signals[f.category]:
            signals[f.category].append(f.rule_id)
    return signals


def _build_summary(
    findings: list[ObjectAuthzFinding], handlers: list[RouteHandler]
) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        "rule": {},
        "layer": {"ast": 0, "ast+openapi": 0},
        "contract_status": {},
        "handlers": {
            "total": len(handlers),
            "with_object_id": sum(1 for h in handlers if h.id_params),
            "with_object_access": sum(1 for h in handlers if h.object_accesses),
            "with_ownership_check": sum(1 for h in handlers if h.ownership_checks),
        },
    }
    for f in findings:
        summary["severity"][f.severity] = summary["severity"].get(f.severity, 0) + 1
        summary["rule"][f.rule_id] = summary["rule"].get(f.rule_id, 0) + 1
        summary["layer"][f.layer] = summary["layer"].get(f.layer, 0) + 1
        if f.contract_status:
            status = summary["contract_status"]
            status[f.contract_status] = status.get(f.contract_status, 0) + 1
    # Operazioni che Spectral considera protette (security dichiarato) ma il codice no
    summary["spectral_blind_spot"] = summary["contract_status"].get(SECURITY_DECLARED, 0)
    return summary


def load_spec(spec_path: str | Path) -> dict[str, Any] | None:
    """Carica un contratto OpenAPI YAML/JSON; None se assente o illeggibile."""
    path = Path(spec_path)
    if not path.is_file():
        return None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return None
    return data if isinstance(data, dict) else None


def analyze(
    target_path: str,
    openapi_spec: dict[str, Any] | None = None,
    enrich_spec: bool = False,
) -> ObjectAuthzReport:
    """
    Entry point del modulo statico API1:2023 Broken Object Level Authorization.

    Args:
        target_path: Radice (o singolo file) del codice da analizzare.
        openapi_spec: Specifica OpenAPI già caricata; se None il Layer 3 viene saltato.
        enrich_spec: Se True e la spec è fornita, aggiunge ``x-security-analysis``
            alle operazioni coinvolte (in-place).

    Returns:
        ObjectAuthzReport con i finding deduplicati di tutti i layer.
    """
    findings, handlers = analyze_ast_with_handlers(target_path)
    if openapi_spec is not None:
        findings = analyze_openapi(openapi_spec, findings, handlers, enrich_spec=enrich_spec)
    findings = deduplicate_findings(findings)
    return ObjectAuthzReport(
        target_path=target_path,
        findings=findings,
        coverage_signals=_build_coverage_signals(findings),
        summary=_build_summary(findings, handlers),
        handlers_analyzed=len(handlers),
    )


def analyze_content(content: str, filename: str = "app.py") -> ObjectAuthzReport:
    """Analizza un sorgente inline (helper per i test)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / filename).write_text(content, encoding="utf-8")
        return analyze(tmpdir)


_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def to_domain_findings(report: ObjectAuthzReport) -> list[Finding]:
    """
    Converte i finding API1 nel modello di dominio unificato.

    La ``correlation_key`` è la stessa del validatore runtime BOLA, quindi il
    ``RiskCorrelationEngine`` unisce l'ipotesi statica con la conferma dinamica.
    """
    result: list[Finding] = []
    root = Path(report.target_path)
    base = root.parent if root.is_file() else root
    for f in report.findings:
        method = (f.http_methods or ["GET"])[0]
        # Path relativo al target: l'ID resta stabile tra macchine e cartelle temporanee
        try:
            rel_path = Path(f.file_path).resolve().relative_to(base.resolve()).as_posix()
        except ValueError:
            rel_path = f.file_path
        result.append(
            Finding.create(
                source=FindingSource.STATIC_ANALYZER,
                category=FindingCategory.AUTHORIZATION,
                title=f"[API1 {f.rule_id}] {f.category} su {method} {f.endpoint}",
                description=f"{f.missing_guard}.",
                severity=_SEVERITY.get(f.severity, Severity.MEDIUM),
                confidence=f.confidence,
                rule_id=f.rule_id,
                target_identifier=f"{rel_path}|{method}|{f.endpoint}|{f.id_parameter}",
                rule_name=f.category,
                location=CodeLocation(
                    file_path=f.file_path, start_line=f.line_number, code_snippet=f.evidence
                ),
                api=APIContext(endpoint=f.endpoint, method=method),
                correlation_key=f.correlation_key,
                owasp_api_category="API1:2023",
                cwe_id=f.cwe_id,
                nature=FindingNature.EXPOSURE,
                tags=["api1", "bola", f"layer:{f.layer}"],
                raw_data={
                    "id_parameter": f.id_parameter,
                    "found_guard": f.found_guard,
                    "layer": f.layer,
                    "contract_status": f.contract_status,
                    "related_rules": f.related_rules,
                },
            )
        )
    return result
