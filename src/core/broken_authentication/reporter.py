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
    skip_count = sum(1 for t in dynamic_tests if t.risultato.upper() == "SKIP")
    
    librerie = ", ".join(report.stack.librerie_auth) if report.stack.librerie_auth else "Nessuna"
    idp = report.stack.identity_provider if report.stack.identity_provider else "Nessuno"
    
    md = []
    md.append("# Broken Authentication Report")
    md.append(f"Data: {report.timestamp}")
    md.append(f"Repository: {report.repository}\n")
    
    md.append("## Stack Identificato")
    md.append(f"- Linguaggio: {report.stack.linguaggio}")
    md.append(f"- Framework: {report.stack.framework}")
    md.append(f"- Librerie Auth: {librerie}")
    md.append(f"- Identity Provider: {idp}\n")
    
    md.append("## Sommario")
    md.append(f"- Vulnerabilità CRITICAL: {crit_count}")
    md.append(f"- Vulnerabilità HIGH: {high_count}")
    md.append(f"- Vulnerabilità MEDIUM: {med_count}")
    md.append(f"- Vulnerabilità LOW: {low_count}")
    md.append(f"- Test PASS: {pass_count}")
    md.append(f"- Test FAIL: {fail_count}")
    md.append(f"- Test SKIP: {skip_count}\n")
    
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
            md.append(f"### {t.test_id} - {t.test_nome}: {t.risultato}")
            md.append(f"- Dettaglio: {t.dettaglio}")
            md.append(f"- Raccomandazione: {t.raccomandazione}\n")
            
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
