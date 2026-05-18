import sys
from typing import List
from src.models.finding import Finding, FindingSource
from src.correlation_engine.engine import CorrelationEngine, CorrelatedRisk

def consolidate_reports(spectral_findings: List[Finding], checkov_findings: List[Finding], semgrep_findings: List[Finding], shadow_api_findings: List[Finding], bola_findings: List[Finding] = None):
    print("\n" + "="*80)
    print("📊 REPORT GLOBALE MULTI-LAYER CORRELATO (CORRELATION ENGINE)")
    print("="*80)
    
    if bola_findings is None:
        bola_findings = []
        
    all_findings = spectral_findings + checkov_findings + semgrep_findings + shadow_api_findings + bola_findings
    
    # Inizializziamo ed eseguiamo la correlazione
    engine = CorrelationEngine()
    engine.ingest(all_findings)
    correlated_risks = engine.correlate()
    
    total_findings = len(all_findings)
    total_risks = len(correlated_risks)
    
    print(f"🔄 Ingestione completata: {total_findings} Finding raw deduplicati e aggregati in {total_risks} Asset/Rischi Core.\n")
    
    if not correlated_risks:
        print("✅ Nessun rischio rilevato. Il sistema è sicuro!\n")
        print("="*80)
        return

    for idx, risk in enumerate(correlated_risks, 1):
        status_flag = "⚠️ ATTIVO"
        if risk.has_runtime_evidence and risk.is_exploitable:
            status_flag = "🔥 CONFERMATO A RUNTIME (ESPLORABILE)"
            
        print("-" * 80)
        print(f"ASSET/RISCHIO #{idx}: [{risk.highest_severity.value}] {risk.correlation_key} ({status_flag})")
        print("-" * 80)
        print(f"  Categoria Primaria: {risk.primary_category}")
        print(f"  Finding sottostanti correlati ({len(risk.findings)}):")
        
        for f in risk.findings:
            loc_str = ""
            if f.location and f.location.file_path:
                loc_str = f" ({f.location.file_path}:{f.location.start_line or 'N/A'})"
            elif f.resource_id:
                loc_str = f" ({f.resource_id})"
                
            owasp_tag = f" [{f.owasp_api_category}]" if f.owasp_api_category else ""
            print(f"    - [{f.severity.value}] {f.source.value}: {f.title}{owasp_tag}{loc_str}")
            if f.description and f.description != f.title:
                print(f"      ↳ {f.description}")
        print()

    print("="*80)
    print(f"❌ Trovati {total_risks} cluster di rischio unificati da {total_findings} finding grezzi.")
    sys.exit(1)
