import sys
import os

# Aggiungiamo la root del progetto al PYTHONPATH per permettere l'importazione dei moduli src.*
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.scanners.checkov_runner import run_checkov
from src.scanners.semgrep_runner import run_semgrep
from src.scanners.spectral_runner import run_spectral
from src.detectors.shadow_api_hunter import run_shadow_api_hunter
from src.scanners.zap_runner import ZAPRunner
from src.enrichers.runtime_enricher import RuntimeEnricher
from src.utils.report_builder import consolidate_reports

def main():
    target_dir = "."
    if len(sys.argv) > 1:
        target_dir = sys.argv[1]

    print(f"🎯 Target della scansione: {target_dir}")

    # Fase 1: Scansione Statica Multi-Layer
    checkov_data = run_checkov(target_dir)
    spectral_data = run_spectral(target_dir)
    semgrep_data = run_semgrep(target_dir)
    shadow_apis = run_shadow_api_hunter(target_dir)
    
    all_static_findings = spectral_data + checkov_data + semgrep_data + shadow_apis

    # Fase 2: Discovery dei Target (Estrazione rotte e percorsi)
    target_urls = []
    base_host = "http://localhost:5000"  # Target applicativo live standard
    
    for f in all_static_findings:
        if f.api and f.api.endpoint:
            # Assicuriamo che sia un URL assoluto per ZAP
            url = f.api.endpoint
            if not url.startswith("http"):
                url = f"{base_host}{url}"
                # Aggiorniamo anche l'endpoint/correlation_key per favorire l'enrichment
                f.api.endpoint = url
                if f.correlation_key == f.api.endpoint.replace(base_host, ""):
                    f.correlation_key = url
            if url not in target_urls:
                target_urls.append(url)

    # Fase 3: Esecuzione DAST Mirata (OWASP ZAP)
    zap = ZAPRunner()
    zap_alerts = zap.scan_targets(target_urls)

    # Fase 4: Arricchimento Runtime (Senza duplicare finding)
    enricher = RuntimeEnricher()
    enricher.enrich_findings(all_static_findings, zap_alerts)

    # Fase 5: Correlazione Finale e Output
    consolidate_reports(spectral_data, checkov_data, semgrep_data, shadow_apis)

if __name__ == "__main__":
    main()
