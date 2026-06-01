import os
import argparse
import logging
from typing import List

from src.domain.entities import Finding
from src.application.orchestrator import ScanPipelineOrchestrator
from src.infrastructure.adapters.checkov_adapter import CheckovScannerAdapter
from src.infrastructure.adapters.semgrep_adapter import SemgrepScannerAdapter
from src.infrastructure.adapters.zap_adapter import ZapClientAdapter
from src.infrastructure.adapters.mitmproxy_adapter import MitmproxyClientAdapter
from src.infrastructure.persistence.report_repository import ReportRepository
from src.presentation.dashboard_generator import APIDashboardGenerator

# Configurazione logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("SecurityPlatform.CLI")


def parse_args():
    parser = argparse.ArgumentParser(description="Security Platform Core - Unified Scanner & Detector CLI")
    parser.add_argument(
        "--target-dir", 
        default=".", 
        help="Directory contenente il codice o infrastruttura da scansionare"
    )
    parser.add_argument(
        "--plugins-dir", 
        default="src/plugins", 
        help="Directory contenente i plugin dei detector"
    )
    parser.add_argument(
        "--output-dir", 
        default="output", 
        help="Directory dove salvare i report dei findings"
    )
    parser.add_argument(
        "--traffic-file", 
        default="soluzione_api/src/output/raw_traffic.json",
        help="File contenente il traffico catturato da mitmproxy"
    )
    parser.add_argument(
        "--zap-url", 
        default="http://localhost:8090", 
        help="URL del daemon OWASP ZAP per stimolazione e scansione DAST"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    
    logger.info("================================================================================")
    logger.info("🛡️  AVVIO SECURITY PLATFORM CORE - UNIFIED DISCOVERY PIPELINE")
    logger.info("================================================================================")
    logger.info(f"Target Directory:  {args.target_dir}")
    target_abs = os.path.abspath(args.target_dir)
    logger.info(f"Absolute Target Path: {target_abs}")

    # 1. Inizializza gli scanner core (adapters)
    scanners = [
        CheckovScannerAdapter(),
        SemgrepScannerAdapter()
    ]
    
    # 2. Inizializza l'orchestratore
    orchestrator = ScanPipelineOrchestrator(
        plugins_dir=args.plugins_dir,
        target_dir=args.target_dir
    )

    # 3. Carica il traffico a runtime (Mitmproxy adapter)
    # Se il file non esiste, proviamo a controllare se è presente nella cartella output locale
    traffic_path = args.traffic_file
    if not os.path.exists(traffic_path):
        traffic_path = "output/raw_traffic.json"
        
    mitm_adapter = MitmproxyClientAdapter(traffic_path)
    raw_traffic = mitm_adapter.load_captured_traffic()

    # Se non c'è traffico registrato (offline mode), simuliamo del traffico per permettere ai detector di girare
    if not raw_traffic:
        logger.info("⚠️ Nessun traffico Mitmproxy trovato. Generazione scenario simulato per dimostrazione...")
        raw_traffic = [
            # Richiesta valida con token
            {
                "method": "GET",
                "path": "/users/42",
                "full_url": "http://localhost:5000/users/42",
                "status": 200,
                "headers": {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjo0Mn0.signature"},
                "body_params": {}
            },
            # Richiesta Shadow API (non documentata)
            {
                "method": "POST",
                "path": "/api/v1/debug/dump-database",
                "full_url": "http://localhost:5000/api/v1/debug/dump-database",
                "status": 200,
                "headers": {},
                "body_params": {"raw_sql": "SELECT * FROM secrets"}
            }
        ]

    # 4. Esecuzione pipeline
    correlated_findings = orchestrator.run_pipeline(
        static_scanners=scanners,
        raw_traffic_data=raw_traffic
    )

    # 5. Persistenza dei risultati
    report_repo = ReportRepository(args.output_dir)
    report_repo.save_findings(correlated_findings, "unified_security_report.json")

    # Salviamo l'inventario delle API correlate in formato serializzato per consistenza
    api_inventory = []
    for f in correlated_findings:
        if f.api and f.api.endpoint:
            api_inventory.append(f.to_dict())
    report_repo.save_inventory(api_inventory, "unified_api_inventory.json")

    # 6. Generazione Dashboard interattiva
    dashboard_path = os.path.join(args.output_dir, "dashboard.html")
    dash_gen = APIDashboardGenerator(correlated_findings)
    dash_gen.generate(dashboard_path)

    logger.info("================================================================================")
    logger.info(f"🏆 PIPELINE COMPLETATA. Report salvato in '{args.output_dir}/'")
    logger.info(f"🖥️  Dashboard interattiva premium: {dashboard_path}")
    logger.info("================================================================================")


if __name__ == "__main__":
    main()
