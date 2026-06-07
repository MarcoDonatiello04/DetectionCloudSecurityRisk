import os
import argparse
import logging
from typing import List

from src.domain.entities import Finding
from src.application.orchestrator import ScanPipelineOrchestrator
from src.infrastructure.adapters.checkov_adapter import CheckovScannerAdapter
from src.infrastructure.adapters.semgrep_adapter import SemgrepScannerAdapter
from src.infrastructure.adapters.spectral_adapter import SpectralScannerAdapter
from src.infrastructure.adapters.zap_adapter import ZapClientAdapter
from src.infrastructure.adapters.mitmproxy_adapter import MitmproxyClientAdapter
from src.infrastructure.persistence.report_repository import ReportRepository
from src.presentation.dashboard_generator import APIDashboardGenerator
from src.core.bola.dynamic_orchestrator import DynamicOrchestrator


# Configurazione logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("SecurityPlatform.CLI")

# Configurazione costanti di default del CLI
DEFAULT_PLUGINS_DIR = "src/plugins"
DEFAULT_OUTPUT_DIR = "output"
DEFAULT_TRAFFIC_FILE = "soluzione_api/src/output/raw_traffic.json"
DEFAULT_FALLBACK_TRAFFIC_FILE = "output/raw_traffic.json"
DEFAULT_ZAP_URL = "http://localhost:8090"
DEFAULT_TARGET_BASE_URL = "http://localhost:5000"
DEFAULT_KEYCLOAK_URL = "http://localhost:8080"

DEFAULT_OPENAPI_SPEC_PATH = "problema_api/openapi.yaml"
REPORT_FINDINGS_FILENAME = "unified_security_report.json"
REPORT_INVENTORY_FILENAME = "unified_api_inventory.json"
DASHBOARD_FILENAME = "dashboard.html"


def parse_args() -> argparse.Namespace:
    """
    Effettua il parsing degli argomenti da riga di comando per il tool CLI.

    Returns:
        argparse.Namespace: Gli argomenti parsati.
    """
    parser = argparse.ArgumentParser(description="Security Platform Core - Unified Scanner & Detector CLI")
    parser.add_argument(
        "--target-dir", 
        default=".", 
        help="Directory contenente il codice o infrastruttura da scansionare"
    )
    parser.add_argument(
        "--plugins-dir", 
        default=DEFAULT_PLUGINS_DIR, 
        help="Directory contenente i plugin dei detector"
    )
    parser.add_argument(
        "--output-dir", 
        default=DEFAULT_OUTPUT_DIR, 
        help="Directory dove salvare i report dei findings"
    )
    parser.add_argument(
        "--traffic-file", 
        default=DEFAULT_TRAFFIC_FILE,
        help="File contenente il traffico catturato da mitmproxy"
    )
    parser.add_argument(
        "--zap-url", 
        default=DEFAULT_ZAP_URL, 
        help="URL del daemon OWASP ZAP per stimolazione e scansione DAST"
    )
    parser.add_argument(
        "--target-base-url",
        default=DEFAULT_TARGET_BASE_URL,
        help="URL di base dell'API target per seeding e attacchi D-AST"
    )
    parser.add_argument(
        "--keycloak-url",
        default=DEFAULT_KEYCLOAK_URL,
        help="URL di base del server Keycloak per acquisizione token"
    )
    parser.add_argument(
        "--assessment-mode",
        action="store_true",
        help="Abilita la modalita' Assessment (senza seeding/snapshot/rollback)"
    )
    return parser.parse_args()


def main() -> None:
    """
    Funzione principale che esegue l'intera pipeline di security Discovery, Correlation, Seeding e D-AST.
    """
    args = parse_args()
    
    logger.info("================================================================================")
    logger.info("🛡️  AVVIO SECURITY PLATFORM CORE - UNIFIED DISCOVERY PIPELINE")
    logger.info("================================================================================")
    logger.info(f"Target Directory:  {args.target_dir}")
    target_abs = os.path.abspath(args.target_dir)
    logger.info(f"Absolute Target Path: {target_abs}")

    # 1. Inizializza gli scanner core (adapters)
    # SpectralScannerAdapter: lancia Stoplight Spectral sul contratto OpenAPI del progetto
    openapi_spec = os.path.abspath(DEFAULT_OPENAPI_SPEC_PATH)
    scanners = [
        CheckovScannerAdapter(),
        SemgrepScannerAdapter(),
        SpectralScannerAdapter(),  # Analisi conformità contratto OpenAPI
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
        traffic_path = DEFAULT_FALLBACK_TRAFFIC_FILE
        
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

    # 5. Esecuzione scansione D-AST dinamica
    logger.info("⚡ Avvio fase D-AST (Dynamic Application Security Testing)...")
    try:
        dast_orchestrator = DynamicOrchestrator(
            target_base_url=args.target_base_url,
            keycloak_url=args.keycloak_url,
            zap_proxy_url=args.zap_url,
            assessment_mode=args.assessment_mode
        )
        # Costruiamo l'inventario per ZAP basandoci sui findings provvisori
        api_inventory = []
        for f in correlated_findings:
            if f.api and f.api.endpoint:
                api_inventory.append(f.to_dict())

        dast_findings = dast_orchestrator.run_dast_pipeline(
            api_inventory, 
            output_dir=args.output_dir, 
            raw_traffic=raw_traffic
        ) or []
        
        # Recuperiamo gli alert da ZAP per integrarli nei findings correlati
        logger.info("📥 Recupero dei findings dinamici generati da OWASP ZAP...")
        zap_client = ZapClientAdapter(zap_url=args.zap_url)
        # ZAP scansiona mappando localhost a api-server per il container
        zap_target_url = args.target_base_url.replace("localhost", "api-server").replace("127.0.0.1", "api-server")
        zap_findings = zap_client.scan(zap_target_url)
        logger.info(f"   - Trovati {len(zap_findings)} findings da OWASP ZAP.")
        
        # Uniamo tutti i runtime findings (mitmproxy + zap + test differenziali di sbarramento)
        all_runtime = list(orchestrator.runtime_findings) + zap_findings + dast_findings
        
        # Correliamo nuovamente l'intero set
        correlated_findings = orchestrator.correlation_engine.correlate(
            orchestrator.static_findings,
            all_runtime
        )
        
        # Ricalcoliamo i punteggi di rischio
        for f in correlated_findings:
            score = orchestrator.correlation_engine.calculate_risk_score(f)
            f.raw_data["correlated_risk_score"] = score

    except Exception as e:
        logger.error(f"⚠️ Esecuzione D-AST o recupero findings ZAP fallito: {e}", exc_info=True)

    # 6. Persistenza dei risultati finali
    report_repo = ReportRepository(args.output_dir)
    report_repo.save_findings(correlated_findings, REPORT_FINDINGS_FILENAME)

    # 7. Generazione Dashboard interattiva con dati completi
    dashboard_path = os.path.join(args.output_dir, DASHBOARD_FILENAME)
    dash_gen = APIDashboardGenerator(correlated_findings)
    dash_gen.generate(dashboard_path)

    # Salviamo l'inventario finale delle API correlate strutturato per la GUI
    final_api_inventory = dash_gen._build_endpoint_catalog(correlated_findings)
    report_repo.save_inventory(final_api_inventory, REPORT_INVENTORY_FILENAME)

    logger.info("================================================================================")
    logger.info(f"🏆 PIPELINE COMPLETATA. Report salvato in '{args.output_dir}/'")
    logger.info(f"🖥️  Dashboard interattiva premium: {dashboard_path}")
    logger.info("================================================================================")


if __name__ == "__main__":
    main()
