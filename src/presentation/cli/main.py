import argparse
import logging
import os
from typing import Any

from src.application.correlation.engine import RiskCorrelationEngine
from src.application.event_bus import EventBus
from src.application.orchestrator import ScanPipelineOrchestrator
from src.application.plugin_loader import PluginLoader
from src.core.api1_bola.dynamic_orchestrator import DynamicOrchestrator
from src.core.config import (
    DEFAULT_FALLBACK_TRAFFIC_FILE,
    DEFAULT_KEYCLOAK_URL,
    DEFAULT_OPENAPI_SPEC_PATH,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_PLUGINS_DIR,
    DEFAULT_TARGET_BASE_URL,
    DEFAULT_TRAFFIC_FILE,
    DEFAULT_ZAP_URL,
    REPORT_FINDINGS_FILENAME,
    REPORT_INVENTORY_FILENAME,
)
from src.core.utilities.openapi_parser import load_openapi_spec
from src.domain.entities import Finding
from src.infrastructure.adapters.checkov_adapter import CheckovScannerAdapter
from src.infrastructure.adapters.mitmproxy_adapter import MitmproxyClientAdapter
from src.infrastructure.adapters.semgrep_adapter import SemgrepScannerAdapter
from src.infrastructure.adapters.spectral_adapter import SpectralScannerAdapter
from src.infrastructure.adapters.zap_adapter import ZapClientAdapter
from src.infrastructure.persistence.report_repository import ReportRepository
from src.normalization.normalizer import APIEndpointNormalizer

# Configurazione logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)-35s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("SecurityPlatform.CLI")


def parse_args() -> argparse.Namespace:
    """
    Effettua il parsing degli argomenti da riga di comando per il tool CLI.

    Returns:
        argparse.Namespace: Gli argomenti parsati.
    """
    parser = argparse.ArgumentParser(
        description="Security Platform Core - Unified Scanner & Detector CLI"
    )
    parser.add_argument(
        "--target-dir",
        default=".",
        help="Directory contenente il codice o infrastruttura da scansionare",
    )
    parser.add_argument(
        "--plugins-dir",
        default=DEFAULT_PLUGINS_DIR,
        help="Directory contenente i plugin dei detector",
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help="Directory dove salvare i report dei findings",
    )
    parser.add_argument(
        "--traffic-file",
        default=DEFAULT_TRAFFIC_FILE,
        help="File contenente il traffico catturato da mitmproxy",
    )
    parser.add_argument(
        "--zap-url",
        default=DEFAULT_ZAP_URL,
        help="URL del daemon OWASP ZAP per stimolazione e scansione DAST",
    )
    parser.add_argument(
        "--target-base-url",
        default=DEFAULT_TARGET_BASE_URL,
        help="URL di base dell'API target per seeding e attacchi D-AST",
    )
    parser.add_argument(
        "--keycloak-url",
        default=DEFAULT_KEYCLOAK_URL,
        help="URL di base del server Keycloak per acquisizione token",
    )
    parser.add_argument(
        "--assessment-mode",
        action="store_true",
        help="Abilita la modalita' Assessment (senza seeding/snapshot/rollback)",
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
    os.path.abspath(DEFAULT_OPENAPI_SPEC_PATH)
    scanners = [
        CheckovScannerAdapter(),
        SemgrepScannerAdapter(),
        SpectralScannerAdapter(),  # Analisi conformità contratto OpenAPI
    ]

    # 2. Inizializza l'orchestratore
    event_bus = EventBus()
    plugin_loader = PluginLoader(args.plugins_dir)
    correlation_engine = RiskCorrelationEngine()

    orchestrator = ScanPipelineOrchestrator(
        target_dir=args.target_dir,
        event_bus=event_bus,
        plugin_loader=plugin_loader,
        correlation_engine=correlation_engine,
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
        logger.info(
            "⚠️ Nessun traffico Mitmproxy trovato. Generazione scenario simulato per dimostrazione..."
        )
        raw_traffic = [
            # Richiesta valida con token
            {
                "method": "GET",
                "path": "/users/42",
                "full_url": "http://localhost:5000/users/42",
                "status": 200,
                "headers": {
                    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjo0Mn0.signature"
                },
                "body_params": {},
            },
            # Richiesta Shadow API (non documentata)
            {
                "method": "POST",
                "path": "/api/v1/debug/dump-database",
                "full_url": "http://localhost:5000/api/v1/debug/dump-database",
                "status": 200,
                "headers": {},
                "body_params": {"raw_sql": "SELECT * FROM secrets"},
            },
        ]

    # 4. Esecuzione pipeline
    correlated_findings = orchestrator.run_pipeline(
        static_scanners=scanners, raw_traffic_data=raw_traffic
    )

    # 5. Esecuzione scansione D-AST dinamica
    logger.info("⚡ Avvio fase D-AST (Dynamic Application Security Testing)...")
    try:
        dast_orchestrator = DynamicOrchestrator(
            target_base_url=args.target_base_url,
            keycloak_url=args.keycloak_url,
            zap_proxy_url=args.zap_url,
            assessment_mode=args.assessment_mode,
        )
        # Costruiamo l'inventario per ZAP basandoci sui findings provvisori
        api_inventory = []
        for f in correlated_findings:
            if f.api and f.api.endpoint:
                api_inventory.append(f.to_dict())

        dast_findings = (
            dast_orchestrator.run_dast_pipeline(
                api_inventory, output_dir=args.output_dir, raw_traffic=raw_traffic
            )
            or []
        )

        # Recuperiamo gli alert da ZAP per integrarli nei findings correlati
        logger.info("📥 Recupero dei findings dinamici generati da OWASP ZAP...")
        zap_client = ZapClientAdapter(zap_url=args.zap_url)
        # ZAP scansiona mappando localhost a api-server per il container
        zap_target_url = args.target_base_url.replace("localhost", "api-server").replace(
            "127.0.0.1", "api-server"
        )
        zap_findings = zap_client.scan(zap_target_url)
        logger.info(f"   - Trovati {len(zap_findings)} findings da OWASP ZAP.")

        # Uniamo tutti i runtime findings (mitmproxy + zap + test differenziali di sbarramento)
        all_runtime = list(orchestrator.runtime_findings) + zap_findings + dast_findings

        # Correliamo nuovamente l'intero set
        correlated_findings = orchestrator.correlation_engine.correlate(
            orchestrator.static_findings, all_runtime
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

    # 7. Salviamo l'inventario finale delle API correlate strutturato per la GUI
    final_api_inventory = _build_endpoint_catalog(correlated_findings)
    report_repo.save_inventory(final_api_inventory, REPORT_INVENTORY_FILENAME)

    logger.info("================================================================================")
    logger.info(f"🏆 PIPELINE COMPLETATA. Report salvato in '{args.output_dir}/'")
    logger.info("================================================================================")


def _build_endpoint_catalog(findings: list[Finding]) -> list[dict[str, Any]]:
    """Costruisce il catalogo completo degli endpoint incrociando specifiche e findings."""
    # 1. Carica endpoint documentati in OpenAPI
    documented_endpoints = load_openapi_spec(return_endpoints_list=True)

    catalog = {}
    for ep in documented_endpoints:
        key = f"{ep['method']} {ep['path']}"
        catalog[key] = {
            "method": ep["method"],
            "path": ep["path"],
            "summary": ep["summary"],
            "description": ep["description"],
            "documented": True,
            "shadow": False,
            "violations": [],
            "bola_status": "UNTESTED",  # UNTESTED, SAFE, VULNERABLE, POTENTIAL
            "bola_findings": [],
        }

    # 2. Analizza i findings per popolare violazioni, shadow api e bola
    for f in findings:
        if not f.api or not f.api.endpoint:
            continue

        method = (f.api.method or "GET").upper()
        norm_path = APIEndpointNormalizer.normalize_path(f.api.endpoint)
        key = f"{method} {norm_path}"

        matched_key = None
        if key in catalog:
            matched_key = key
        else:
            for cat_key, cat_ep in catalog.items():
                if cat_ep["method"] == method:
                    if APIEndpointNormalizer.normalize_path(cat_ep["path"]) == norm_path:
                        matched_key = cat_key
                        break

        if not matched_key:
            # È un endpoint non documentato (Shadow API)
            matched_key = key
            catalog[matched_key] = {
                "method": method,
                "path": norm_path,
                "summary": f.title if f.source.value == "SHADOW_API" else "Endpoint Rilevato",
                "description": f.description,
                "documented": False,
                "shadow": True,
                "violations": [],
                "bola_status": "UNTESTED",
                "bola_findings": [],
            }

        ep_entry = catalog[matched_key]

        # Spectral violations
        if f.source.value == "SPECTRAL":
            ep_entry["violations"].append(
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "line": f.location.start_line if f.location else None,
                }
            )

        # BOLA / D-AST
        is_bola = (
            f.category.value == "AUTHORIZATION"
            or f.category.value == "AUTHENTICATION"
            or "bola" in f.title.lower()
            or "idor" in f.title.lower()
            or f.source.value in ("ZAP_DAST", "RUNTIME_VALIDATOR")
        )
        if is_bola:
            ep_entry["bola_findings"].append(f.to_dict())
            if f.rule_id == "dynamic-test-secure":
                if ep_entry["bola_status"] not in ("VULNERABLE", "POTENTIAL"):
                    ep_entry["bola_status"] = "SAFE"
            else:
                if f.validation_status.value == "CONFIRMED":
                    ep_entry["bola_status"] = "VULNERABLE"
                elif ep_entry["bola_status"] not in ("VULNERABLE", "SAFE"):
                    ep_entry["bola_status"] = "POTENTIAL"

    # 3. Imposta stato test BOLA per gli endpoint dinamici
    for ep_entry in catalog.values():
        path = ep_entry["path"]
        is_dynamic = "{" in path or "<" in path or ":" in path or "id" in path.lower()
        ep_entry["is_dynamic"] = is_dynamic

        # Controlla se abbiamo ricevuto evidenza di sbarramento (status 401 o 403) o se l'assertion engine lo ritiene sicuro
        has_blocking_evidence = False
        for f in ep_entry["bola_findings"]:
            if f.get("rule_id") == "dynamic-test-secure":
                has_blocking_evidence = True
                break
            re = f.get("runtime_evidence")
            if re:
                status = re.get("http_status")
                if status in (401, 403):
                    has_blocking_evidence = True
                    break

        if is_dynamic and ep_entry["bola_status"] in ("UNTESTED", "SAFE"):
            if ep_entry["bola_status"] == "SAFE" or has_blocking_evidence:
                ep_entry["bola_status"] = "SAFE"
            else:
                ep_entry["bola_status"] = "UNTESTED"

    return sorted(catalog.values(), key=lambda x: (x["path"], x["method"]))


if __name__ == "__main__":
    main()
