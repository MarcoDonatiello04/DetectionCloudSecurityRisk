import logging
import os
from typing import Any

from fastapi import Depends, FastAPI
from fastapi.responses import HTMLResponse

from remediation.remediation_engine import RemediationEngine
from src.application.orchestrator import ScanPipelineOrchestrator
from src.infrastructure.adapters.checkov_adapter import CheckovScannerAdapter
from src.infrastructure.adapters.semgrep_adapter import SemgrepScannerAdapter
from src.infrastructure.adapters.spectral_adapter import SpectralScannerAdapter
from src.infrastructure.persistence.report_repository import ReportRepository

logger = logging.getLogger("SecurityPlatform.API")
remediation_engine = RemediationEngine()


app = FastAPI(
    title="Security Platform Core API",
    description="Enterprise API and Infrastructure Risk Management Platform",
    version="1.0.0",
)


@app.get("/", response_class=HTMLResponse, tags=["UI"])
def serve_dashboard() -> HTMLResponse:
    """
    Ritorna la dashboard iniziale in stile glassmorphism per il controllo sicurezza.
    """
    template_path = "src/presentation/templates/dashboard.html"
    if os.path.exists(template_path):
        with open(template_path, encoding="utf-8") as f:
            html_content = f.read()
    else:
        html_content = "<h1>Dashboard Template Not Found</h1>"
    return HTMLResponse(content=html_content)


@app.get("/results", response_class=HTMLResponse, tags=["UI"])
def serve_results() -> HTMLResponse:
    """
    Ritorna la pagina dei risultati in stile glassmorphism per Checkov.
    """
    template_path = "src/presentation/templates/results.html"
    if os.path.exists(template_path):
        with open(template_path, encoding="utf-8") as f:
            html_content = f.read()
    else:
        html_content = "<h1>Results Template Not Found</h1>"
    return HTMLResponse(content=html_content)


@app.get("/api-results", response_class=HTMLResponse, tags=["UI"])
def serve_api_results() -> HTMLResponse:
    """
    Ritorna la pagina dei risultati per l'Analisi del Codice (Semgrep).
    """
    template_path = "src/presentation/templates/api_results.html"
    if os.path.exists(template_path):
        with open(template_path, encoding="utf-8") as f:
            html_content = f.read()
    else:
        html_content = "<h1>API Results Template Not Found</h1>"
    return HTMLResponse(content=html_content)


@app.get("/contract-results", response_class=HTMLResponse, tags=["UI"])
def serve_contract_results() -> HTMLResponse:
    """
    Ritorna la pagina dei risultati per la conformità del contratto OpenAPI (Spectral).
    """
    template_path = "src/presentation/templates/contract_results.html"
    if os.path.exists(template_path):
        with open(template_path, encoding="utf-8") as f:
            html_content = f.read()
    else:
        html_content = "<h1>Contract Validation Results Template Not Found</h1>"
    return HTMLResponse(content=html_content)


@app.get("/bola-results", response_class=HTMLResponse, tags=["UI"])
def serve_bola_results() -> HTMLResponse:
    """
    Ritorna la pagina dei risultati del test differenziale BOLA/IDOR.
    """
    template_path = "src/presentation/templates/bola_results.html"
    if os.path.exists(template_path):
        with open(template_path, encoding="utf-8") as f:
            html_content = f.read()
    else:
        html_content = "<h1>BOLA Results Template Not Found</h1>"
    return HTMLResponse(content=html_content)


@app.get("/unified-results", response_class=HTMLResponse, tags=["UI"])
def serve_unified_results() -> HTMLResponse:
    """
    Ritorna la pagina dei risultati per le scansioni unificate/veloci dei moduli Core.
    """
    template_path = "src/presentation/templates/unified_results.html"
    if os.path.exists(template_path):
        with open(template_path, encoding="utf-8") as f:
            html_content = f.read()
    else:
        html_content = "<h1>Unified Results Template Not Found</h1>"
    return HTMLResponse(content=html_content)


@app.post("/bola-scan", response_model=dict[str, Any], tags=["Scanning"])
def run_bola_scan() -> dict[str, Any]:
    """
    Esegue la pipeline completa di BOLA tramite il modulo reale DynamicOrchestrator.
    Configura le identità tramite Keycloak, esegue il seeding ed effettua il differential testing.
    """
    import hashlib
    import json
    import time
    from datetime import datetime, timezone

    from src.core.object_level_authorization.dynamic_orchestrator import DynamicOrchestrator

    start_t = time.time()
    start_time = datetime.now(timezone.utc)

    try:
        # Istanza dell'orchestratore reale configurato con i container attivi
        dast_orchestrator = DynamicOrchestrator(
            target_base_url="http://localhost:5000",
            keycloak_url="http://localhost:8080",
            zap_proxy_url="http://localhost:8090",
            assessment_mode=False,
        )

        # Carica inventario API per Discovery
        inventory_path = "output/unified_api_inventory.json"
        api_inventory = []
        if os.path.exists(inventory_path):
            try:
                with open(inventory_path, encoding="utf-8") as f:
                    inv_data = json.load(f)
                    for item in inv_data:
                        path = item.get("path") or item.get("endpoint")
                        method = item.get("method", "GET")
                        if path:
                            api_inventory.append({"api": {"endpoint": path, "method": method}})
            except Exception as e:
                logger.error(f"Errore caricamento inventario API: {e}")

        # Integra da unified_security_report.json se disponibile
        report_path = "output/unified_security_report.json"
        if os.path.exists(report_path):
            try:
                with open(report_path, encoding="utf-8") as f:
                    findings = json.load(f)
                    for fnd in findings:
                        api_ctx = fnd.get("api")
                        if api_ctx and (api_ctx.get("endpoint") or api_ctx.get("path")):
                            api_inventory.append(fnd)
            except Exception as e:
                logger.error(f"Errore integrazione report di sicurezza: {e}")

        # Fallback se vuoto
        if not api_inventory:
            api_inventory = [
                {"api": {"endpoint": "/identity/api/v2/user/{id}", "method": "GET"}},
                {"api": {"endpoint": "/community/api/v2/community/posts/{id}", "method": "GET"}},
                {"api": {"endpoint": "/workshop/api/shop/orders/{id}", "method": "GET"}},
                {"api": {"endpoint": "/workshop/api/shop/orders/{id}", "method": "DELETE"}},
                {"api": {"endpoint": "/identity/api/v2/vehicle/{id}/location", "method": "GET"}},
                {"api": {"endpoint": "/workshop/api/mechanic/receive_report", "method": "POST"}},
                {
                    "api": {
                        "endpoint": "/community/api/v2/community/posts/{id}/comment",
                        "method": "POST",
                    }
                },
            ]

        # Carica traffico reale intercettato
        traffic_path = "output/raw_traffic.json"
        if os.path.exists(traffic_path):
            try:
                with open(traffic_path, encoding="utf-8") as f:
                    json.load(f)
            except Exception as e:
                logger.error(f"Errore caricamento traffico: {e}")

        # Esegue la pipeline reale D-AST (Keycloak, Seeder, ZAP controller)
        dast_orchestrator.run_dast_pipeline(
            api_inventory=api_inventory, output_dir="output", raw_traffic=None
        )

        # Estrae e formatta i risultati del test differenziale
        results = []
        total_tests = 0
        vulnerable_count = 0

        for res in dast_orchestrator.zap_controller.test_results:
            is_vuln = res.get("is_vulnerable", False)
            total_tests += 1
            if is_vuln:
                vulnerable_count += 1

            path = res.get("path", "")
            segments = [s for s in path.split("/") if s]
            resource_name = "resource"
            for i, seg in enumerate(segments):
                if seg == "{id}" and i > 0:
                    resource_name = segments[i - 1]
                    break

            results.append(
                {
                    "endpoint": path,
                    "raw_endpoint": path,
                    "method": res.get("method", "GET"),
                    "resource_name": resource_name,
                    "scenario_name": res.get("scenario_name", res.get("test_name", "")),
                    "scenario_type": "HORIZONTAL"
                    if "Orizzontale" in res.get("scenario_name", "")
                    else (
                        "VERTICAL" if "Verticale" in res.get("scenario_name", "") else "BROKEN_AUTH"
                    ),
                    "test_url": res.get("url", ""),
                    "attacker": "bob@crapi.io"
                    if res.get("attacker_role") == "user"
                    else ("admin@crapi.io" if res.get("attacker_role") == "admin" else "anonymous"),
                    "attacker_role": res.get("attacker_role", "user"),
                    "owner": "alice@crapi.io"
                    if res.get("owner_role") == "user"
                    else "admin@crapi.io",
                    "owner_role": res.get("owner_role", "user"),
                    "res_owner_status": res.get("res_owner_status", 200),
                    "res_attacker_status": res.get("status_code", 403),
                    "res_owner_body_preview": res.get("res_owner_text", "")[:400],
                    "res_attacker_body_preview": res.get("response_text", "")[:400],
                    "is_vulnerable": is_vuln,
                    "verdict": res.get("assertion_details", {}).get(
                        "verdict", "VULNERABLE" if is_vuln else "SAFE"
                    ),
                    "assertion_details": res.get("assertion_details", {}),
                    "was_live_request": True,
                    "severity": "HIGH" if is_vuln else "INFO",
                }
            )

        elapsed = round(time.time() - start_t, 2)
        scan_meta = {
            "scan_id": hashlib.sha256(start_time.isoformat().encode()).hexdigest()[:12],
            "started_at": start_time.isoformat(),
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": elapsed,
            "target_url": dast_orchestrator.target_base_url,
            "mode": "LIVE",
            "endpoints_discovered": len(
                {r.get("path") for r in dast_orchestrator.zap_controller.test_results}
            ),
            "total_tests": total_tests,
            "vulnerable_count": vulnerable_count,
            "safe_count": total_tests - vulnerable_count,
            "vulnerability_rate": round(
                (vulnerable_count / total_tests * 100) if total_tests > 0 else 0, 1
            ),
        }

        report = {"meta": scan_meta, "results": results}

        # Salva il report
        os.makedirs("output", exist_ok=True)
        with open("output/bola_scan_results.json", "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        return report
    except Exception as e:
        logger.error(f"Errore durante BOLA scan: {e}", exc_info=True)
        return {
            "meta": {
                "error": str(e),
                "total_tests": 0,
                "vulnerable_count": 0,
                "safe_count": 0,
                "vulnerability_rate": 0,
                "mode": "LIVE",
            },
            "results": [],
        }


@app.post("/cancel-bola-scan", tags=["Scanning"])
def cancel_bola_scan() -> dict[str, Any]:
    """
    Interrompe la scansione BOLA impostando il flag _is_cancelled su True.
    """
    from src.core.object_level_authorization.dynamic_orchestrator import ZapController

    ZapController._is_cancelled = True
    logger.info(
        "🛑 Ricevuto segnale di cancellazione per la scansione BOLA. Interruzione in corso..."
    )
    return {"status": "cancelled"}


@app.get("/api/bola-report", response_model=dict[str, Any], tags=["Scanning"])
def get_bola_report() -> dict[str, Any]:
    """
    Ritorna l'ultimo report BOLA salvato (output/bola_scan_results.json).
    """
    report_path = "output/bola_scan_results.json"
    if os.path.exists(report_path):
        import json as _json

        try:
            with open(report_path, encoding="utf-8") as f:
                return _json.load(f)
        except Exception as e:
            logger.error(f"Errore lettura report BOLA: {e}")
    return {"meta": {"total_tests": 0, "vulnerable_count": 0, "safe_count": 0}, "results": []}


@app.get("/api/openapi-spec", tags=["Scanning"])
def get_openapi_spec() -> dict[str, str]:
    """
    Ritorna il contenuto del contratto OpenAPI unito.
    """
    spec_path = "output/openapi_merged.yaml"
    if os.path.exists(spec_path):
        try:
            with open(spec_path, encoding="utf-8") as f:
                return {"spec": f.read()}
        except Exception as e:
            logger.error(f"Errore lettura api spec: {e}")
            return {"spec": "", "error": str(e)}
    return {"spec": "Nessun contratto generato."}


# Dependency Injection per gli scanner
def get_static_scanners() -> list[Any]:
    """
    Ritorna la lista delle istanze concrete degli scanner statici.

    Returns:
        List[Any]: Lista di adattatori per l'analisi statica.
    """
    return [CheckovScannerAdapter(), SemgrepScannerAdapter(), SpectralScannerAdapter()]


# Dependency Injection per l'orchestratore
def get_orchestrator() -> ScanPipelineOrchestrator:
    """
    Inizializza e ritorna l'orchestratore di scansione per la directory di progetto corrente.

    Returns:
        ScanPipelineOrchestrator: Istanza configurata dell'orchestratore.
    """
    # Carica la directory corrente come target e i plugin di default
    return ScanPipelineOrchestrator(plugins_dir="src/plugins", target_dir=".")


@app.get("/health", tags=["System"])
def health_check() -> dict[str, str]:
    """
    Ritorna lo stato dell'applicazione.

    Returns:
        Dict[str, str]: Mappa di stato di salute.
    """
    return {"status": "healthy", "service": "security-platform-core"}


@app.post("/scan", response_model=list[dict[str, Any]], tags=["Scanning"])
def trigger_scan(
    scanners: list[Any] = Depends(get_static_scanners),
    orchestrator: ScanPipelineOrchestrator = Depends(get_orchestrator),
) -> list[dict[str, Any]]:
    """
    Avvia la pipeline di scansione, raccoglie i findings da static analysis e
    runtime, correla i rischi e ritorna l'inventario unificato dei findings.

    Args:
        scanners: Lista di scanner iniettati come dipendenza.
        orchestrator: Istanza dell'orchestratore iniettata.

    Returns:
        List[Dict[str, Any]]: Lista serializzata in dizionari dei Finding correlati.
    """
    # Usiamo un payload di traffico di test mock se non è configurato nessun proxy attivo
    mock_traffic = [
        {
            "method": "GET",
            "path": "/users/10",
            "full_url": "http://localhost:5000/users/10",
            "status": 200,
            "headers": {
                "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMH0.signature"
            },
            "body_params": {},
        }
    ]

    correlated_findings = orchestrator.run_pipeline(
        static_scanners=scanners, raw_traffic_data=mock_traffic
    )

    # Salviamo i report
    report_repo = ReportRepository("output")
    report_repo.save_findings(correlated_findings, filename="findings_report.json")
    report_repo.save_findings(correlated_findings, filename="unified_security_report.json")

    return [f.to_dict() for f in correlated_findings]


@app.get("/api/report", response_model=list[dict[str, Any]], tags=["Scanning"])
def get_unified_report() -> list[dict[str, Any]]:
    """
    Ritorna i findings dell'ultimo report di sicurezza unificato (make api-security).
    """
    report_path = "output/unified_security_report.json"
    if os.path.exists(report_path):
        import json

        try:
            with open(report_path, encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Errore lettura report di sicurezza: {e}")
    return []


@app.get("/api/benchmark-report", response_model=list[dict[str, Any]], tags=["Scanning"])
def get_benchmark_report() -> list[dict[str, Any]]:
    """
    Ritorna i risultati dell'esecuzione e benchmark di tutti i moduli di sicurezza Core.
    """
    report_path = "output/benchmark_results.json"
    if os.path.exists(report_path):
        import json

        try:
            with open(report_path, encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Errore lettura report benchmark: {e}")
    return []


async def execute_benchmark_scan(run_bola: bool) -> dict[str, Any]:
    import asyncio
    import json
    import time
    from pathlib import Path

    import yaml

    from src.core.broken_authentication import ast_parser as ba_ast_parser
    from src.core.broken_authentication import authentication_intelligence as ba_auth_intel
    from src.core.broken_authentication import discovery as ba_discovery
    from src.core.broken_authentication import dynamic_tester as ba_dynamic_tester
    from src.core.broken_authentication.discovery import Config as BaConfig
    from src.core.broken_function_level_authorization import detector as bfla_detector
    from src.core.broken_object_property_level_access.orchestrator import BOPLAOrchestrator
    from src.core.security_misconfiguration import detector as secmis_detector
    from src.core.server_side_request_forgery import detector as ssrf_detector
    from src.core.unrestricted_resource_consumption import detector as urc_detector
    from src.core.unsafe_consumption import detector as uc_detector

    openapi_spec = None
    for p in ["test_targets/bola/openapi.yaml", "openapi.yaml", "openapi.json"]:
        if os.path.exists(p):
            try:
                with open(p, encoding="utf-8") as f:
                    if p.endswith(".yaml") or p.endswith(".yml"):
                        openapi_spec = yaml.safe_load(f)
                    else:
                        openapi_spec = json.load(f)
                break
            except Exception:
                pass

    runtime_traffic = None
    for p in ["soluzione_api/src/output/raw_traffic.json", "output/raw_traffic.json"]:
        if os.path.exists(p):
            try:
                with open(p, encoding="utf-8") as f:
                    runtime_traffic = json.load(f)
                break
            except Exception:
                pass

    benchmark_path = "output/benchmark_results.json"
    results = []
    findings_by_module = {}

    def serialize_finding(f) -> dict[str, Any]:
        if hasattr(f, "to_dict"):
            return f.to_dict()
        res = {}
        for attr in [
            "rule_id",
            "cwe_id",
            "category",
            "severity",
            "file_path",
            "line_number",
            "evidence",
            "missing_guard",
            "confidence",
            "layer",
            "description",
            "title",
            "id",
        ]:
            if hasattr(f, attr):
                val = getattr(f, attr)
                if isinstance(val, Path):
                    val = str(val)
                res[attr] = val
        return res

    # 1. BOPLA
    start = time.time()
    bopla_list = []
    try:
        bopla_data = BOPLAOrchestrator(
            BaConfig(output=ba_discovery.OutputConfig(path="output"))
        ).run_assessment(
            repo_path=".",
            openapi_spec=openapi_spec,
            runtime_traffic=runtime_traffic,
            headers_matrix=None,
        )
        bopla_list = [f for f in bopla_data.get("findings", []) if f.get("verified")]
        findings_count = len(bopla_list)
        status = "SUCCESS"
    except Exception as e:
        findings_count = 0
        status = f"FAILED: {e}"
    results.append(
        {
            "name": "BOPLA (Broken Object Property Level Access)",
            "dir": "src/core/broken_object_property_level_access",
            "time": time.time() - start,
            "status": status,
            "findings": findings_count,
        }
    )
    findings_by_module["bopla"] = bopla_list

    # 1.5. BOLA
    bola_list = []
    if run_bola:
        start_bola = time.time()
        try:
            # Carica inventario API per Discovery
            inventory_path = "output/unified_api_inventory.json"
            api_inventory = []
            if os.path.exists(inventory_path):
                try:
                    with open(inventory_path, encoding="utf-8") as f:
                        inv_data = json.load(f)
                        for item in inv_data:
                            path = item.get("path") or item.get("endpoint")
                            method = item.get("method", "GET")
                            if path:
                                api_inventory.append({"api": {"endpoint": path, "method": method}})
                except Exception as e:
                    logger.error(f"Errore caricamento inventario API in benchmark: {e}")

            # Integra da unified_security_report.json se disponibile
            report_path = "output/unified_security_report.json"
            if os.path.exists(report_path):
                try:
                    with open(report_path, encoding="utf-8") as f:
                        findings = json.load(f)
                        for fnd in findings:
                            api_ctx = fnd.get("api")
                            if api_ctx and (api_ctx.get("endpoint") or api_ctx.get("path")):
                                api_inventory.append(fnd)
                except Exception as e:
                    logger.error(f"Errore integrazione report di sicurezza in benchmark: {e}")

            # Fallback se vuoto
            if not api_inventory:
                api_inventory = [
                    {"api": {"endpoint": "/identity/api/v2/user/{id}", "method": "GET"}},
                    {
                        "api": {
                            "endpoint": "/community/api/v2/community/posts/{id}",
                            "method": "GET",
                        }
                    },
                    {"api": {"endpoint": "/workshop/api/shop/orders/{id}", "method": "GET"}},
                    {"api": {"endpoint": "/workshop/api/shop/orders/{id}", "method": "DELETE"}},
                    {
                        "api": {
                            "endpoint": "/identity/api/v2/vehicle/{id}/location",
                            "method": "GET",
                        }
                    },
                    {
                        "api": {
                            "endpoint": "/workshop/api/mechanic/receive_report",
                            "method": "POST",
                        }
                    },
                    {
                        "api": {
                            "endpoint": "/community/api/v2/community/posts/{id}/comment",
                            "method": "POST",
                        }
                    },
                ]

            from src.core.object_level_authorization.dynamic_orchestrator import DynamicOrchestrator

            dast_orchestrator = DynamicOrchestrator(
                target_base_url="http://localhost:5000",
                keycloak_url="http://localhost:8080",
                zap_proxy_url="http://localhost:8090",
                assessment_mode=False,
            )
            dast_orchestrator.run_dast_pipeline(
                api_inventory=api_inventory, output_dir="output", raw_traffic=None
            )
            # Estrae e formatta i risultati BOLA (tutti i test, non solo i vulnerabili)
            total_tests = len(dast_orchestrator.zap_controller.test_results)
            for res in dast_orchestrator.zap_controller.test_results:
                is_vuln = res.get("is_vulnerable", False)
                path = res.get("path", "")
                segments = [s for s in path.split("/") if s]
                resource_name = "resource"
                for i, seg in enumerate(segments):
                    if seg == "{id}" and i > 0:
                        resource_name = segments[i - 1]
                        break
                bola_list.append(
                    {
                        "title": f"{'⚠️ BOLA VULNERABILE' if is_vuln else '✅ SAFE'}: {res.get('method', 'GET')} {path}",
                        "severity": "HIGH" if is_vuln else "INFO",
                        "endpoint": path,
                        "file_path": path,
                        "method": res.get("method", "GET"),
                        "resource_name": resource_name,
                        "is_vulnerable": is_vuln,
                        "evidence": (
                            f"Scenario: {res.get('scenario_name', res.get('test_name', ''))}\n"
                            f"Attacker Role: {res.get('attacker_role', 'user')}\n"
                            f"Owner Role: {res.get('owner_role', 'user')}\n"
                            f"Attacker Response Code: {res.get('status_code', 403)}\n"
                            f"Assertion Verdict: {res.get('assertion_details', {}).get('verdict', 'VULNERABLE' if is_vuln else 'SAFE')}"
                        ),
                    }
                )
            findings_count = sum(1 for r in bola_list if r.get("is_vulnerable"))
            # Se non ci sono stati test eseguiti, lo segnaliamo come warning
            if total_tests == 0:
                bola_list.append(
                    {
                        "title": "⚠️ Nessun test eseguito",
                        "severity": "MEDIUM",
                        "file_path": "N/A",
                        "evidence": "ZAP non raggiungibile o inventario API vuoto. Verificare che i container Docker siano in esecuzione.",
                    }
                )
            status = "SUCCESS"
        except Exception as e:
            findings_count = 0
            status = f"FAILED: {e}"
        results.append(
            {
                "name": "BOLA (Broken Object Level Authorization)",
                "dir": "src/core/object_level_authorization",
                "time": time.time() - start_bola,
                "status": status,
                "findings": findings_count,
            }
        )
    else:
        results.append(
            {
                "name": "BOLA (Broken Object Level Authorization)",
                "dir": "src/core/object_level_authorization",
                "time": 0.0,
                "status": "SKIPPED",
                "findings": 0,
            }
        )
    findings_by_module["bola"] = bola_list

    # 2. Broken Authentication
    start = time.time()
    ba_list = []
    try:
        config = BaConfig()
        config.target.base_url = "http://localhost:5000"
        config.output.path = "output"
        config.output.formato = "json"

        stack = ba_discovery.StackInfo(
            linguaggio="python",
            framework="FastAPI",
            librerie_auth=["jwt"],
            file_configurazione_rilevanti=["requirements.txt"],
        )
        scored_files = await ba_ast_parser.run(".", stack, config)
        auth_intel = ba_auth_intel.AuthenticationIntelligenceEngine.correlate(
            discovery_output=stack,
            ast_output=scored_files,
            openapi_spec=openapi_spec,
            runtime_traffic=runtime_traffic or [],
        )

        vulnerabilities = []
        for f in scored_files:
            if f.chiamate_auth or f.route_auth:
                vulnerabilities.append(
                    ba_dynamic_tester.Vulnerabilita(
                        id=f"VULN-{f.file.replace('/', '_')}",
                        tipo="static",
                        descrizione="Static auth endpoint detected via AST",
                        file=f.file,
                        linea=1,
                        route_auth=f.route_auth,
                    )
                )
        from unittest.mock import MagicMock

        import httpx

        mock_client = MagicMock(spec=httpx.AsyncClient)
        mock_client.base_url = httpx.URL(config.target.base_url)

        async def mock_http(*args, **kwargs):
            return MagicMock(status_code=401, text="Unauthorized")

        mock_client.get = mock_http
        mock_client.post = mock_http
        tester = ba_dynamic_tester.DynamicTester(config, client=mock_client, auth_intel=auth_intel)
        tester.health_check = lambda: asyncio.sleep(0)
        ba_res = await tester.run_all(stack, vulnerabilities)
        ba_list = [f.dict() for f in ba_res if f.stato == "FAIL"]
        findings_count = len(ba_list)
        status = "SUCCESS"
    except Exception as e:
        findings_count = 0
        status = f"FAILED: {e}"
    results.append(
        {
            "name": "Broken Authentication",
            "dir": "src/core/broken_authentication",
            "time": time.time() - start,
            "status": status,
            "findings": findings_count,
        }
    )
    findings_by_module["broken_authentication"] = ba_list

    # 3. BFLA
    start = time.time()
    bfla_list = []
    try:
        report = bfla_detector.analyze(".", openapi_spec)
        bfla_list = [serialize_finding(f) for f in report.findings]
        findings_count = len(bfla_list)
        status = "SUCCESS"
    except Exception as e:
        findings_count = 0
        status = f"FAILED: {e}"
    results.append(
        {
            "name": "BFLA (Broken Function Level Authorization)",
            "dir": "src/core/broken_function_level_authorization",
            "time": time.time() - start,
            "status": status,
            "findings": findings_count,
        }
    )
    findings_by_module["bfla"] = bfla_list

    # 4. Security Misconfiguration
    start = time.time()
    secmis_list = []
    try:
        report = secmis_detector.analyze(".")
        secmis_list = [serialize_finding(f) for f in report.findings]
        findings_count = len(secmis_list)
        status = "SUCCESS"
    except Exception as e:
        findings_count = 0
        status = f"FAILED: {e}"
    results.append(
        {
            "name": "Security Misconfiguration",
            "dir": "src/core/security_misconfiguration",
            "time": time.time() - start,
            "status": status,
            "findings": findings_count,
        }
    )
    findings_by_module["security_misconfiguration"] = secmis_list

    # 5. SSRF
    start = time.time()
    ssrf_list = []
    try:
        report = ssrf_detector.analyze(".", openapi_spec, semgrep_timeout=15)
        ssrf_list = [serialize_finding(f) for f in report.findings]
        findings_count = len(ssrf_list)
        status = "SUCCESS"
    except Exception as e:
        findings_count = 0
        status = f"FAILED: {e}"
    results.append(
        {
            "name": "SSRF (Server Side Request Forgery)",
            "dir": "src/core/server_side_request_forgery",
            "time": time.time() - start,
            "status": status,
            "findings": findings_count,
        }
    )
    findings_by_module["ssrf"] = ssrf_list

    # 6. Unrestricted Resource Consumption
    start = time.time()
    urc_list = []
    try:
        report = urc_detector.analyze(".", openapi_spec)
        urc_list = [serialize_finding(f) for f in report.findings]
        findings_count = len(urc_list)
        status = "SUCCESS"
    except Exception as e:
        findings_count = 0
        status = f"FAILED: {e}"
    results.append(
        {
            "name": "Unrestricted Resource Consumption",
            "dir": "src/core/unrestricted_resource_consumption",
            "time": time.time() - start,
            "status": status,
            "findings": findings_count,
        }
    )
    findings_by_module["unrestricted_resource_consumption"] = urc_list

    # 7. Unsafe Consumption
    start = time.time()
    uc_list = []
    try:
        report = uc_detector.analyze(".")
        uc_list = [serialize_finding(f) for f in report.findings]
        findings_count = len(uc_list)
        status = "SUCCESS"
    except Exception as e:
        findings_count = 0
        status = f"FAILED: {e}"
    results.append(
        {
            "name": "Unsafe Consumption",
            "dir": "src/core/unsafe_consumption",
            "time": time.time() - start,
            "status": status,
            "findings": findings_count,
        }
    )
    findings_by_module["unsafe_consumption"] = uc_list

    try:
        with open(benchmark_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
    except Exception as e:
        logger.error(f"Errore scrittura benchmark: {e}")

    return {"benchmark": results, "findings": findings_by_module}


@app.post("/api/scan/all", response_model=dict[str, Any], tags=["Scanning"])
async def scan_all_modules() -> dict[str, Any]:
    """
    Esegue la scansione completa di tutti i moduli di sicurezza Core (BOLA inclusa).
    """
    return await execute_benchmark_scan(run_bola=True)


@app.post("/api/scan/non-bola", response_model=dict[str, Any], tags=["Scanning"])
async def scan_non_bola_modules() -> dict[str, Any]:
    """
    Esegue la scansione di tutti i moduli di sicurezza Core (incluso BOLA e Checkov come esclusi non testati).
    """
    return await execute_benchmark_scan(run_bola=False)


@app.post("/remediation", tags=["Remediation"])
def get_remediation_on_demand(finding_data: dict[str, Any]) -> dict[str, Any]:
    """
    Recupera la remediation per un singolo finding on-demand.
    """
    try:
        # Ricostruiamo un oggetto Finding minimale per il motore
        class TempFinding:
            def __init__(self, d):
                self.id = d.get("finding_id", "")
                self.finding_id = d.get("finding_id", "")
                self.rule_id = d.get("rule_id", "N/A")
                self.title = d.get("title", "")
                self.description = d.get("description", "")
                self.severity = d.get("severity", "INFO")
                self.category = d.get("category", "MISCONFIGURATION")
                self.source = d.get("source", "CHECKOV")
                self.remediation = d.get("remediation", "")

        f = TempFinding(finding_data)
        rem = remediation_engine.get_remediation(f)
        return {
            "title": rem.title,
            "description": rem.description,
            "impact": rem.impact,
            "steps": rem.remediation_steps,
            "example": rem.example,
            "source": rem.source,
            "confidence": rem.confidence,
        }
    except Exception as e:
        logger.error(f"Errore caricamento remediation on-demand: {e}")
        return {
            "title": "Errore di caricamento",
            "description": f"Impossibile generare la remediation: {e!s}",
            "impact": "N/A",
            "steps": [],
            "example": "",
            "source": "error",
            "confidence": 0.0,
        }
