from fastapi import FastAPI, Depends, BackgroundTasks
from fastapi.responses import HTMLResponse
from typing import List, Dict, Any
import os
import logging
from src.domain.entities import Finding
from src.application.orchestrator import ScanPipelineOrchestrator
from src.infrastructure.adapters.checkov_adapter import CheckovScannerAdapter
from src.infrastructure.adapters.semgrep_adapter import SemgrepScannerAdapter
from src.infrastructure.adapters.spectral_adapter import SpectralScannerAdapter
from src.infrastructure.persistence.report_repository import ReportRepository
from remediation.remediation_engine import RemediationEngine

logger = logging.getLogger("SecurityPlatform.API")
remediation_engine = RemediationEngine()


app = FastAPI(
    title="Security Platform Core API",
    description="Enterprise API and Infrastructure Risk Management Platform",
    version="1.0.0"
)


@app.get("/", response_class=HTMLResponse, tags=["UI"])
def serve_dashboard() -> HTMLResponse:
    """
    Ritorna la dashboard iniziale in stile glassmorphism per il controllo sicurezza.
    """
    template_path = "src/presentation/templates/dashboard.html"
    if os.path.exists(template_path):
        with open(template_path, "r", encoding="utf-8") as f:
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
        with open(template_path, "r", encoding="utf-8") as f:
            html_content = f.read()
    else:
        html_content = "<h1>Results Template Not Found</h1>"
    return HTMLResponse(content=html_content)


@app.get("/api-results", response_class=HTMLResponse, tags=["UI"])
def serve_api_results() -> HTMLResponse:
    """
    Ritorna la pagina dei risultati per API Security / D-AST (make api-security).
    """
    template_path = "src/presentation/templates/api_results.html"
    if os.path.exists(template_path):
        with open(template_path, "r", encoding="utf-8") as f:
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
        with open(template_path, "r", encoding="utf-8") as f:
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
        with open(template_path, "r", encoding="utf-8") as f:
            html_content = f.read()
    else:
        html_content = "<h1>BOLA Results Template Not Found</h1>"
    return HTMLResponse(content=html_content)


@app.post("/bola-scan", response_model=Dict[str, Any], tags=["Scanning"])
def run_bola_scan() -> Dict[str, Any]:
    """
    Esegue la pipeline completa di BOLA tramite il modulo reale DynamicOrchestrator.
    Configura le identità tramite Keycloak, esegue il seeding ed effettua il differential testing.
    """
    import json
    import time
    import hashlib
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
            assessment_mode=False
        )

        # Carica inventario API per Discovery
        inventory_path = "output/unified_api_inventory.json"
        api_inventory = []
        if os.path.exists(inventory_path):
            try:
                with open(inventory_path, "r", encoding="utf-8") as f:
                    inv_data = json.load(f)
                    for item in inv_data:
                        path = item.get("path") or item.get("endpoint")
                        method = item.get("method", "GET")
                        if path:
                            api_inventory.append({
                                "api": {
                                    "endpoint": path,
                                    "method": method
                                }
                            })
            except Exception as e:
                logger.error(f"Errore caricamento inventario API: {e}")

        # Integra da unified_security_report.json se disponibile
        report_path = "output/unified_security_report.json"
        if os.path.exists(report_path):
            try:
                with open(report_path, "r", encoding="utf-8") as f:
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
                {"api": {"endpoint": "/community/api/v2/community/posts/{id}/comment", "method": "POST"}},
            ]

        # Carica traffico reale intercettato
        traffic_path = "output/raw_traffic.json"
        raw_traffic = []
        if os.path.exists(traffic_path):
            try:
                with open(traffic_path, "r", encoding="utf-8") as f:
                    raw_traffic = json.load(f)
            except Exception as e:
                logger.error(f"Errore caricamento traffico: {e}")

        # Esegue la pipeline reale D-AST (Keycloak, Seeder, ZAP controller)
        dast_orchestrator.run_dast_pipeline(
            api_inventory=api_inventory,
            output_dir="output",
            raw_traffic=None
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

            results.append({
                "endpoint": path,
                "raw_endpoint": path,
                "method": res.get("method", "GET"),
                "resource_name": resource_name,
                "scenario_name": res.get("scenario_name", res.get("test_name", "")),
                "scenario_type": "HORIZONTAL" if "Orizzontale" in res.get("scenario_name", "") else ("VERTICAL" if "Verticale" in res.get("scenario_name", "") else "BROKEN_AUTH"),
                "test_url": res.get("url", ""),
                "attacker": "bob@crapi.io" if res.get("attacker_role") == "user" else ("admin@crapi.io" if res.get("attacker_role") == "admin" else "anonymous"),
                "attacker_role": res.get("attacker_role", "user"),
                "owner": "alice@crapi.io" if res.get("owner_role") == "user" else "admin@crapi.io",
                "owner_role": res.get("owner_role", "user"),
                "res_owner_status": res.get("res_owner_status", 200),
                "res_attacker_status": res.get("status_code", 403),
                "res_owner_body_preview": res.get("res_owner_text", "")[:400],
                "res_attacker_body_preview": res.get("response_text", "")[:400],
                "is_vulnerable": is_vuln,
                "verdict": res.get("assertion_details", {}).get("verdict", "VULNERABLE" if is_vuln else "SAFE"),
                "assertion_details": res.get("assertion_details", {}),
                "was_live_request": True,
                "severity": "HIGH" if is_vuln else "INFO"
            })

        elapsed = round(time.time() - start_t, 2)
        scan_meta = {
            "scan_id": hashlib.sha256(start_time.isoformat().encode()).hexdigest()[:12],
            "started_at": start_time.isoformat(),
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": elapsed,
            "target_url": dast_orchestrator.target_base_url,
            "mode": "LIVE",
            "endpoints_discovered": len(set(r.get("path") for r in dast_orchestrator.zap_controller.test_results)),
            "total_tests": total_tests,
            "vulnerable_count": vulnerable_count,
            "safe_count": total_tests - vulnerable_count,
            "vulnerability_rate": round((vulnerable_count / total_tests * 100) if total_tests > 0 else 0, 1)
        }

        report = {
            "meta": scan_meta,
            "results": results
        }

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
                "mode": "LIVE"
            },
            "results": []
        }


@app.get("/api/bola-report", response_model=Dict[str, Any], tags=["Scanning"])
def get_bola_report() -> Dict[str, Any]:
    """
    Ritorna l'ultimo report BOLA salvato (output/bola_scan_results.json).
    """
    report_path = "output/bola_scan_results.json"
    if os.path.exists(report_path):
        import json as _json
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                return _json.load(f)
        except Exception as e:
            logger.error(f"Errore lettura report BOLA: {e}")
    return {"meta": {"total_tests": 0, "vulnerable_count": 0, "safe_count": 0}, "results": []}


@app.get("/api/openapi-spec", tags=["Scanning"])
def get_openapi_spec() -> Dict[str, str]:
    """
    Ritorna il contenuto del contratto OpenAPI unito.
    """
    spec_path = "output/openapi_merged.yaml"
    if os.path.exists(spec_path):
        try:
            with open(spec_path, "r", encoding="utf-8") as f:
                return {"spec": f.read()}
        except Exception as e:
            logger.error(f"Errore lettura api spec: {e}")
            return {"spec": "", "error": str(e)}
    return {"spec": "Nessun contratto generato."}



# Dependency Injection per gli scanner
def get_static_scanners() -> List[Any]:
    """
    Ritorna la lista delle istanze concrete degli scanner statici.

    Returns:
        List[Any]: Lista di adattatori per l'analisi statica.
    """
    return [
        CheckovScannerAdapter(),
        SemgrepScannerAdapter(),
        SpectralScannerAdapter()
    ]


# Dependency Injection per l'orchestratore
def get_orchestrator() -> ScanPipelineOrchestrator:
    """
    Inizializza e ritorna l'orchestratore di scansione per la directory di progetto corrente.

    Returns:
        ScanPipelineOrchestrator: Istanza configurata dell'orchestratore.
    """
    # Carica la directory corrente come target e i plugin di default
    return ScanPipelineOrchestrator(
        plugins_dir="src/plugins",
        target_dir="."
    )


@app.get("/health", tags=["System"])
def health_check() -> Dict[str, str]:
    """
    Ritorna lo stato dell'applicazione.

    Returns:
        Dict[str, str]: Mappa di stato di salute.
    """
    return {"status": "healthy", "service": "security-platform-core"}


@app.post("/scan", response_model=List[Dict[str, Any]], tags=["Scanning"])
def trigger_scan(
    scanners: List[Any] = Depends(get_static_scanners),
    orchestrator: ScanPipelineOrchestrator = Depends(get_orchestrator)
) -> List[Dict[str, Any]]:
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
            "headers": {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMH0.signature"},
            "body_params": {}
        }
    ]
    
    correlated_findings = orchestrator.run_pipeline(
        static_scanners=scanners,
        raw_traffic_data=mock_traffic
    )
    
    # Salviamo i report
    report_repo = ReportRepository("output")
    report_repo.save_findings(correlated_findings, filename="findings_report.json")
    report_repo.save_findings(correlated_findings, filename="unified_security_report.json")
    
    return [f.to_dict() for f in correlated_findings]


@app.get("/api/report", response_model=List[Dict[str, Any]], tags=["Scanning"])
def get_unified_report() -> List[Dict[str, Any]]:
    """
    Ritorna i findings dell'ultimo report di sicurezza unificato (make api-security).
    """
    report_path = "output/unified_security_report.json"
    if os.path.exists(report_path):
        import json
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Errore lettura report di sicurezza: {e}")
    return []


@app.post("/remediation", tags=["Remediation"])
def get_remediation_on_demand(finding_data: Dict[str, Any]) -> Dict[str, Any]:
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
            "confidence": rem.confidence
        }
    except Exception as e:
        logger.error(f"Errore caricamento remediation on-demand: {e}")
        return {
            "title": "Errore di caricamento",
            "description": f"Impossibile generare la remediation: {str(e)}",
            "impact": "N/A",
            "steps": [],
            "example": "",
            "source": "error",
            "confidence": 0.0
        }
