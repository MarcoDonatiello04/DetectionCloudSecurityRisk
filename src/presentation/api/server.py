import logging
import os
import threading
import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from src.application.correlation.engine import RiskCorrelationEngine
from src.application.orchestrator import ScanPipelineOrchestrator
from src.application.remediation.remediation_engine import RemediationEngine
from src.core.api1_bola.target_config import load_bola_target_config, reset_bola_target_config
from src.core.config import (
    DEFAULT_KEYCLOAK_URL,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_TARGET_BASE_URL,
    DEFAULT_TARGET_DIR,
    DEFAULT_ZAP_URL,
)
from src.core.utilities.file_io import safe_read_json
from src.core.utilities.openapi_parser import find_openapi_spec_path, load_openapi_spec
from src.core.utilities.url_utils import extract_resource_name_from_path
from src.infrastructure.adapters.checkov_adapter import CheckovScannerAdapter
from src.infrastructure.adapters.semgrep_adapter import SemgrepScannerAdapter
from src.infrastructure.adapters.spectral_adapter import SpectralScannerAdapter
from src.infrastructure.llm.ollama_adapter import OllamaAdapter
from src.infrastructure.persistence.report_repository import ReportRepository
from src.presentation.api import external_targets, target_catalog

if TYPE_CHECKING:
    from src.core.api1_bola.dynamic_orchestrator import DynamicOrchestrator
    from src.presentation.api.target_catalog import DashboardTarget

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)-35s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("SecurityPlatform.API")
remediation_engine = RemediationEngine(llm_provider=OllamaAdapter())

# ─── BERSAGLIO DELLA SESSIONE ────────────────────────────────────────────────
# Un'istanza della dashboard lavora su UN bersaglio, fissato all'avvio dalle variabili
# d'ambiente (vedi i target `make dashboard-<bersaglio>`):
#   TARGET_DIR        directory del codice analizzato da TUTTI i moduli (statici e Core)
#   OPENAPI_SPEC_PATH contratto del bersaglio; se assente viene cercato dentro TARGET_DIR
#   TARGET_BASE_URL   URL dell'applicazione in esecuzione (moduli dinamici)
#   OUTPUT_DIR        cartella dei report, separata per bersaglio
# Nessun modulo ricade su file di altri bersagli: senza contratto il Layer OpenAPI viene
# saltato, senza inventario la BOLA dinamica non esegue test.
TARGET_DIR = DEFAULT_TARGET_DIR
TARGET_BASE_URL = DEFAULT_TARGET_BASE_URL
OUTPUT_DIR = DEFAULT_OUTPUT_DIR

# Dashboard unica: invece di una dashboard dedicata per bersaglio, un unico processo cambia
# bersaglio in-process. Il catalogo elenca tutti i bersagli locali (casi di prova, repo target,
# insieme di prova); POST /api/select-target riassegna le variabili qui sopra, lette da tutti
# i moduli. Lo switch è vietato mentre una scansione BOLA è in corso (vedi select_target).
CURRENT_TARGET_ID = (
    target_catalog.match_by_dirs(TARGET_DIR, output_dir=OUTPUT_DIR)
    or target_catalog.default_target_id()
)


def _catalog() -> dict[str, "DashboardTarget"]:
    """Catalogo dei bersagli locali, ricostruito a ogni richiesta.

    Scoperto da ``data/test_targets`` e dal registro esterno: ricostruirlo a ogni richiesta
    tiene conto di cartelle o voci di registro aggiunte senza riavviare la dashboard.
    """
    return target_catalog.build_catalog()


def _apply_target(target: "DashboardTarget") -> None:
    """Rende ``target`` il bersaglio corrente, aggiornando lo stato letto da tutti i moduli."""
    global TARGET_DIR, TARGET_BASE_URL, OUTPUT_DIR, CURRENT_TARGET_ID
    TARGET_DIR = target.target_dir
    TARGET_BASE_URL = target.base_url  # vuoto per i bersagli solo statici
    OUTPUT_DIR = target.output_dir
    CURRENT_TARGET_ID = target.id
    # Il Layer OpenAPI usa il contratto del bersaglio quando c'è, altrimenti lo cerca in TARGET_DIR.
    if target.openapi:
        os.environ["OPENAPI_SPEC_PATH"] = target.openapi
    else:
        os.environ.pop("OPENAPI_SPEC_PATH", None)
    # Il contratto BOLA (identita', seeding, snapshot) e' un'istanza condivisa caricata una volta:
    # va ricaricato dal file del bersaglio, altrimenti la BOLA dinamica userebbe quello precedente.
    try:
        reset_bola_target_config(load_bola_target_config(target.bola_config or None))
    except Exception as e:
        logger.warning(f"Contratto BOLA di {target.id} non caricato ({e}): uso quello di default.")
        reset_bola_target_config(None)
    os.makedirs(OUTPUT_DIR, exist_ok=True)


# Allinea lo stato iniziale al bersaglio del catalogo che corrisponde all'ambiente (o al default).
_bootstrap_catalog = _catalog()
if CURRENT_TARGET_ID in _bootstrap_catalog:
    _apply_target(_bootstrap_catalog[CURRENT_TARGET_ID])


def _out(name: str) -> str:
    """Percorso di un report nella cartella di output del bersaglio corrente."""
    return os.path.join(OUTPUT_DIR, name)


def _report_dir(target_id: str | None) -> str:
    """
    Cartella dei report da leggere: quella del bersaglio corrente se ``target_id`` manca,
    altrimenti quella del bersaglio indicato del catalogo. Serve alle pagine dei risultati per
    mostrare i report salvati di un bersaglio senza renderlo corrente e senza rilanciare scansioni.
    """
    if not target_id or target_id in ("principale", CURRENT_TARGET_ID):
        return OUTPUT_DIR
    target = _catalog().get(target_id)
    if target is None:
        raise HTTPException(status_code=404, detail=f"Bersaglio '{target_id}' sconosciuto.")
    return target.output_dir


def _target_openapi_path() -> str | None:
    explicit = os.getenv("OPENAPI_SPEC_PATH")
    if explicit:
        return explicit if os.path.exists(explicit) else None
    return find_openapi_spec_path(TARGET_DIR)


def _load_target_openapi_spec() -> dict[str, Any] | None:
    path = _target_openapi_path()
    if not path:
        logger.warning(f"Nessun contratto OpenAPI nel bersaglio {TARGET_DIR}: Layer 3 saltato.")
        return None
    return load_openapi_spec([path])


def _target_reachable(base_url: str, timeout: float = 3.0) -> bool:
    import httpx

    if not base_url:
        # Bersagli solo statici: nessuna applicazione da interrogare.
        return False
    try:
        httpx.get(base_url, timeout=timeout)
        return True
    except Exception:
        return False


def _load_api_inventory() -> list[dict[str, Any]]:
    """
    Inventario delle rotte per la BOLA dinamica, letto SOLO dai report del bersaglio
    corrente (inventario della pipeline e findings della scansione statica).
    Nessun ripiego su rotte scritte nel codice: se l'inventario e' vuoto, nessun test.
    """
    import json

    api_inventory: list[dict[str, Any]] = []
    inventory_path = _out("unified_api_inventory.json")
    if os.path.exists(inventory_path):
        try:
            with open(inventory_path, encoding="utf-8") as f:
                for item in json.load(f):
                    path = item.get("path") or item.get("endpoint")
                    if path:
                        method = item.get("method", "GET")
                        api_inventory.append({"api": {"endpoint": path, "method": method}})
        except Exception as e:
            logger.error(f"Errore caricamento inventario API: {e}")
    report_path = _out("unified_security_report.json")
    if os.path.exists(report_path):
        try:
            with open(report_path, encoding="utf-8") as f:
                for fnd in json.load(f):
                    api_ctx = fnd.get("api")
                    if api_ctx and (api_ctx.get("endpoint") or api_ctx.get("path")):
                        api_inventory.append(fnd)
        except Exception as e:
            logger.error(f"Errore integrazione report di sicurezza: {e}")
    if not api_inventory:
        logger.warning(
            "Inventario API vuoto per il bersaglio corrente: eseguire prima la scansione "
            "statica (/scan). La BOLA dinamica non eseguira' test."
        )
    return api_inventory


app = FastAPI(
    title="Security Platform Core API",
    description="Enterprise API and Infrastructure Risk Management Platform",
    version="1.0.0",
)

# Sezione "Bersagli esterni" (validation/PROTOCOLLO.md): solo nella dashboard principale,
# non in quelle dedicate a un bersaglio, che la avviano con EXTERNAL_TARGETS_PANEL=0.
if os.getenv("EXTERNAL_TARGETS_PANEL", "1") != "0":
    app.include_router(external_targets.router)


# Registro delle scansioni BOLA in corso: ogni orchestratore porta il proprio segnale di
# cancellazione, cosi' due scansioni concorrenti non si annullano a vicenda e nessun flag
# resta "sporco" tra un run e l'altro (ADR: niente stato a livello di classe).
_active_bola_scans: dict[str, "DynamicOrchestrator"] = {}
_active_bola_scans_lock = threading.Lock()


def _new_scan_id() -> str:
    return uuid.uuid4().hex[:12]


def _register_bola_scan(scan_id: str, orchestrator: "DynamicOrchestrator") -> None:
    with _active_bola_scans_lock:
        _active_bola_scans[scan_id] = orchestrator


def _unregister_bola_scan(scan_id: str) -> None:
    with _active_bola_scans_lock:
        _active_bola_scans.pop(scan_id, None)


def _cancel_bola_scans(scan_id: str | None = None) -> list[str]:
    """
    Cancella la scansione BOLA indicata oppure, senza scan_id, tutte quelle attive.
    Ritorna gli id effettivamente cancellati (vuoto se lo scan_id non e' registrato).
    """
    with _active_bola_scans_lock:
        if scan_id is None:
            targets = dict(_active_bola_scans)
        else:
            orchestrator = _active_bola_scans.get(scan_id)
            targets = {scan_id: orchestrator} if orchestrator is not None else {}
    for orchestrator in targets.values():
        orchestrator.cancel()
    return list(targets)


def _serve_template(template_name: str, fallback_title: str) -> HTMLResponse:
    template_path = f"src/presentation/web/templates/{template_name}"
    if os.path.exists(template_path):
        with open(template_path, encoding="utf-8") as f:
            html_content = f.read()
    else:
        html_content = f"<h1>{fallback_title} Not Found</h1>"
    return HTMLResponse(content=html_content)


@app.get("/", response_class=HTMLResponse, tags=["UI"])
def serve_dashboard() -> HTMLResponse:
    """Ritorna la dashboard iniziale in stile glassmorphism per il controllo sicurezza."""
    return _serve_template("dashboard.html", "Dashboard Template")


@app.get("/results", response_class=HTMLResponse, tags=["UI"])
def serve_results() -> HTMLResponse:
    """Ritorna la pagina dei risultati in stile glassmorphism per Checkov."""
    return _serve_template("results.html", "Results Template")


@app.get("/api-results", response_class=HTMLResponse, tags=["UI"])
def serve_api_results() -> HTMLResponse:
    """Ritorna la pagina dei risultati per l'Analisi del Codice (Semgrep)."""
    return _serve_template("api_results.html", "API Results Template")


@app.get("/contract-results", response_class=HTMLResponse, tags=["UI"])
def serve_contract_results() -> HTMLResponse:
    """Ritorna la pagina dei risultati per la conformità del contratto OpenAPI (Spectral)."""
    return _serve_template("contract_results.html", "Contract Validation Results Template")


@app.get("/bola-results", response_class=HTMLResponse, tags=["UI"])
def serve_bola_results() -> HTMLResponse:
    """Ritorna la pagina dei risultati del test differenziale BOLA/IDOR."""
    return _serve_template("bola_results.html", "BOLA Results Template")


@app.get("/unified-results", response_class=HTMLResponse, tags=["UI"])
def serve_unified_results() -> HTMLResponse:
    """Ritorna la pagina dei risultati per le scansioni unificate/veloci dei moduli Core."""
    return _serve_template("unified_results.html", "Unified Results Template")


@app.post("/bola-scan", response_model=dict[str, Any], tags=["Scanning"])
def run_bola_scan() -> dict[str, Any]:
    """
    Esegue la pipeline completa di BOLA tramite il modulo reale DynamicOrchestrator.
    Configura le identità tramite Keycloak, esegue il seeding ed effettua il differential testing.
    """
    import json
    import time
    from datetime import datetime, timezone

    from src.core.api1_bola.dynamic_orchestrator import DynamicOrchestrator

    start_t = time.time()
    start_time = datetime.now(timezone.utc)
    scan_id = _new_scan_id()

    try:
        # Istanza dell'orchestratore reale configurato con i container attivi
        dast_orchestrator = DynamicOrchestrator(
            target_base_url=TARGET_BASE_URL,
            keycloak_url=DEFAULT_KEYCLOAK_URL,
            zap_proxy_url=DEFAULT_ZAP_URL,
            assessment_mode=False,
            require_real_identities=True,
        )
        _register_bola_scan(scan_id, dast_orchestrator)

        api_inventory = _load_api_inventory()

        # Carica traffico reale intercettato: alimenta la discovery degli ID in
        # query/body (ObjectReferenceDiscoveryEngine) e l'ownership inference.
        raw_traffic = None
        traffic_path = _out("raw_traffic.json")
        if os.path.exists(traffic_path):
            try:
                with open(traffic_path, encoding="utf-8") as f:
                    raw_traffic = json.load(f)
            except Exception as e:
                logger.error(f"Errore caricamento traffico: {e}")

        # Esegue la pipeline reale D-AST (Keycloak, Seeder, ZAP controller)
        try:
            dast_orchestrator.run_dast_pipeline(
                api_inventory=api_inventory, output_dir=OUTPUT_DIR, raw_traffic=raw_traffic
            )
        finally:
            _unregister_bola_scan(scan_id)

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
            resource_name = extract_resource_name_from_path(path)

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
                    "attacker": res.get("attacker_role") or "anonymous",
                    "attacker_role": res.get("attacker_role", "user"),
                    "owner": res.get("owner_role", "user"),
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
            "scan_id": scan_id,
            "started_at": start_time.isoformat(),
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": elapsed,
            "target_url": dast_orchestrator.target_base_url,
            "mode": "LIVE",
            "cancelled": dast_orchestrator.is_cancelled,
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
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        with open(_out("bola_scan_results.json"), "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        return report
    except Exception as e:
        _unregister_bola_scan(scan_id)
        logger.error(f"Errore durante BOLA scan: {e}", exc_info=True)
        return {
            "meta": {
                "scan_id": scan_id,
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
def cancel_bola_scan(scan_id: str | None = None) -> dict[str, Any]:
    """
    Interrompe una scansione BOLA in corso tramite il suo segnale di cancellazione.

    Con `scan_id` viene fermata solo quella scansione; senza (es. beacon di `beforeunload`
    della dashboard, che non conosce l'id perche' `/bola-scan` e' sincrono) vengono fermate
    tutte le scansioni attive. Non tocca alcuno stato globale: una scansione conclusa non
    lascia flag sporchi per quella successiva.
    """
    cancelled = _cancel_bola_scans(scan_id)
    if scan_id is not None and not cancelled:
        logger.info(f"Cancellazione BOLA ignorata: nessuna scansione attiva con id {scan_id}.")
        return {"status": "not_found", "scan_ids": []}
    logger.info(
        "🛑 Ricevuto segnale di cancellazione per la scansione BOLA "
        f"({len(cancelled)} in corso). Interruzione in corso..."
    )
    return {"status": "cancelled", "scan_ids": cancelled}


@app.get("/api/bola-scan/active", tags=["Scanning"])
def list_active_bola_scans() -> dict[str, Any]:
    """Elenca gli id delle scansioni BOLA attualmente in corso (utile per cancellazioni mirate)."""
    with _active_bola_scans_lock:
        return {"scan_ids": list(_active_bola_scans)}


@app.get("/api/bola-report", response_model=dict[str, Any], tags=["Scanning"])
def get_bola_report(target: str | None = None) -> dict[str, Any]:
    """Ritorna l'ultimo report BOLA salvato (del bersaglio corrente o di ``target``)."""
    default = {"meta": {"total_tests": 0, "vulnerable_count": 0, "safe_count": 0}, "results": []}
    return safe_read_json(os.path.join(_report_dir(target), "bola_scan_results.json"), default)


@app.get("/api/openapi-spec", tags=["Scanning"])
def get_openapi_spec(target: str | None = None) -> dict[str, str]:
    """
    Ritorna il contenuto del contratto OpenAPI unito (del bersaglio corrente o di ``target``).
    """
    spec_path = os.path.join(_report_dir(target), "openapi_merged.yaml")
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
    Inizializza e ritorna l'orchestratore di scansione per la directory bersaglio (TARGET_DIR).

    Returns:
        ScanPipelineOrchestrator: Istanza configurata dell'orchestratore.
    """
    # Il bersaglio e' la directory target configurata (TARGET_DIR), mai la radice
    # della piattaforma: e' il perimetro che gli scanner ricevono in scan().
    return ScanPipelineOrchestrator(
        target_dir=TARGET_DIR, correlation_engine=RiskCorrelationEngine()
    )


@app.get("/health", tags=["System"])
def health_check() -> dict[str, str]:
    """
    Ritorna lo stato dell'applicazione.

    Returns:
        Dict[str, str]: Mappa di stato di salute.
    """
    return {"status": "healthy", "service": "security-platform-core"}


@app.get("/api/target", tags=["System"])
def get_current_target() -> dict[str, Any]:
    """Bersaglio su cui lavora questa istanza della dashboard (fissato all'avvio)."""
    return {
        "target_dir": TARGET_DIR,
        "openapi_spec": _target_openapi_path(),
        "target_base_url": TARGET_BASE_URL,
        "target_reachable": _target_reachable(TARGET_BASE_URL),
        "output_dir": OUTPUT_DIR,
    }


@app.post("/scan", response_model=list[dict[str, Any]], tags=["Scanning"])
def trigger_scan(
    scanners: list[Any] = Depends(get_static_scanners),
    orchestrator: ScanPipelineOrchestrator = Depends(get_orchestrator),
) -> list[dict[str, Any]]:
    """
    Avvia la pipeline statica, correla i rischi e ritorna l'inventario unificato
    dei findings.

    Args:
        scanners: Lista di scanner iniettati come dipendenza.
        orchestrator: Istanza dell'orchestratore iniettata.

    Returns:
        List[Dict[str, Any]]: Lista serializzata in dizionari dei Finding correlati.
    """
    correlated_findings = orchestrator.run_pipeline(static_scanners=scanners)

    # Salviamo i report
    report_repo = ReportRepository(OUTPUT_DIR)
    report_repo.save_findings(correlated_findings, filename="findings_report.json")
    report_repo.save_findings(correlated_findings, filename="unified_security_report.json")

    return [f.to_dict() for f in correlated_findings]


@app.get("/api/report", response_model=list[dict[str, Any]], tags=["Scanning"])
def get_unified_report(target: str | None = None) -> list[dict[str, Any]]:
    """
    Ritorna i findings dell'ultimo report statico unificato (Checkov, Semgrep, Spectral) del
    bersaglio corrente o di ``target``.
    """
    return safe_read_json(os.path.join(_report_dir(target), "unified_security_report.json"), [])


@app.get("/api/unified-summary", response_model=dict[str, Any], tags=["Scanning"])
def get_unified_summary() -> dict[str, Any]:
    """Ritorna una sintesi dell'ultima scansione unificata dei moduli Core."""
    return _benchmark_summary(_out("benchmark_results.json"))


@app.get("/api/targets", response_model=dict[str, Any], tags=["System"])
def list_targets_with_results() -> dict[str, Any]:
    """
    Bersagli selezionabili dalla dashboard principale, ciascuno con la sintesi dell'ultima
    scansione letta dalla propria cartella dei report. Il bersaglio principale e' quello di
    questa istanza; quelli esterni vengono dal registro e si scansionano nella loro dashboard
    dedicata (POST /api/external-targets/{id}/scan). Nelle dashboard dedicate, che non
    mostrano la sezione Bersagli esterni, l'elenco contiene solo il bersaglio corrente.
    """
    targets = []
    for target in _catalog().values():
        targets.append(
            {
                "id": target.id,
                "label": target.label,
                "group": target.group,
                "external": target.external,
                "target_dir": target.target_dir,
                "base_url": target.base_url,
                "output_dir": target.output_dir,
                "has_app": target.has_app,
                "note": target.note,
                "current": target.id == CURRENT_TARGET_ID,
                "results_url": f"/unified-results?target={target.id}",
                "summary": _benchmark_summary(
                    os.path.join(target.output_dir, "benchmark_results.json")
                ),
                "static": _static_summary(target.output_dir),
            }
        )
    return {
        "targets": targets,
        "current": CURRENT_TARGET_ID,
        "groups": list(target_catalog.GROUP_ORDER),
    }


@app.post("/api/select-target", response_model=dict[str, Any], tags=["System"])
def select_target(id: str) -> dict[str, Any]:
    """
    Rende ``id`` il bersaglio corrente della dashboard (switch in-process).

    Lo switch è rifiutato con 409 se una scansione BOLA è in corso: cambiare bersaglio a
    metà scansione la farebbe proseguire sul bersaglio sbagliato. È la stessa garanzia che
    il vecchio flusso otteneva con una dashboard separata per bersaglio.
    """
    target = _catalog().get(id)
    if target is None:
        raise HTTPException(status_code=404, detail=f"Bersaglio '{id}' sconosciuto.")
    with _active_bola_scans_lock:
        busy = list(_active_bola_scans)
    if busy:
        raise HTTPException(
            status_code=409,
            detail="Scansione BOLA in corso: attendere la fine prima di cambiare bersaglio.",
        )
    _apply_target(target)
    logger.info(f"Bersaglio corrente: {target.id} ({target.target_dir})")
    return {
        "current": CURRENT_TARGET_ID,
        "label": target.label,
        "target_dir": TARGET_DIR,
        "base_url": TARGET_BASE_URL,
        "output_dir": OUTPUT_DIR,
        "target_reachable": _target_reachable(TARGET_BASE_URL),
    }


@app.get("/api/targets/{target_id}/findings", response_model=dict[str, Any], tags=["Scanning"])
def get_target_findings(target_id: str) -> dict[str, Any]:
    """
    Findings dell'ultima scansione unificata di un bersaglio, modulo per modulo, letti da
    core_findings.json nella sua cartella dei report: la pagina dei risultati li mostra
    senza rilanciare la scansione.
    """
    if target_id in ("principale", CURRENT_TARGET_ID):
        catalog = _catalog()
        target = catalog.get(CURRENT_TARGET_ID)
        label, output_dir = (target.label if target else CURRENT_TARGET_ID), OUTPUT_DIR
        target_dir, base_url = TARGET_DIR, TARGET_BASE_URL
    else:
        target = _catalog().get(target_id)
        if target is None:
            raise HTTPException(status_code=404, detail=f"Bersaglio '{target_id}' sconosciuto.")
        label, output_dir = target.label, target.output_dir
        target_dir, base_url = target.target_dir, target.base_url

    evidence = safe_read_json(os.path.join(output_dir, "core_findings.json"), {})
    if not isinstance(evidence, dict) or not evidence.get("modules"):
        # Scansioni precedenti a core_findings.json: solo l'esito per modulo.
        evidence = {"modules": safe_read_json(os.path.join(output_dir, "benchmark_results.json"))}
    return {
        "id": target_id,
        "label": label,
        "target_dir": evidence.get("target_dir", target_dir),
        "openapi_spec": evidence.get("openapi_spec"),
        "target_base_url": evidence.get("target_base_url", base_url),
        "output_dir": output_dir,
        "generated_at": evidence.get("generated_at"),
        "modules": evidence.get("modules") or [],
        "findings": evidence.get("findings") or {},
    }


def _static_summary(output_dir: str) -> dict[str, Any]:
    """
    Sintesi dell'ultima analisi statica (unified_security_report.json): findings per scanner,
    cosi' la dashboard mostra se l'analisi IaC (Checkov) e' stata eseguita sul bersaglio.
    """
    report_path = os.path.join(output_dir, "unified_security_report.json")
    findings = safe_read_json(report_path, [])
    if not os.path.exists(report_path) or not isinstance(findings, list):
        return {"available": False, "generated_at": None, "total": 0, "by_source": {}}
    by_source: dict[str, int] = {}
    for finding in findings:
        source = finding.get("source") or "ALTRO"
        by_source[source] = by_source.get(source, 0) + 1
    return {
        "available": True,
        "generated_at": datetime.fromtimestamp(os.path.getmtime(report_path)).isoformat(),
        "total": len(findings),
        "by_source": by_source,
    }


def _benchmark_summary(report_path: str) -> dict[str, Any]:
    """Sintesi di un benchmark_results.json: esito per modulo, findings e durata totali."""
    # safe_read_json rende [] (non None) per un file assente: bersaglio mai scansionato
    modules = safe_read_json(report_path, [])

    if not isinstance(modules, list) or not modules:
        return {"available": False, "generated_at": None, "totals": {}, "modules": []}

    executed = [m for m in modules if m.get("status") != "SKIPPED"]
    return {
        "available": True,
        "generated_at": datetime.fromtimestamp(os.path.getmtime(report_path)).isoformat(),
        "totals": {
            "modules": len(modules),
            "executed": len(executed),
            "findings": sum(m.get("findings", 0) for m in modules),
            "failed": len([m for m in modules if m.get("status") not in ("SUCCESS", "SKIPPED")]),
            "elapsed_seconds": round(sum(m.get("time", 0.0) for m in modules), 2),
        },
        "modules": modules,
    }


@app.get("/api/benchmark-report", response_model=list[dict[str, Any]], tags=["Scanning"])
def get_benchmark_report() -> list[dict[str, Any]]:
    """Ritorna i risultati dell'esecuzione e benchmark di tutti i moduli di sicurezza Core."""
    return safe_read_json(_out("benchmark_results.json"), [])


async def execute_benchmark_scan(run_bola: bool) -> dict[str, Any]:
    import json
    import time
    from pathlib import Path

    from src.core.api2_broken_auth import ast_parser as ba_ast_parser
    from src.core.api2_broken_auth import authentication_intelligence as ba_auth_intel
    from src.core.api2_broken_auth import discovery as ba_discovery
    from src.core.api2_broken_auth import dynamic_tester as ba_dynamic_tester
    from src.core.api2_broken_auth.discovery import Config as BaConfig
    from src.core.api3_bopla.orchestrator import BOPLAOrchestrator, to_dashboard_items
    from src.core.api4_resource_consumption import detector as urc_detector
    from src.core.api5_bfla import detector as bfla_detector
    from src.core.api7_ssrf import detector as ssrf_detector
    from src.core.api8_security_misconfig import detector as secmis_detector
    from src.core.api10_unsafe_consumption import detector as uc_detector

    openapi_spec = _load_target_openapi_spec()
    runtime_traffic = safe_read_json(_out("raw_traffic.json"), None)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    benchmark_path = _out("benchmark_results.json")
    results = []
    findings_by_module = {}

    def serialize_finding(f) -> dict[str, Any]:
        if hasattr(f, "to_dict"):
            return f.to_dict()
        # Serializzazione completa (metodo, endpoint, chiave di correlazione inclusi): servono
        # per confrontare ogni segnalazione con il riferimento di verita'.
        import dataclasses

        if dataclasses.is_dataclass(f) and not isinstance(f, type):
            from fastapi.encoders import jsonable_encoder

            return jsonable_encoder(dataclasses.asdict(f))
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
            BaConfig(output=ba_discovery.OutputConfig(path=OUTPUT_DIR))
        ).run_assessment(
            repo_path=TARGET_DIR,
            openapi_spec=openapi_spec,
            runtime_traffic=runtime_traffic,
            headers_matrix=None,
        )
        # Confirmed dynamic tests plus the static findings (the only output when, as here,
        # no identity matrix is passed and the dynamic phase does not run)
        bopla_list = to_dashboard_items(bopla_data)
        findings_count = len(bopla_list)
        status = "SUCCESS"
    except Exception as e:
        findings_count = 0
        status = f"FAILED: {e}"
    results.append(
        {
            "name": "BOPLA (Broken Object Property Level Access)",
            "dir": "src/core/api3_bopla",
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
            api_inventory = _load_api_inventory()

            from src.core.api1_bola.dynamic_orchestrator import DynamicOrchestrator

            dast_orchestrator = DynamicOrchestrator(
                target_base_url=TARGET_BASE_URL,
                keycloak_url=DEFAULT_KEYCLOAK_URL,
                zap_proxy_url=DEFAULT_ZAP_URL,
                assessment_mode=False,
                require_real_identities=True,
            )
            scan_id = _new_scan_id()
            _register_bola_scan(scan_id, dast_orchestrator)
            try:
                dast_orchestrator.run_dast_pipeline(
                    api_inventory=api_inventory, output_dir=OUTPUT_DIR, raw_traffic=runtime_traffic
                )
            finally:
                _unregister_bola_scan(scan_id)
            # Estrae e formatta i risultati BOLA (tutti i test, non solo i vulnerabili)
            total_tests = len(dast_orchestrator.zap_controller.test_results)
            for res in dast_orchestrator.zap_controller.test_results:
                is_vuln = res.get("is_vulnerable", False)
                path = res.get("path", "")
                resource_name = extract_resource_name_from_path(path)
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
                        "evidence": (
                            "Nessun test BOLA eseguito: inventario API del bersaglio vuoto "
                            "(eseguire prima /scan) oppure ZAP/bersaglio non raggiungibili."
                        ),
                    }
                )
            status = "SUCCESS"
        except Exception as e:
            findings_count = 0
            status = f"FAILED: {e}"
        results.append(
            {
                "name": "BOLA (Broken Object Level Authorization)",
                "dir": "src/core/api1_bola",
                "time": time.time() - start_bola,
                "status": status,
                "findings": findings_count,
            }
        )
    else:
        results.append(
            {
                "name": "BOLA (Broken Object Level Authorization)",
                "dir": "src/core/api1_bola",
                "time": 0.0,
                "status": "SKIPPED",
                "findings": 0,
            }
        )
    findings_by_module["bola"] = bola_list

    # 1.6. BOLA - livello statico (codice + contratto). Non richiede container.
    start = time.time()
    bola_static_list = []
    try:
        from src.core.api1_bola import detector as bola_static_detector

        report = bola_static_detector.analyze(TARGET_DIR, openapi_spec)
        bola_static_list = [serialize_finding(f) for f in report.findings]
        findings_count = len(bola_static_list)
        status = "SUCCESS"
    except Exception as e:
        findings_count = 0
        status = f"FAILED: {e}"
    results.append(
        {
            "name": "BOLA statica (Broken Object Level Authorization)",
            "dir": "src/core/api1_bola",
            "time": time.time() - start,
            "status": status,
            "findings": findings_count,
        }
    )
    findings_by_module["bola_static"] = bola_static_list

    # 2. Broken Authentication
    start = time.time()
    ba_list = []
    try:
        config = BaConfig()
        config.target.base_url = TARGET_BASE_URL
        config.output.path = OUTPUT_DIR
        config.output.formato = "json"

        # Stack rilevato sul bersaglio (euristiche deterministiche se l'LLM non e' attivo),
        # non piu' fissato a FastAPI.
        stack = await ba_discovery.run(TARGET_DIR, config)
        scored_files = await ba_ast_parser.run(TARGET_DIR, stack, config)
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

        # Fase dinamica SOLO contro il bersaglio reale. Prima un client simulato rispondeva
        # sempre 401 e i risultati non dicevano nulla del bersaglio: ora, se il bersaglio
        # non risponde, la fase dinamica non viene eseguita e lo stato lo dichiara.
        if not _target_reachable(TARGET_BASE_URL):
            raise RuntimeError(
                f"fase dinamica non eseguita: bersaglio non raggiungibile su {TARGET_BASE_URL}"
            )
        tester = ba_dynamic_tester.DynamicTester(
            config, auth_intel=auth_intel, openapi_spec=openapi_spec
        )
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
            "dir": "src/core/api2_broken_auth",
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
        report = bfla_detector.analyze(TARGET_DIR, openapi_spec)
        bfla_list = [serialize_finding(f) for f in report.findings]
        findings_count = len(bfla_list)
        status = "SUCCESS"
    except Exception as e:
        findings_count = 0
        status = f"FAILED: {e}"
    results.append(
        {
            "name": "BFLA (Broken Function Level Authorization)",
            "dir": "src/core/api5_bfla",
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
        report = secmis_detector.analyze(TARGET_DIR)
        secmis_list = [serialize_finding(f) for f in report.findings]
        findings_count = len(secmis_list)
        status = "SUCCESS"
    except Exception as e:
        findings_count = 0
        status = f"FAILED: {e}"
    results.append(
        {
            "name": "Security Misconfiguration",
            "dir": "src/core/api8_security_misconfig",
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
        report = ssrf_detector.analyze(TARGET_DIR, openapi_spec)
        ssrf_list = [serialize_finding(f) for f in report.findings]
        findings_count = len(ssrf_list)
        status = "SUCCESS"
    except Exception as e:
        findings_count = 0
        status = f"FAILED: {e}"
    results.append(
        {
            "name": "SSRF (Server Side Request Forgery)",
            "dir": "src/core/api7_ssrf",
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
        report = urc_detector.analyze(TARGET_DIR, openapi_spec)
        urc_list = [serialize_finding(f) for f in report.findings]
        findings_count = len(urc_list)
        status = "SUCCESS"
    except Exception as e:
        findings_count = 0
        status = f"FAILED: {e}"
    results.append(
        {
            "name": "Unrestricted Resource Consumption",
            "dir": "src/core/api4_resource_consumption",
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
        report = uc_detector.analyze(TARGET_DIR)
        uc_list = [serialize_finding(f) for f in report.findings]
        findings_count = len(uc_list)
        status = "SUCCESS"
    except Exception as e:
        findings_count = 0
        status = f"FAILED: {e}"
    results.append(
        {
            "name": "Unsafe Consumption",
            "dir": "src/core/api10_unsafe_consumption",
            "time": time.time() - start,
            "status": status,
            "findings": findings_count,
        }
    )
    findings_by_module["unsafe_consumption"] = uc_list

    try:
        with open(benchmark_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        # Evidenza completa dell'esecuzione: tutte le segnalazioni, modulo per modulo, con il
        # bersaglio e il contratto effettivamente usati.
        from fastapi.encoders import jsonable_encoder

        with open(_out("core_findings.json"), "w", encoding="utf-8") as f:
            json.dump(
                jsonable_encoder(
                    {
                        "generated_at": datetime.now().isoformat(),
                        "target_dir": TARGET_DIR,
                        "openapi_spec": _target_openapi_path(),
                        "target_base_url": TARGET_BASE_URL,
                        "modules": results,
                        "findings": findings_by_module,
                    }
                ),
                f,
                indent=2,
                ensure_ascii=False,
            )
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
