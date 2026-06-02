from fastapi import FastAPI, Depends, BackgroundTasks
from typing import List, Dict, Any
from src.domain.entities import Finding
from src.application.orchestrator import ScanPipelineOrchestrator
from src.infrastructure.adapters.checkov_adapter import CheckovScannerAdapter
from src.infrastructure.adapters.semgrep_adapter import SemgrepScannerAdapter
from src.infrastructure.persistence/report_repository import ReportRepository

app = FastAPI(
    title="Security Platform Core API",
    description="Enterprise API and Infrastructure Risk Management Platform",
    version="1.0.0"
)


# Dependency Injection per gli scanner
def get_static_scanners() -> List[Any]:
    """
    Ritorna la lista delle istanze concrete degli scanner statici.

    Returns:
        List[Any]: Lista di adattatori per l'analisi statica.
    """
    return [
        CheckovScannerAdapter(),
        SemgrepScannerAdapter()
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
    report_repo.save_findings(correlated_findings)
    
    return [f.to_dict() for f in correlated_findings]
