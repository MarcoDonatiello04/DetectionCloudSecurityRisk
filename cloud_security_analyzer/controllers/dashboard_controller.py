"""
Elabora e coordina i dati della dashboard.
Responsabilità:
- Tradurre i modelli aggregati di rischio in formati consumabili dai grafici (liste, dizionari di percentuali).
- Esporre metriche globali (vulnerabilità confermate, conformità, stato BOLA).
- Indicizzare lo storico delle scansioni precedenti tramite ScanService.
"""

from typing import Dict, Any, List
from cloud_security_analyzer.services.state_service import StateService
from cloud_security_analyzer.services.scan_service import ScanService

class DashboardController:
    """
    Controller preposto ad alimentare i widget riassuntivi e grafici della Dashboard.
    """

    def __init__(self, state_service: StateService, scan_service: ScanService = None):
        self.state = state_service
        self.scan_service = scan_service

    def get_severity_distribution(self) -> Dict[str, int]:
        """
        Ritorna il dizionario per alimentare il DonutChart.
        """
        risk = self.state.risk_model
        if not risk:
            return {}
        return {
            "CRITICAL": risk.critical_count,
            "HIGH": risk.high_count,
            "MEDIUM": risk.medium_count,
            "LOW": risk.low_count,
            "INFO": risk.info_count
        }

    def get_source_distribution(self) -> Dict[str, int]:
        """
        Ritorna la distribuzione per sorgente di scanner per alimentare il BarChart.
        """
        risk = self.state.risk_model
        if not risk:
            return {}
        return {
            "CHECKOV": risk.stats.get("checkov_total", 0),
            "SEMGREP": risk.stats.get("semgrep_total", 0),
            "SPECTRAL": risk.stats.get("spectral_total", 0),
            "RUNTIME": risk.stats.get("runtime_total", 0),
            "ZAP": risk.stats.get("zap_total", 0)
        }

    def get_summary_metrics(self) -> Dict[str, Any]:
        """
        Ritorna valori aggregati per le RiskCard riassuntive.
        """
        risk = self.state.risk_model
        if not risk:
            return {
                "risk_score": "0.0",
                "risk_status": "N/A",
                "total_findings": "0",
                "confirmed_findings": "0",
                "api_compliance": "100%",
                "shadow_apis": "0",
                "bola_vulnerabilities": "0"
            }
        
        # Calcolo conformità API = (Documentati / Totale) * 100
        api_total = risk.stats.get("api_total", 0)
        api_doc = risk.stats.get("api_documented", 0)
        compliance_pct = "100%"
        if api_total > 0:
            compliance_pct = f"{int((api_doc / api_total) * 100)}%"

        return {
            "risk_score": f"{risk.global_risk_score}/10",
            "risk_status": risk.status_summary,
            "total_findings": str(risk.total_findings),
            "confirmed_findings": str(risk.confirmed_count),
            "api_compliance": compliance_pct,
            "shadow_apis": str(risk.stats.get("api_shadow", 0)),
            "bola_vulnerabilities": str(risk.stats.get("bola_vulnerable", 0))
        }

    def get_historical_scans(self) -> List[Dict[str, Any]]:
        """
        Interroga lo ScanService per elencare lo storico delle scansioni precedenti.
        """
        if self.scan_service:
            return self.scan_service.list_historical_scans()
        return []
