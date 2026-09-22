import logging

from src.application.correlation.engine import RiskCorrelationEngine
from src.domain.entities import Finding
from src.domain.interfaces import IScanner

logger = logging.getLogger("SecurityPlatform.Orchestrator")


class ScanPipelineOrchestrator:
    """
    Orchestratore della pipeline statica.
    Esegue gli scanner registrati sul bersaglio e consegna le segnalazioni al motore di
    correlazione, che le aggrega per chiave e assegna a ciascuna il punteggio di rischio.
    """

    def __init__(self, target_dir: str, correlation_engine: RiskCorrelationEngine):
        """
        Inizializza l'orchestratore con le sue dipendenze e imposta la cartella target.

        Args:
            target_dir (str): Percorso della cartella target da analizzare.
            correlation_engine (RiskCorrelationEngine): Istanza del motore di correlazione.
        """
        self.target_dir = target_dir
        self.correlation_engine = correlation_engine

        # Stato condiviso durante l'esecuzione del pipeline
        self.static_findings: list[Finding] = []
        self.runtime_findings: list[Finding] = []

    def run_pipeline(self, static_scanners: list[IScanner]) -> list[Finding]:
        """
        Esegue il workflow statico:
        1. Esegue gli scanner registrati (Checkov, Semgrep, Spectral) sul bersaglio.
        2. Correla i findings e calcola il punteggio di rischio di ciascuno.

        Le segnalazioni a runtime (D-AST, ZAP) vengono aggiunte dal chiamante in una
        seconda correlazione, dopo la fase dinamica.

        Args:
            static_scanners (List[IScanner]): Lista delle istanze degli scanner statici da eseguire.

        Returns:
            List[Finding]: Lista finale dei Finding correlati e ordinati per punteggio di rischio.
        """
        logger.info("🎬 Avvio Pipeline di Security Detection e Risk Correlation...")
        self.static_findings = []
        self.runtime_findings = []

        # 1. Esecuzione Scansioni Statiche di Infrastruttura/AST
        logger.info("🔍 [Fase 1] Esecuzione Scanners Statici Core...")
        for scanner in static_scanners:
            try:
                findings = scanner.scan(self.target_dir)
                self.static_findings.extend(findings)
                logger.info(
                    f"   - Scanner {scanner.__class__.__name__} ha rilevato {len(findings)} findings."
                )
            except Exception as e:
                logger.error(
                    f"   - Fallimento dello scanner {scanner.__class__.__name__}: {e}",
                    exc_info=True,
                )

        # 2. Correlazione dei rischi e calcolo scoring pesato
        logger.info("⚙️ [Fase 2] Correlazione e Calcolo dei Rischi Centralizzato...")
        correlated_results = self.correlation_engine.correlate(
            self.static_findings, self.runtime_findings
        )

        # Ricalcola lo score di rischio per ciascun finding finale correlato
        for finding in correlated_results:
            score = self.correlation_engine.calculate_risk_score(finding)
            finding.raw_data["correlated_risk_score"] = score

        logger.info(f"🏆 Pipeline completata. Totale findings correlati: {len(correlated_results)}")
        return correlated_results
