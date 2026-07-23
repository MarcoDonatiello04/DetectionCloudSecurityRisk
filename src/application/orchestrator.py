import logging
from typing import Any

from src.application.correlation.engine import RiskCorrelationEngine
from src.application.plugin_loader import PluginLoader
from src.domain.entities import Finding, FindingSource
from src.domain.events import (
    EVENT_FINDING_DETECTED,
    EVENT_PIPELINE_COMPLETED,
    EVENT_STATIC_SCAN_COMPLETED,
    EVENT_TRAFFIC_CAPTURED,
)
from src.domain.interfaces import IDetector, IEventBus, IScanner

logger = logging.getLogger("SecurityPlatform.Orchestrator")


class ScanPipelineOrchestrator:
    """
    Orchestratore Centralizzato del Flusso Event-Driven.
    Inizializza il bus, carica i plugin, esegue gli scanner di infrastruttura statici,
    invia i dati del traffico e coordina la correlazione finale dei rischi.
    """

    def __init__(
        self,
        target_dir: str,
        event_bus: IEventBus,
        plugin_loader: PluginLoader,
        correlation_engine: RiskCorrelationEngine,
    ):
        """
        Inizializza l'orchestratore con le sue dipendenze e imposta la cartella target.

        Args:
            target_dir (str): Percorso della cartella target da analizzare.
            event_bus (IEventBus): Istanza del bus degli eventi.
            plugin_loader (PluginLoader): Istanza del caricatore di plugin.
            correlation_engine (RiskCorrelationEngine): Istanza del motore di correlazione.
        """
        self.target_dir = target_dir
        self.event_bus = event_bus
        self.plugin_loader = plugin_loader
        self.correlation_engine = correlation_engine

        # Stato condiviso durante l'esecuzione del pipeline
        self.detected_findings: list[Finding] = []
        self.static_findings: list[Finding] = []
        self.runtime_findings: list[Finding] = []

        # Sottoscrizione al bus per accumulare i findings generati dai detector
        self.event_bus.subscribe(EVENT_FINDING_DETECTED, self._on_finding_detected)

    def _on_finding_detected(self, event: Any) -> None:
        """
        Callback eseguita quando un detector pubblica un Finding sul bus.

        Args:
            event (DomainEvent): L'evento intercettato contenente il Finding nel payload.
        """
        finding = event.payload
        if isinstance(finding, Finding):
            self.detected_findings.append(finding)
            logger.debug(
                f"📥 Ricevuto Finding via Event Bus: [{finding.severity.value}] {finding.title} ({finding.finding_id})"
            )

    def run_pipeline(
        self, static_scanners: list[IScanner], raw_traffic_data: list[dict[str, Any]] | None = None
    ) -> list[Finding]:
        """
        Esegue il workflow completo:
        1. Carica i detector plugins e li registra sull'Event Bus.
        2. Esegue gli scanner statici di infrastruttura (Checkov, Semgrep).
        3. Emette EVENT_STATIC_SCAN_COMPLETED sul bus.
        4. Se c'è traffico di rete, emette EVENT_TRAFFIC_CAPTURED.
        5. I detector (iscritti ai vari eventi) analizzano i dati e sollevano FindingDetected.
        6. Correla tutti i findings statici, rilevati dai detector e runtime.
        7. Emette EVENT_PIPELINE_COMPLETED.

        Args:
            static_scanners (List[IScanner]): Lista delle istanze degli scanner statici da eseguire.
            raw_traffic_data (List[Dict[str, Any]], optional): Dati sul traffico di rete catturato.

        Returns:
            List[Finding]: Lista finale dei Finding correlati e ordinati per punteggio di rischio.
        """
        logger.info("🎬 Avvio Pipeline di Security Detection ed Event Correlation...")
        self.detected_findings = []
        self.static_findings = []
        self.runtime_findings = []

        # 1. Caricamento dinamico dei detector e binding sull'Event Bus
        detectors = self.plugin_loader.load_detectors()
        self._register_detector_handlers(detectors)

        # 2. Esecuzione Scansioni Statiche di Infrastruttura/AST
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

        # 3. Notifica il completamento dell'analisi statica
        # Questo evento sveglierà i detector registrati per l'analisi statica/euristica (es. BOLA statico)
        logger.info("📢 [Fase 2] Pubblicazione EVENT_STATIC_SCAN_COMPLETED...")
        self.event_bus.publish(
            EVENT_STATIC_SCAN_COMPLETED,
            {
                "target_dir": self.target_dir,
                "static_findings": [finding.to_dict() for finding in self.static_findings],
            },
        )

        # 4. Elaborazione e pubblicazione del traffico runtime
        # Sveglierà i detector dinamici (es. BOLA runtime analyzer, Shadow API Hunter)
        if raw_traffic_data:
            logger.info(
                f"📢 [Fase 3] Pubblicazione EVENT_TRAFFIC_CAPTURED con {len(raw_traffic_data)} record di traffico..."
            )
            self.event_bus.publish(
                EVENT_TRAFFIC_CAPTURED, {"traffic": raw_traffic_data, "target_dir": self.target_dir}
            )

        # Dividiamo i findings catturati in statici (di origine Semgrep/Checkov/ecc) e runtime
        # I detector che lavorano sul traffico producono findings di tipo RUNTIME_VALIDATOR o SHADOW_API
        for finding in self.detected_findings:
            if finding.source in (
                FindingSource.RUNTIME_VALIDATOR,
                FindingSource.SHADOW_API,
                FindingSource.ZAP_DAST,
            ):
                self.runtime_findings.append(finding)
            else:
                self.static_findings.append(finding)

        # 5. Correlazione dei rischi e calcolo scoring pesato
        logger.info("⚙️ [Fase 4] Correlazione e Calcolo dei Rischi Centralizzato...")
        correlated_results = self.correlation_engine.correlate(
            self.static_findings, self.runtime_findings
        )

        # Ricalcola lo score di rischio per ciascun finding finale correlato
        for finding in correlated_results:
            score = self.correlation_engine.calculate_risk_score(finding)
            finding.raw_data["correlated_risk_score"] = score

        logger.info(f"🏆 Pipeline completata. Totale findings correlati: {len(correlated_results)}")

        # 6. Notifica conclusione pipeline
        self.event_bus.publish(
            EVENT_PIPELINE_COMPLETED,
            {"correlated_findings": [finding.to_dict() for finding in correlated_results]},
        )

        return correlated_results

    def _register_detector_handlers(self, detectors: list[IDetector]) -> None:
        """
        Registra i metodi analyze dei detector sull'Event Bus in base alle loro iscrizioni.

        Args:
            detectors (List[IDetector]): Lista dei detector caricati da associare al bus degli eventi.
        """
        for detector in detectors:
            # Convenzione: se il detector definisce "subscribed_events", lo usiamo per il binding automatico.
            # Altrimenti lo associamo a entrambi per compatibilità di default.
            events = getattr(
                detector, "subscribed_events", [EVENT_STATIC_SCAN_COMPLETED, EVENT_TRAFFIC_CAPTURED]
            )

            for event_type in events:
                # Creiamo una funzione adapter per convertire la callback dell'evento in chiamata a analyze
                def make_handler(detector_instance=detector, captured_event_type=event_type):
                    def handler(event) -> None:
                        logger.debug(
                            f"Esecuzione detector {detector_instance.name} su evento {captured_event_type}"
                        )
                        findings = detector_instance.analyze(event.payload)
                        if findings:
                            for finding in findings:
                                self.event_bus.publish(EVENT_FINDING_DETECTED, finding)

                    # Forniamo un nome leggibile per il debug del bus
                    handler.__name__ = f"handler_{detector_instance.__class__.__name__}_{captured_event_type.replace('.', '_')}"
                    return handler

                self.event_bus.subscribe(event_type, make_handler())
