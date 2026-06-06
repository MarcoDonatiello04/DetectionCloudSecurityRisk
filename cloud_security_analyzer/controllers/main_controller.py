"""
Controller centrale dell'applicazione GUI.
Responsabilità:
- Caricare asincronamente i report tramite ThreadWorker e QThreadPool.
- Gestire l'avvio e la cancellazione delle scansioni reali tramite PipelineService.
- Gestire il caricamento dello storico delle scansioni archiviate.
- Gestire il ciclo di vita del caricamento dei dati e catturare centralmente le eccezioni.
- Gestire lo switch del tema grafico ed esporre le notifiche di errore per l'utente.
"""

import logging
from PySide6.QtCore import QObject, Signal, QThreadPool, Slot
from cloud_security_analyzer.core.worker import ThreadWorker
from cloud_security_analyzer.services.scan_service import ScanService
from cloud_security_analyzer.services.state_service import StateService
from cloud_security_analyzer.services.pipeline_service import PipelineService

logger = logging.getLogger("SecurityPlatform.GUI.MainController")

class MainController(QObject):
    """
    Controller principale che supervisiona l'interazione globale dell'applicazione.
    """

    # Segnali di notifica del caricamento/scansione
    scan_loading_started = Signal()
    scan_loading_finished = Signal(bool, str)     # (success, message)
    scan_progress_updated = Signal(int)           # (0-100)
    scan_step_started = Signal(str)               # (nome fase corrente)

    def __init__(self, scan_service: ScanService, state_service: StateService, pipeline_service: PipelineService):
        super().__init__()
        self.scan_service = scan_service
        self.state = state_service
        self.pipeline = pipeline_service
        self.thread_pool = QThreadPool.globalInstance()

        # Collega i segnali di PipelineService a MainController
        self.pipeline.output_received.connect(self._handle_pipeline_output)
        self.pipeline.progress_updated.connect(self.scan_progress_updated.emit)
        self.pipeline.step_started.connect(self.scan_step_started.emit)
        self.pipeline.scan_finished.connect(self._handle_pipeline_finished)

    def reload_scan_directory(self, path: str):
        """
        Avvia il caricamento asincrono della directory selezionata.
        """
        self.scan_service.set_directory(path)
        self.state.set_scan_directory(path)

        # 1. Verifica preliminare dei file
        exists, msg = self.scan_service.verify_files_exist()
        if not exists:
            self.scan_loading_finished.emit(False, msg)
            return

        self.scan_loading_started.emit()

        # 2. Avvio worker thread
        worker = ThreadWorker(self._perform_load)
        worker.signals.result.connect(self._on_load_success)
        worker.signals.error.connect(self._on_load_error)
        self.thread_pool.start(worker)

    def trigger_new_scan(self) -> bool:
        """
        Richiede l'avvio di una nuova scansione di sicurezza.
        """
        self.scan_loading_started.emit()
        self.scan_progress_updated.emit(0)
        self.scan_step_started.emit("Inizializzazione scansione...")
        
        success = self.pipeline.start_full_scan()
        if not success:
            self.scan_loading_finished.emit(False, "Impossibile avviare la scansione: c'è già un processo in esecuzione.")
            return False
        return True

    def cancel_new_scan(self):
        """
        Annulla la scansione corrente.
        """
        self.pipeline.cancel_scan()

    def load_historical_report(self, filepath: str):
        """
        Carica in background una scansione storica passata.
        """
        self.scan_loading_started.emit()
        self.scan_progress_updated.emit(50)
        self.scan_step_started.emit("Caricamento report storico...")

        worker = ThreadWorker(self._perform_historical_load, filepath)
        worker.signals.result.connect(self._on_load_success)
        worker.signals.error.connect(self._on_load_error)
        self.thread_pool.start(worker)

    def _perform_load(self) -> tuple:
        findings = self.scan_service.load_findings()
        endpoints = self.scan_service.load_endpoints()
        return findings, endpoints

    def _perform_historical_load(self, filepath: str) -> tuple:
        return self.scan_service.load_historical_scan(filepath)

    def _on_load_success(self, data: tuple):
        findings, endpoints = data
        self.state.update_data(findings, endpoints)
        self.scan_loading_finished.emit(True, "")

    def _on_load_error(self, err_tuple: tuple):
        exctype, value, traceback_str = err_tuple
        logger.error(f"Errore caricamento scansione: {value}\n{traceback_str}")
        user_message = f"Si è verificato un errore durante l'elaborazione dei report:\n{str(value)}"
        self.scan_loading_finished.emit(False, user_message)

    @Slot(str)
    def _handle_pipeline_output(self, text: str):
        # Devia l'output semplicemente stampandolo a log.
        # Poiché LogsView ha configurato un Handler radice, questo loggger
        # intercetterà il testo in tempo reale e lo scriverà nella console!
        logging.getLogger("SecurityPlatform.Pipeline").info(text.strip())

    @Slot(bool, str)
    def _handle_pipeline_finished(self, success: bool, message: str):
        """
        Gestore richiamato alla conclusione dei processi di scansione di background.
        """
        if success:
            logger.info("Pipeline conclusa con successo. Ricaricamento dei nuovi report generati...")
            # Ricarica automaticamente i report aggiornati nella cartella output di default
            self.reload_scan_directory(self.scan_service.current_dir)
        else:
            self.scan_loading_finished.emit(False, message)

    def switch_theme(self, theme_name: str):
        """
        Cambia il tema dell'applicazione.
        """
        self.state.set_theme(theme_name)
