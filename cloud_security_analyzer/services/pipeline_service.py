"""
Gestisce l'esecuzione in background della pipeline di scansione di sicurezza.
Responsabilità:
- Avviare gli script di scansione (2_iac_analysis.sh e 3_api_security.sh) tramite QProcess.
- Intercettare lo standard output in tempo reale per aggiornare i log console.
- Gestire lo stato di avanzamento della scansione ed notificare il completamento.
- Salvare una copia di backup datata dei report al termine di una scansione di successo.
"""

import os
import shutil
import logging
from datetime import datetime
from PySide6.QtCore import QObject, Signal, QProcess

logger = logging.getLogger("SecurityPlatform.GUI.PipelineService")

class PipelineService(QObject):
    """
    Servizio preposto al coordinamento dei sottoprocessi di scansione di sicurezza.
    """

    # Segnali per la notifica dello stato di avanzamento
    output_received = Signal(str)            # Emesso quando arriva nuovo testo da stdout/stderr
    progress_updated = Signal(int)           # Emesso con la percentuale di avanzamento (0-100)
    step_started = Signal(str)               # Notifica l'avvio di una fase (es. "Analisi IaC")
    scan_finished = Signal(bool, str)        # Notifica il termine del processo completo (success, message)

    def __init__(self, project_root: str):
        super().__init__()
        self.project_root = os.path.abspath(project_root)
        self.process = None
        self.steps_queue = []
        self.current_step_name = ""
        self.is_running = False

    def start_full_scan(self) -> bool:
        """
        Incolonna e avvia l'intera scansione di sicurezza (IaC + API Security).
        """
        if self.is_running:
            logger.warning("Scansione già in corso.")
            return False

        # Incolonna i comandi da eseguire sequentially
        self.steps_queue = [
            ("Analisi IaC (Provisioning)", "bash", [os.path.join(self.project_root, "scripts", "2_iac_analysis.sh")]),
            ("Analisi API Security & D-AST", "bash", [os.path.join(self.project_root, "scripts", "3_api_security.sh")])
        ]
        
        self.is_running = True
        self.progress_updated.emit(5)
        self._run_next_step()
        return True

    def _run_next_step(self):
        """
        Esegue il prossimo step in coda nella QProcess.
        """
        if not self.steps_queue:
            # Tutte le fasi completate con successo!
            self._archive_current_results()
            self.is_running = False
            self.progress_updated.emit(100)
            self.scan_finished.emit(True, "Scansione completata con successo! I risultati sono stati archiviati.")
            return

        self.current_step_name, cmd, args = self.steps_queue.pop(0)
        self.step_started.emit(self.current_step_name)

        # Calcola progresso indicativo
        pct = 15 if "IaC" in self.current_step_name else 50
        self.progress_updated.emit(pct)

        self.process = QProcess(self)
        self.process.setWorkingDirectory(self.project_root)
        
        # Connette i canali di lettura standard
        self.process.readyReadStandardOutput.connect(self._read_output)
        self.process.readyReadStandardError.connect(self._read_error)
        self.process.finished.connect(self._on_step_finished)

        # Avvio del processo
        logger.info(f"Avvio step pipeline: {self.current_step_name} -> {cmd} {args}")
        self.process.start(cmd, args)

    def _read_output(self):
        """
        Legge lo standard output in tempo reale.
        """
        data = self.process.readAllStandardOutput().data().decode("utf-8", errors="replace")
        # Rimuove sequenze di escape colore bash per pulizia log GUI
        clean_data = self._strip_bash_colors(data)
        self.output_received.emit(clean_data)

    def _read_error(self):
        """
        Legge lo standard errore in tempo reale.
        """
        data = self.process.readAllStandardError().data().decode("utf-8", errors="replace")
        clean_data = self._strip_bash_colors(data)
        self.output_received.emit(f"[ERROR] {clean_data}")

    def _on_step_finished(self, exit_code: int, exit_status: QProcess.ExitStatus):
        """
        Gestisce la terminazione di uno step.
        """
        logger.info(f"Step '{self.current_step_name}' terminato con exit_code={exit_code}")
        
        if exit_code != 0 or exit_status == QProcess.ExitStatus.CrashExit:
            self.is_running = False
            self.scan_finished.emit(False, f"Scansione interrotta: la fase '{self.current_step_name}' è fallita.")
            return

        # Procede al prossimo step
        self._run_next_step()

    def _archive_current_results(self):
        """
        Copia e archivia i file generati al termine della scansione con timestamp datato.
        """
        output_dir = os.path.join(self.project_root, "output")
        reports_dir = os.path.join(self.project_root, "reports")
        os.makedirs(reports_dir, exist_ok=True)

        report_src = os.path.join(output_dir, "unified_security_report.json")
        inventory_src = os.path.join(output_dir, "unified_api_inventory.json")

        if os.path.exists(report_src):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_dest = os.path.join(reports_dir, f"unified_report_{timestamp}.json")
            inventory_dest = os.path.join(reports_dir, f"unified_inventory_{timestamp}.json")

            try:
                shutil.copy2(report_src, report_dest)
                logger.info(f"Archiviato report findings: {report_dest}")
                if os.path.exists(inventory_src):
                    shutil.copy2(inventory_src, inventory_dest)
                    logger.info(f"Archiviato inventario API: {inventory_dest}")
            except Exception as e:
                logger.error(f"Errore durante l'archiviazione dei risultati: {e}", exc_info=True)

    def _strip_bash_colors(self, text: str) -> str:
        """
        Rimuove sequenze di caratteri per i colori del terminale bash.
        """
        import re
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)

    def cancel_scan(self):
        """
        Interrompe la scansione in esecuzione.
        """
        if self.process and self.process.state() != QProcess.ProcessState.NotRunning:
            self.process.kill()
            self.is_running = False
            self.scan_finished.emit(False, "Scansione annullata dall'utente.")
