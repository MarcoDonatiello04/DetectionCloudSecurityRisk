"""
Punto di ingresso principale (Launcher) per l'applicazione desktop.
Responsabilità:
- Inizializzare il logging per la GUI.
- Istanziare e collegare servizi, modelli e controller (MVC).
- Caricare il tema iniziale e visualizzare la MainWindow.
- Eseguire il caricamento dei report iniziali.
"""

import sys
import os
import logging
from PySide6.QtWidgets import QApplication

# Aggiunge la cartella principale del progetto al PYTHONPATH a runtime per evitare conflitti di import
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from cloud_security_analyzer.services.scan_service import ScanService
from cloud_security_analyzer.services.state_service import StateService
from cloud_security_analyzer.services.export_service import ExportService
from cloud_security_analyzer.services.pipeline_service import PipelineService

from cloud_security_analyzer.controllers.main_controller import MainController
from cloud_security_analyzer.controllers.dashboard_controller import DashboardController
from cloud_security_analyzer.controllers.findings_controller import FindingsController
from cloud_security_analyzer.controllers.endpoints_controller import EndpointsController

from cloud_security_analyzer.gui.main_window.main_window_view import MainWindow

def setup_gui_logging():
    """
    Configura il logger della GUI per raccogliere eventi di sistema e di business.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    logger = logging.getLogger("SecurityPlatform.GUI")
    logger.info("🚀 Avvio interfaccia desktop di Cloud Security Analyzer...")

def main():
    # 1. Configurazione logging
    setup_gui_logging()

    # 2. Inizializzazione della QApplication
    app = QApplication(sys.argv)
    app.setStyle("Fusion") # Stile uniforme cross-platform

    # 3. Istanziazione dei Servizi Core
    # Usa la cartella "output" di default se esistente nel workspace
    default_scan_dir = os.path.join(project_root, "output")
    if not os.path.exists(default_scan_dir):
        default_scan_dir = "."

    scan_service = ScanService(default_scan_dir)
    state_service = StateService()
    state_service.set_scan_directory(default_scan_dir)
    
    export_service = ExportService(os.path.join(project_root, "reports"))
    pipeline_service = PipelineService(project_root)

    # 4. Istanziazione dei Controller (MVC)
    main_controller = MainController(scan_service, state_service, pipeline_service)
    dashboard_controller = DashboardController(state_service, scan_service)
    findings_controller = FindingsController(state_service)
    endpoints_controller = EndpointsController(state_service)

    # 5. Costruzione e visualizzazione della MainWindow
    window = MainWindow(
        main_controller=main_controller,
        dashboard_controller=dashboard_controller,
        findings_controller=findings_controller,
        endpoints_controller=endpoints_controller,
        export_service=export_service
    )
    window.show()

    # 6. Avvio automatico della prima scansione di default se presente
    if os.path.exists(os.path.join(default_scan_dir, "unified_security_report.json")):
        main_controller.reload_scan_directory(default_scan_dir)

    sys.exit(app.exec())

if __name__ == "__main__":
    main()
