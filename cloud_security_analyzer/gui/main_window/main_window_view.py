"""
Gestisce il contenitore principale della GUI (MainWindow).
Responsabilità:
- Presentare una barra di navigazione laterale (Sidebar) con pulsanti per cambiare schermata.
- Gestire il layout stacked delle viste principali.
- Gestire gli stati di caricamento visualizzando messaggi di attesa e popup di successo/errore.
- Cambiare il foglio di stile QSS a runtime in risposta al cambio tema nello StateService.
"""

import os
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QPushButton, 
    QStackedWidget, QLabel, QFrame, QMessageBox, QStatusBar
)
from PySide6.QtCore import Slot, Qt
from PySide6.QtGui import QFont, QIcon

from cloud_security_analyzer.core.config import APP_TITLE, APP_VERSION, get_absolute_path
from cloud_security_analyzer.controllers.main_controller import MainController
from cloud_security_analyzer.controllers.dashboard_controller import DashboardController
from cloud_security_analyzer.controllers.findings_controller import FindingsController
from cloud_security_analyzer.controllers.endpoints_controller import EndpointsController

from cloud_security_analyzer.gui.dashboard.dashboard_view import DashboardView
from cloud_security_analyzer.gui.findings.findings_view import FindingsView
from cloud_security_analyzer.gui.endpoints.endpoints_view import EndpointsView
from cloud_security_analyzer.gui.authorization.authorization_view import AuthorizationView
from cloud_security_analyzer.gui.authentication.authentication_view import AuthenticationView
from cloud_security_analyzer.gui.infrastructure.infrastructure_view import InfrastructureView
from cloud_security_analyzer.gui.logs.logs_view import LogsView
from cloud_security_analyzer.gui.settings.settings_view import SettingsView
from cloud_security_analyzer.services.export_service import ExportService

class MainWindow(QMainWindow):
    """
    Finestra principale contenente la navigazione ed il contenitore delle schermate.
    """

    def __init__(self, 
                 main_controller: MainController, 
                 dashboard_controller: DashboardController,
                 findings_controller: FindingsController,
                 endpoints_controller: EndpointsController,
                 export_service: ExportService,
                 parent=None):
        super().__init__(parent)
        self.main_controller = main_controller
        self.dashboard_controller = dashboard_controller
        self.findings_controller = findings_controller
        self.endpoints_controller = endpoints_controller
        self.export_service = export_service
        self.state = main_controller.state

        self.setWindowTitle(f"{APP_TITLE} v{APP_VERSION}")
        self.resize(1200, 800)

        # Sottoscrizione ai segnali
        self.main_controller.scan_loading_started.connect(self._on_loading_started)
        self.main_controller.scan_loading_finished.connect(self._on_loading_finished)
        self.state.theme_changed.connect(self._apply_theme)

        self._init_ui()
        self._apply_theme(self.state.theme)

    def _init_ui(self):
        # 1. Central Widget & Main Layout
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # 2. Sidebar sinistra (QFrame)
        self.sidebar = QFrame(self)
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setFixedWidth(240)
        
        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(16, 24, 16, 24)
        sidebar_layout.setSpacing(8)

        # Header Sidebar (Logo + Versione)
        logo_container = QVBoxLayout()
        logo_container.setSpacing(2)
        logo_container.setContentsMargins(0, 0, 0, 24)
        
        lbl_logo_icon = QLabel("🛡️")
        lbl_logo_icon.setFont(QFont("Outfit", 26))
        lbl_logo_icon.setAlignment(Qt.AlignCenter)
        
        lbl_logo_title = QLabel(APP_TITLE.upper())
        lbl_logo_title.setFont(QFont("Outfit", 11, QFont.Bold))
        lbl_logo_title.setAlignment(Qt.AlignCenter)
        lbl_logo_title.setStyleSheet("color: #38bdf8; letter-spacing: 1px;")

        lbl_logo_ver = QLabel(f"SECURITY ENGINE v{APP_VERSION}")
        lbl_logo_ver.setFont(QFont("Outfit", 8))
        lbl_logo_ver.setAlignment(Qt.AlignCenter)
        lbl_logo_ver.setStyleSheet("color: #6b7280;")

        logo_container.addWidget(lbl_logo_icon)
        logo_container.addWidget(lbl_logo_title)
        logo_container.addWidget(lbl_logo_ver)
        sidebar_layout.addLayout(logo_container)

        # Tab Buttons
        self.tab_buttons = []
        tabs_config = [
            ("Dashboard", "📊  Dashboard"),
            ("Findings", "🔍  Vulnerabilità (Tutte)"),
            ("Endpoints", "🛣️  Catalogo API"),
            ("Authorization", "🔑  Autorizzazione & BOLA"),
            ("Authentication", "🔒  Autenticazione API"),
            ("Infrastructure", "☁️  Infrastruttura IaC"),
            ("Logs", "⚙️  Console di Sistema"),
            ("Settings", "🛠️  Impostazioni")
        ]

        for index, (obj_name, label_text) in enumerate(tabs_config):
            btn = QPushButton(label_text, self)
            btn.setObjectName("sidebarTab")
            btn.setCheckable(True)
            # Collega il click alla selezione del rispettivo stacked widget index
            btn.clicked.connect(lambda checked=False, idx=index: self._switch_tab(idx))
            sidebar_layout.addWidget(btn)
            self.tab_buttons.append(btn)

        # Imposta la prima tab attiva di default
        self.tab_buttons[0].setChecked(True)
        
        sidebar_layout.addStretch()
        main_layout.addWidget(self.sidebar)

        # 3. Stacked Widget centrale (schermate della GUI)
        self.stacked_widget = QStackedWidget(self)
        self.stacked_widget.setObjectName("panelContent")
        main_layout.addWidget(self.stacked_widget)

        # Istanziazione delle Viste
        self.view_dashboard = DashboardView(self.dashboard_controller, self.main_controller, self)
        self.view_dashboard.search_requested.connect(self._handle_dashboard_search)
        self.view_dashboard.scan_start_requested.connect(self.main_controller.trigger_new_scan)
        self.view_dashboard.scan_cancel_requested.connect(self.main_controller.cancel_new_scan)
        self.view_dashboard.history_load_requested.connect(self.main_controller.load_historical_report)

        self.view_findings = FindingsView(self.findings_controller, self)
        self.view_endpoints = EndpointsView(self.endpoints_controller, self)
        
        # Controller dedicati clonando quello principale ma con presets diversi
        authz_ctrl = FindingsController(self.state, {"category": ["AUTHORIZATION"]})
        self.view_authz = AuthorizationView(authz_ctrl, self)
        
        authn_ctrl = FindingsController(self.state, {"category": ["AUTHENTICATION"]})
        self.view_authn = AuthenticationView(authn_ctrl, self)
        
        infra_ctrl = FindingsController(self.state, {"source": ["CHECKOV"]})
        self.view_infra = InfrastructureView(infra_ctrl, self)
        
        self.view_logs = LogsView(self)
        self.view_settings = SettingsView(self.main_controller, self.export_service, self)

        # Aggiunta allo Stack nello stesso ordine della configurazione tabs
        self.stacked_widget.addWidget(self.view_dashboard)
        self.stacked_widget.addWidget(self.view_findings)
        self.stacked_widget.addWidget(self.view_endpoints)
        self.stacked_widget.addWidget(self.view_authz)
        self.stacked_widget.addWidget(self.view_authn)
        self.stacked_widget.addWidget(self.view_infra)
        self.stacked_widget.addWidget(self.view_logs)
        self.stacked_widget.addWidget(self.view_settings)

        # 4. Status Bar
        self.status_bar = QStatusBar(self)
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Pronto")

    def _switch_tab(self, index: int):
        """
        Sblocca ed attiva la tab all'indice specificato, deselezionando le altre.
        """
        self.stacked_widget.setCurrentIndex(index)
        for idx, btn in enumerate(self.tab_buttons):
            btn.setChecked(idx == index)

    @Slot()
    def _on_loading_started(self):
        self.status_bar.showMessage("Caricamento dei report di sicurezza in corso...")
        self.setEnabled(False)

    @Slot(bool, str)
    def _on_loading_finished(self, success: bool, err_message: str):
        self.setEnabled(True)
        if success:
            self.status_bar.showMessage("Caricamento completato con successo.", 5000)
            QMessageBox.information(self, "Scansione Caricata", "I report di sicurezza sono stati caricati ed elaborati con successo!")
        else:
            self.status_bar.showMessage("Errore durante il caricamento della scansione.")
            QMessageBox.critical(self, "Errore Caricamento", err_message)

    @Slot(str)
    def _apply_theme(self, theme_name: str):
        """
        Carica e applica il foglio di stile QSS a runtime.
        """
        filename = f"{theme_name}.qss"
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "resources", "themes", filename)
        
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    qss = f.read()
                self.setStyleSheet(qss)
                # Forza il refresh grafico del widget radice
                self.style().unpolish(self)
                self.style().polish(self)
                # Riconfigura lo stile del radio group delle impostazioni nel caso cambi
                if hasattr(self, "view_settings") and hasattr(self.view_settings, "rad_dark"):
                    text_color = "color: #1e293b;" if theme_name == "light" else "color: #fff;"
                    self.view_settings.rad_dark.setStyleSheet(f"QRadioButton {{ {text_color} border: none; }}")
                    self.view_settings.rad_light.setStyleSheet(f"QRadioButton {{ {text_color} border: none; }}")
                
                # Riconfigura lo stile della sidebar
                if theme_name == "light":
                    self.sidebar.setStyleSheet("QFrame#sidebar { background-color: #ffffff; border-right: 1px solid #e2e8f0; }")
                else:
                    self.sidebar.setStyleSheet("QFrame#sidebar { background-color: #0c101b; border-right: 1px solid #1c2333; }")
                    
            except Exception as e:
                logger.error(f"Impossibile applicare il foglio di stile {path}: {e}")

    def _handle_dashboard_search(self, query: str):
        """
        Gestisce la ricerca globale inoltrando la query alla vista findings e cambiando tab.
        """
        self._switch_tab(1)  # Tab dei Findings
        self.view_findings.search_bar.setText(query)
