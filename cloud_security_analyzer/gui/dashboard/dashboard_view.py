"""
Gestisce la schermata della Dashboard di Sicurezza, ridisegnata.
Responsabilità:
- Presentare un layout a 4 pannelli premium:
  1. Execution Hub (Pulsante Avvia Scansione, progresso e stato di avanzamento)
  2. Cloud Target Status (OrbitWidget animato per LocalStack e Keycloak)
  3. Search Navigator (Barra di ricerca globale che reindirizza ai findings)
  4. Integrations & Historical Catalog (ScannerStatusWidget e lista cliccabile delle scansioni precedenti)
- Collegare eventi utente per l'esecuzione in background e caricamento dello storico.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton, 
    QProgressBar, QLineEdit, QListWidget, QListWidgetItem, QScrollArea
)
from PySide6.QtCore import Slot, Qt, Signal
from PySide6.QtGui import QFont, QColor

from cloud_security_analyzer.widgets.orbit_widget import OrbitWidget
from cloud_security_analyzer.widgets.scanner_status_widget import ScannerStatusWidget
from cloud_security_analyzer.controllers.dashboard_controller import DashboardController
from cloud_security_analyzer.controllers.main_controller import MainController

class DashboardView(QWidget):
    """
    Vista Dashboard Premium a 4 pannelli ispirata al design di riferimento.
    """

    # Segnale per richiedere il cambio tab ai findings con ricerca
    search_requested = Signal(str)
    # Segnale per avviare una scansione reale
    scan_start_requested = Signal()
    # Segnale per annullare la scansione
    scan_cancel_requested = Signal()
    # Segnale per caricare una scansione storica
    history_load_requested = Signal(str)

    def __init__(self, dashboard_controller: DashboardController, main_controller: MainController, parent=None):
        super().__init__(parent)
        self.controller = dashboard_controller
        self.main_controller = main_controller

        # Connessioni ai segnali dello StateService
        self.controller.state.data_loaded.connect(self.refresh_view)
        self.controller.state.filters_changed.connect(self.refresh_view)
        
        # Connessione segnali di progresso scansione dal MainController
        self.main_controller.scan_loading_started.connect(self._on_scan_started)
        self.main_controller.scan_loading_finished.connect(self._on_scan_finished)
        self.main_controller.scan_progress_updated.connect(self._on_scan_progress)
        self.main_controller.scan_step_started.connect(self._on_scan_step)

        self._init_ui()

    def _init_ui(self):
        # Layout principale
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(24)

        # Intestazione Dashboard
        header = QVBoxLayout()
        header.setSpacing(2)
        lbl_title = QLabel("Security Operations Center")
        lbl_title.setFont(QFont("Outfit", 22, QFont.Bold))
        lbl_title.setStyleSheet("color: #ffffff;")
        lbl_desc = QLabel("Gestione in tempo reale del rischio cloud, analisi della sicurezza delle API e conformità IaC.")
        lbl_desc.setFont(QFont("Outfit", 12))
        lbl_desc.setStyleSheet("color: #9ca3af;")
        header.addWidget(lbl_title)
        header.addWidget(lbl_desc)
        layout.addLayout(header)

        # ─── GRID / LAYOUT A 4 PANNELLI ───
        # RIGA SUPERIORE
        top_row = QHBoxLayout()
        top_row.setSpacing(20)

        # 1. PANNELLO SUPERIORE SINISTRO: EXECUTION HUB
        self.panel_exec = QFrame(self)
        self.panel_exec.setObjectName("glassCard")
        exec_layout = QVBoxLayout(self.panel_exec)
        exec_layout.setContentsMargins(24, 24, 24, 24)
        exec_layout.setSpacing(14)

        lbl_exec_title = QLabel("Security Scan Hub")
        lbl_exec_title.setFont(QFont("Outfit", 15, QFont.Bold))
        lbl_exec_title.setStyleSheet("color: #ffffff; border: none;")
        exec_layout.addWidget(lbl_exec_title)

        lbl_exec_desc = QLabel("Avvia scansioni di sicurezza complete sul codice e sull'infrastruttura emulata LocalStack.")
        lbl_exec_desc.setFont(QFont("Outfit", 10))
        lbl_exec_desc.setStyleSheet("color: #9ca3af; border: none;")
        lbl_exec_desc.setWordWrap(True)
        exec_layout.addWidget(lbl_exec_desc)

        # Pulsante Avvia Scansione (Glow Purple Gradient)
        self.btn_run_scan = QPushButton("+ Start New Scan", self)
        self.btn_run_scan.setFixedHeight(44)
        self.btn_run_scan.setFont(QFont("Outfit", 11, QFont.Bold))
        self.btn_run_scan.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #818cf8, stop:1 #4f46e5);
                color: #ffffff;
                border: none;
                border-radius: 8px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #a78bfa, stop:1 #6366f1);
            }
        """)
        self.btn_run_scan.clicked.connect(self._start_scan_pipeline)
        exec_layout.addWidget(self.btn_run_scan)

        # Pulsante Annulla Scansione (inizialmente nascosto)
        self.btn_cancel_scan = QPushButton("Annulla Scansione", self)
        self.btn_cancel_scan.setFixedHeight(32)
        self.btn_cancel_scan.setFont(QFont("Outfit", 10, QFont.Medium))
        self.btn_cancel_scan.setStyleSheet("background-color: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 6px;")
        self.btn_cancel_scan.setVisible(False)
        self.btn_cancel_scan.clicked.connect(self._cancel_scan_pipeline)
        exec_layout.addWidget(self.btn_cancel_scan)

        # Progress bar e status
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setFixedHeight(8)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: rgba(255, 255, 255, 0.04);
                border: none;
                border-radius: 4px;
            }
            QProgressBar::chunk {
                background-color: #a78bfa;
                border-radius: 4px;
            }
        """)
        self.progress_bar.setVisible(False)
        exec_layout.addWidget(self.progress_bar)

        self.lbl_scan_status = QLabel("Stato: Pronto")
        self.lbl_scan_status.setFont(QFont("Outfit", 9, QFont.Medium))
        self.lbl_scan_status.setStyleSheet("color: #6b7280; border: none;")
        exec_layout.addWidget(self.lbl_scan_status)

        exec_layout.addStretch()
        top_row.addWidget(self.panel_exec, 1)

        # 2. PANNELLO SUPERIORE DESTRO: CLOUD STATUS ORBITS
        self.panel_cloud = QFrame(self)
        self.panel_cloud.setObjectName("glassCard")
        cloud_layout = QVBoxLayout(self.panel_cloud)
        cloud_layout.setContentsMargins(24, 24, 24, 24)
        cloud_layout.setSpacing(8)

        lbl_cloud_title = QLabel("Cloud Target Environment")
        lbl_cloud_title.setFont(QFont("Outfit", 15, QFont.Bold))
        lbl_cloud_title.setStyleSheet("color: #ffffff; border: none;")
        cloud_layout.addWidget(lbl_cloud_title)

        lbl_cloud_desc = QLabel("Stato dell'infrastruttura virtuale AWS simulata su LocalStack e Keycloak.")
        lbl_cloud_desc.setFont(QFont("Outfit", 10))
        lbl_cloud_desc.setStyleSheet("color: #9ca3af; border: none;")
        cloud_layout.addWidget(lbl_cloud_desc)

        # Aggiunta dell'OrbitWidget animato
        self.orbit_widget = OrbitWidget(self)
        cloud_layout.addWidget(self.orbit_widget)

        top_row.addWidget(self.panel_cloud, 1)
        layout.addLayout(top_row, 1)

        # RIGA INFERIORE
        bottom_row = QHBoxLayout()
        bottom_row.setSpacing(20)

        # 3. PANNELLO INFERIORE SINISTRO: SEARCH NAVIGATOR
        self.panel_search = QFrame(self)
        self.panel_search.setObjectName("glassCard")
        search_layout = QVBoxLayout(self.panel_search)
        search_layout.setContentsMargins(24, 24, 24, 24)
        search_layout.setSpacing(14)

        lbl_search_title = QLabel("Global Risk Navigator")
        lbl_search_title.setFont(QFont("Outfit", 15, QFont.Bold))
        lbl_search_title.setStyleSheet("color: #ffffff; border: none;")
        search_layout.addWidget(lbl_search_title)

        lbl_search_desc = QLabel("Cerca all'istante vulnerabilità per titolo, risorsa target, file o identificativo CWE/CVE.")
        lbl_search_desc.setFont(QFont("Outfit", 10))
        lbl_search_desc.setStyleSheet("color: #9ca3af; border: none;")
        search_layout.addWidget(lbl_search_desc)

        # Input di ricerca in stile terminale/glowing
        self.search_input = QLineEdit(self)
        self.search_input.setPlaceholderText("Digita la vulnerabilità da cercare... (Premi Invio per navigare)")
        self.search_input.setFixedHeight(40)
        self.search_input.setStyleSheet("""
            QLineEdit {
                background-color: rgba(255, 255, 255, 0.03);
                border: 1px solid rgba(255, 255, 255, 0.08);
                border-radius: 8px;
                color: #ffffff;
                font-family: 'Outfit', sans-serif;
                font-size: 13px;
                padding-left: 12px;
                padding-right: 12px;
            }
            QLineEdit:focus {
                border: 1px solid #818cf8;
                background-color: rgba(255, 255, 255, 0.05);
            }
        """)
        self.search_input.returnPressed.connect(self._trigger_search)
        search_layout.addWidget(self.search_input)

        search_layout.addStretch()
        bottom_row.addWidget(self.panel_search, 1)

        # 4. PANNELLO INFERIORE DESTRO: INTEGRATION STATUS & HISTORICAL SCANS
        self.panel_integrations = QFrame(self)
        self.panel_integrations.setObjectName("glassCard")
        int_layout = QVBoxLayout(self.panel_integrations)
        int_layout.setContentsMargins(24, 24, 24, 24)
        int_layout.setSpacing(14)

        lbl_int_title = QLabel("Integrations & History Catalog")
        lbl_int_title.setFont(QFont("Outfit", 15, QFont.Bold))
        lbl_int_title.setStyleSheet("color: #ffffff; border: none;")
        int_layout.addWidget(lbl_int_title)

        # Nodi degli scanner (ScannerStatusWidget)
        self.scanner_status = ScannerStatusWidget(self)
        int_layout.addWidget(self.scanner_status)

        # Storico Scansioni Precedenti (QListWidget)
        lbl_hist_title = QLabel("CARTELLA REPORT PRECEDENTI")
        lbl_hist_title.setFont(QFont("Outfit", 9, QFont.Bold))
        lbl_hist_title.setStyleSheet("color: #818cf8; letter-spacing: 0.5px; border: none; margin-top: 8px;")
        int_layout.addWidget(lbl_hist_title)

        self.history_list = QListWidget(self)
        self.history_list.setFixedHeight(120)
        self.history_list.setStyleSheet("""
            QListWidget {
                background-color: rgba(0, 0, 0, 0.2);
                border: 1px solid rgba(255, 255, 255, 0.05);
                border-radius: 6px;
                color: #e5e7eb;
                padding: 4px;
            }
            QListWidget::item {
                padding: 6px 8px;
                border-bottom: 1px solid rgba(255, 255, 255, 0.02);
            }
            QListWidget::item:hover {
                background-color: rgba(255, 255, 255, 0.04);
                color: #ffffff;
            }
            QListWidget::item:selected {
                background-color: rgba(129, 140, 248, 0.15);
                color: #818cf8;
                font-weight: bold;
            }
        """)
        self.history_list.itemDoubleClicked.connect(self._on_history_item_clicked)
        int_layout.addWidget(self.history_list)

        bottom_row.addWidget(self.panel_integrations, 1)
        layout.addLayout(bottom_row, 1)

        # Stile Glassmorphism per i 4 pannelli
        self.setStyleSheet("""
            QFrame#glassCard {
                background-color: rgba(13, 11, 22, 0.7);
                border: 1px solid rgba(167, 139, 250, 0.15);
                border-radius: 16px;
            }
        """)

        self.refresh_view()

    @Slot()
    def refresh_view(self):
        """
        Ricarica lo storico delle scansioni passate nella lista.
        """
        self.history_list.clear()
        
        # Recupera lo storico
        history = self.controller.get_historical_scans()
        for h in history:
            text = f"📅  {h['date_str']}  |  Findings: {h['total_findings']}  |  Risk Rating: {h['risk_score']}/10"
            item = QListWidgetItem(text)
            # Memorizza il filepath per caricarlo al click
            item.setData(Qt.UserRole, h["filepath"])
            self.history_list.addItem(item)

    def _trigger_search(self):
        query = self.search_input.text().strip()
        if query:
            # Pulisce l'input ed emette il segnale per reindirizzare l'utente
            self.search_input.clear()
            self.search_requested.emit(query)

    def _start_scan_pipeline(self):
        # Disabilita bottone scansione ed avvia
        self.scan_start_requested.emit()

    def _cancel_scan_pipeline(self):
        self.scan_cancel_requested.emit()

    def _on_history_item_clicked(self, item: QListWidgetItem):
        filepath = item.data(Qt.UserRole)
        if filepath:
            self.history_load_requested.emit(filepath)

    # Slots per aggiornamento progresso provenienti da MainController
    @Slot()
    def _on_scan_started(self):
        self.btn_run_scan.setEnabled(False)
        self.btn_run_scan.setText("Scansione in corso...")
        self.btn_cancel_scan.setVisible(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.lbl_scan_status.setText("Stato: Avvio...")

    @Slot(bool, str)
    def _on_scan_finished(self, success: bool, message: str):
        self.btn_run_scan.setEnabled(True)
        self.btn_run_scan.setText("+ Start New Scan")
        self.btn_cancel_scan.setVisible(False)
        self.progress_bar.setVisible(False)
        
        status_txt = "Stato: Completato" if success else f"Errore: {message}"
        self.lbl_scan_status.setText(status_txt)
        
        # Aggiorna lo storico
        self.refresh_view()

    @Slot(int)
    def _on_scan_progress(self, val: int):
        self.progress_bar.setValue(val)

    @Slot(str)
    def _on_scan_step(self, step_name: str):
        self.lbl_scan_status.setText(f"Fase: {step_name}")
