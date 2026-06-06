"""
Gestisce la schermata delle impostazioni e delle esportazioni.
Responsabilità:
- Configurare la directory di caricamento dei report di sicurezza.
- Abilitare lo switch dinamico del tema grafico (Dark / Light).
- Gestire l'esportazione offline in formati Markdown/HTML tramite ExportService.
"""

import os
import logging
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, 
    QFileDialog, QMessageBox, QFrame, QRadioButton, QButtonGroup
)
from PySide6.QtCore import Slot, Qt
from PySide6.QtGui import QFont

from cloud_security_analyzer.services.state_service import StateService
from cloud_security_analyzer.controllers.main_controller import MainController
from cloud_security_analyzer.services.export_service import ExportService

logger = logging.getLogger("SecurityPlatform.GUI.SettingsView")

class SettingsView(QWidget):
    """
    Vista per gestire i percorsi dei file, i temi visivi ed esportare riepiloghi.
    """

    def __init__(self, main_controller: MainController, export_service: ExportService, parent=None):
        super().__init__(parent)
        self.controller = main_controller
        self.export_service = export_service
        self.state = main_controller.state
        
        # Sottoscrizione ai segnali dello stato
        self.state.scan_directory_changed.connect(self._on_dir_changed)
        self.state.theme_changed.connect(self._on_theme_changed)

        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(20)

        # 1. Titolo e descrizione
        header_layout = QVBoxLayout()
        header_layout.setSpacing(2)
        lbl_title = QLabel("Impostazioni e Reportistica")
        lbl_title.setFont(QFont("Outfit", 20, QFont.Bold))
        lbl_desc = QLabel("Configura le preferenze grafiche dell'applicazione ed esporta i report offline.")
        lbl_desc.setFont(QFont("Outfit", 12))
        lbl_desc.setStyleSheet("color: #9ca3af;")
        header_layout.addWidget(lbl_title)
        header_layout.addWidget(lbl_desc)
        layout.addLayout(header_layout)

        # 2. Sezione Percorso Scansione
        dir_frame = QFrame(self)
        dir_frame.setStyleSheet("QFrame { background-color: rgba(20, 27, 45, 0.45); border: 1px solid rgba(255,255,255,0.05); border-radius: 8px; }")
        dir_layout = QVBoxLayout(dir_frame)
        dir_layout.setContentsMargins(16, 16, 16, 16)

        lbl_sec_dir = QLabel("CARTELLA REPORT DI SICUREZZA")
        lbl_sec_dir.setFont(QFont("Outfit", 10, QFont.Bold))
        lbl_sec_dir.setStyleSheet("color: #38bdf8; border: none;")
        dir_layout.addWidget(lbl_sec_dir)

        path_layout = QHBoxLayout()
        path_layout.setSpacing(8)
        
        self.txt_path = QLineEdit(self)
        self.txt_path.setFixedHeight(32)
        self.txt_path.setText(self.state.scan_directory)
        self.txt_path.setStyleSheet("QLineEdit { background-color: #161e31; border: 1px solid rgba(255,255,255,0.06); border-radius: 4px; color: #fff; padding-left: 8px; }")
        path_layout.addWidget(self.txt_path)

        btn_browse = QPushButton("Sfoglia...", self)
        btn_browse.clicked.connect(self._on_browse)
        path_layout.addWidget(btn_browse)

        dir_layout.addLayout(path_layout)

        btn_save_dir = QPushButton("Ricarica Scansione", self)
        btn_save_dir.setStyleSheet("background-color: #38bdf8; color: #080b11; font-weight: bold; border: none;")
        btn_save_dir.clicked.connect(self._on_reload)
        dir_layout.addWidget(btn_save_dir)
        layout.addWidget(dir_frame)

        # 3. Sezione Tema Visivo
        theme_frame = QFrame(self)
        theme_frame.setStyleSheet("QFrame { background-color: rgba(20, 27, 45, 0.45); border: 1px solid rgba(255,255,255,0.05); border-radius: 8px; }")
        theme_layout = QVBoxLayout(theme_frame)
        theme_layout.setContentsMargins(16, 16, 16, 16)

        lbl_sec_theme = QLabel("TEMA VISIVO INTERFACCIA")
        lbl_sec_theme.setFont(QFont("Outfit", 10, QFont.Bold))
        lbl_sec_theme.setStyleSheet("color: #38bdf8; border: none;")
        theme_layout.addWidget(lbl_sec_theme)

        theme_radio_layout = QHBoxLayout()
        self.theme_group = QButtonGroup(self)
        
        self.rad_dark = QRadioButton("Modalità Scura (Glow System)", self)
        self.rad_dark.setStyleSheet("QRadioButton { color: #fff; border: none; }")
        self.rad_dark.setChecked(self.state.theme == "dark")
        self.rad_dark.toggled.connect(self._on_theme_toggled)
        
        self.rad_light = QRadioButton("Modalità Chiara (Steel Contrast)", self)
        self.rad_light.setStyleSheet("QRadioButton { color: #fff; border: none; }")
        self.rad_light.setChecked(self.state.theme == "light")
        self.rad_light.toggled.connect(self._on_theme_toggled)

        self.theme_group.addButton(self.rad_dark)
        self.theme_group.addButton(self.rad_light)
        
        theme_radio_layout.addWidget(self.rad_dark)
        theme_radio_layout.addWidget(self.rad_light)
        theme_radio_layout.addStretch()
        theme_layout.addLayout(theme_radio_layout)
        layout.addWidget(theme_frame)

        # 4. Sezione Esportazione Reports
        export_frame = QFrame(self)
        export_frame.setStyleSheet("QFrame { background-color: rgba(20, 27, 45, 0.45); border: 1px solid rgba(255,255,255,0.05); border-radius: 8px; }")
        export_layout = QVBoxLayout(export_frame)
        export_layout.setContentsMargins(16, 16, 16, 16)

        lbl_sec_exp = QLabel("ESPORTAZIONE OFFLINE RIASSUNTIVA")
        lbl_sec_exp.setFont(QFont("Outfit", 10, QFont.Bold))
        lbl_sec_exp.setStyleSheet("color: #38bdf8; border: none;")
        export_layout.addWidget(lbl_sec_exp)

        exp_buttons_layout = QHBoxLayout()
        exp_buttons_layout.setSpacing(12)
        
        btn_exp_md = QPushButton("Esporta in Markdown (.md)", self)
        btn_exp_md.clicked.connect(self._on_export_markdown)
        
        btn_exp_html = QPushButton("Esporta in HTML Premium (.html)", self)
        btn_exp_html.clicked.connect(self._on_export_html)

        exp_buttons_layout.addWidget(btn_exp_md)
        exp_buttons_layout.addWidget(btn_exp_html)
        exp_buttons_layout.addStretch()
        export_layout.addLayout(exp_buttons_layout)
        layout.addWidget(export_frame)

        layout.addStretch()

    def _on_browse(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Seleziona Cartella Output", self.txt_path.text())
        if dir_path:
            self.txt_path.setText(dir_path)

    def _on_reload(self):
        path = self.txt_path.text().strip()
        if not path or not os.path.exists(path):
            QMessageBox.critical(self, "Errore", "Il percorso specificato non esiste.")
            return
        
        # Avvia il ricaricamento asincrono tramite il controller principale
        self.controller.reload_scan_directory(path)

    def _on_theme_toggled(self, checked):
        if not checked:
            return
        theme = "dark" if self.rad_dark.isChecked() else "light"
        self.controller.switch_theme(theme)

    def _on_export_markdown(self):
        risk = self.state.risk_model
        if not risk or not self.state.findings:
            QMessageBox.warning(self, "Attenzione", "Nessun dato disponibile da esportare. Carica prima una scansione valida.")
            return

        try:
            filepath = self.export_service.export_to_markdown(risk, self.state.findings)
            QMessageBox.information(self, "Report Esportato", f"Il report Markdown è stato salvato in:\n{filepath}")
        except Exception as e:
            QMessageBox.critical(self, "Errore di Esportazione", f"Esportazione non riuscita:\n{str(e)}")

    def _on_export_html(self):
        risk = self.state.risk_model
        if not risk or not self.state.findings:
            QMessageBox.warning(self, "Attenzione", "Nessun dato disponibile da esportare. Carica prima una scansione valida.")
            return

        try:
            filepath = self.export_service.export_to_html(risk, self.state.findings)
            QMessageBox.information(self, "Report Esportato", f"Il report HTML è stato salvato in:\n{filepath}")
        except Exception as e:
            QMessageBox.critical(self, "Errore di Esportazione", f"Esportazione non riuscita:\n{str(e)}")

    @Slot(str)
    def _on_dir_changed(self, path: str):
        self.txt_path.setText(path)

    @Slot(str)
    def _on_theme_changed(self, theme_name: str):
        self.rad_dark.setChecked(theme_name == "dark")
        self.rad_light.setChecked(theme_name == "light")
