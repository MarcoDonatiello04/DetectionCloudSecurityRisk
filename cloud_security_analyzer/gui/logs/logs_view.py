"""
Gestisce la visualizzazione dei log applicativi di scansione (LogViewer).
Responsabilità:
- Visualizzare una console di log a scorrimento in tempo reale.
- Configurare un logging Handler custom per deviare i log della GUI nel visualizzatore.
- Fornire controlli per pulire la console o copiare i log negli appunti.
"""

import logging
from PySide6.QtWidgets import QWidget, QVBoxLayout, QPlainTextEdit, QHBoxLayout, QPushButton, QLabel, QApplication
from PySide6.QtCore import Slot, Qt
from PySide6.QtGui import QFont

class LogHandler(logging.Handler):
    """
    Handler di log personalizzato che scrive i record direttamente in una casella di testo Qt.
    """

    def __init__(self, text_widget: QPlainTextEdit):
        super().__init__()
        self.text_widget = text_widget
        self.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))

    def emit(self, record):
        msg = self.format(record)
        # Assicura l'append del log nel thread principale
        self.text_widget.appendPlainText(msg)


class LogsView(QWidget):
    """
    Vista Console per visualizzare i log del sistema e dell'orchestratore.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()

        # Collega l'handler di logging personalizzato al logger radice della piattaforma
        self.log_handler = LogHandler(self.console)
        self.log_handler.setLevel(logging.INFO)
        logging.getLogger().addHandler(self.log_handler)

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # 1. Titolo e descrizione
        header_layout = QVBoxLayout()
        header_layout.setSpacing(2)
        lbl_title = QLabel("Log e Console di Sistema")
        lbl_title.setFont(QFont("Outfit", 20, QFont.Bold))
        lbl_desc = QLabel("Tracciamento dell'esecuzione del parser, del caricamento asincrono dei file e delle attività GUI.")
        lbl_desc.setFont(QFont("Outfit", 12))
        lbl_desc.setStyleSheet("color: #9ca3af;")
        header_layout.addWidget(lbl_title)
        header_layout.addWidget(lbl_desc)
        layout.addLayout(header_layout)

        # 2. Console di Testo
        self.console = QPlainTextEdit(self)
        self.console.setReadOnly(True)
        self.console.setFont(QFont("JetBrains Mono", 10))
        self.console.setStyleSheet("""
            QPlainTextEdit {
                background-color: #05070c;
                border: 1px solid rgba(255, 255, 255, 0.05);
                border-radius: 8px;
                color: #38bdf8;
                padding: 12px;
            }
        """)
        layout.addWidget(self.console)

        # 3. Bottoni di Controllo (Pulisci, Copia)
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(12)
        
        btn_clear = QPushButton("Pulisci Console", self)
        btn_clear.clicked.connect(self.console.clear)
        
        btn_copy = QPushButton("Copia Log negli Appunti", self)
        btn_copy.clicked.connect(self._copy_to_clipboard)

        btn_layout.addWidget(btn_clear)
        btn_layout.addWidget(btn_copy)
        btn_layout.addStretch()

        layout.addLayout(btn_layout)

    def _copy_to_clipboard(self):
        text = self.console.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            logging.info("📋 Log copiati negli appunti.")
            
    def closeEvent(self, event):
        # Rimuove l'handler alla chiusura per evitare perdite di memoria
        logging.getLogger().removeHandler(self.log_handler)
        super().closeEvent(event)
