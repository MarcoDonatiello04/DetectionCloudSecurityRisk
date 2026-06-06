"""
Gestisce la visualizzazione delle vulnerabilità di Autenticazione (Unprotected Route, Broken Auth).
Responsabilità:
- Presentare un'istanza specializzata di FindingsView pre-filtrata per la categoria AUTHENTICATION.
- Configurare titoli contestuali sui controlli di login e token JWT.
"""

from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel

from cloud_security_analyzer.gui.findings.findings_view import FindingsView
from cloud_security_analyzer.controllers.findings_controller import FindingsController

class AuthenticationView(QWidget):
    """
    Vista dedicata all'analisi dei rischi di Autenticazione delle rotte API.
    """

    def __init__(self, controller: FindingsController, parent=None):
        super().__init__(parent)
        self.controller = controller
        
        # Sovrascrive i preset_filters per isolare solo AUTHENTICATION
        self.controller.preset_filters = {"category": ["AUTHENTICATION"]}

        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Crea la vista findings specializzata
        self.findings_panel = FindingsView(self.controller, self)
        
        # Aggiorna il testo dell'header per personalizzarlo
        for child in self.findings_panel.findChildren(QLabel):
            if child.text() == "Findings di Sicurezza":
                child.setText("Sicurezza dell'Autenticazione")
            elif child.text().startswith("Esplora e analizza le vulnerabilità"):
                child.setText("Analisi dei token JWT mancanti o invalidati, e rotte non protette scoperte a livello statico o dinamico.")

        layout.addWidget(self.findings_panel)
