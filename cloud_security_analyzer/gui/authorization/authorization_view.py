"""
Gestisce la visualizzazione delle vulnerabilità di Autorizzazione (BOLA / IDOR).
Responsabilità:
- Presentare un'istanza specializzata di FindingsView pre-filtrata per la categoria AUTHORIZATION.
- Visualizzare spiegazioni di contesto relative a Broken Object Level Authorization.
"""

from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel
from PySide6.QtGui import QFont

from cloud_security_analyzer.gui.findings.findings_view import FindingsView
from cloud_security_analyzer.controllers.findings_controller import FindingsController

class AuthorizationView(QWidget):
    """
    Vista dedicata all'analisi dei rischi di Autorizzazione (es. BOLA, IDOR).
    """

    def __init__(self, controller: FindingsController, parent=None):
        super().__init__(parent)
        self.controller = controller
        
        # Sovrascrive i preset_filters per isolare solo AUTHORIZATION
        self.controller.preset_filters = {"category": ["AUTHORIZATION"]}

        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Crea la vista findings specializzata
        self.findings_panel = FindingsView(self.controller, self)
        
        # Rintraccia e aggiorna il testo dell'header per personalizzarlo
        for child in self.findings_panel.findChildren(QLabel):
            if child.text() == "Findings di Sicurezza":
                child.setText("Sicurezza dell'Autorizzazione & BOLA")
            elif child.text().startswith("Esplora e analizza le vulnerabilità"):
                child.setText("Analisi degli accessi risorsa (IDOR/BOLA) e controlli di autorizzazione rotti stimolati a runtime.")

        layout.addWidget(self.findings_panel)
