"""
Gestisce la visualizzazione dei findings legati all'infrastruttura (Terraform / Checkov IaC).
Responsabilità:
- Presentare un'istanza specializzata di FindingsView pre-filtrata per la sorgente CHECKOV.
- Configurare i titoli in chiave di cloud storage pubblico, policy IAM ed encryption.
"""

from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel

from cloud_security_analyzer.gui.findings.findings_view import FindingsView
from cloud_security_analyzer.controllers.findings_controller import FindingsController

class InfrastructureView(QWidget):
    """
    Vista dedicata all'esame delle misconfiguration infrastrutturali rileyate su Terraform.
    """

    def __init__(self, controller: FindingsController, parent=None):
        super().__init__(parent)
        self.controller = controller
        
        # Filtra esclusivamente i finding generati da CHECKOV
        self.controller.preset_filters = {"source": ["CHECKOV"]}

        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Crea la vista findings specializzata
        self.findings_panel = FindingsView(self.controller, self)
        
        # Aggiorna il testo dell'header per personalizzarlo
        for child in self.findings_panel.findChildren(QLabel):
            if child.text() == "Findings di Sicurezza":
                child.setText("Sicurezza dell'Infrastruttura (IaC)")
            elif child.text().startswith("Esplora e analizza le vulnerabilità"):
                child.setText("Valutazione statica delle configurazioni cloud Terraform (S3 pubblici, log disattivati, IAM eccessivi).")

        layout.addWidget(self.findings_panel)
