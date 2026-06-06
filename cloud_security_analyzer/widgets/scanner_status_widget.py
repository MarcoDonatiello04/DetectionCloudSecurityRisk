"""
Fornisce il widget dello stato degli scanner (Integrations).
Responsabilità:
- Visualizzare una serie orizzontale di capsule o cerchi per ciascun adapter (Checkov, Semgrep, ZAP, ecc.).
- Evidenziare con colori a contrasto (Verde/Giallo) se lo scanner è configurato ed attivo.
- Utilizzare una grafica uniforme con effetti hover.
"""

from PySide6.QtWidgets import QWidget, QHBoxLayout, QLabel, QVBoxLayout
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QColor

from cloud_security_analyzer.core.config import SOURCE_COLORS

class ScannerCircle(QWidget):
    """
    Singolo cerchio badge rappresentante uno scanner o integrazione.
    """

    def __init__(self, name: str, shortcut: str, status: str = "attivo", parent=None):
        super().__init__(parent)
        self.name = name
        self.shortcut = shortcut
        self.status = status
        self.color_hex = SOURCE_COLORS.get(name.upper(), "#38bdf8")

        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)
        layout.setAlignment(Qt.AlignCenter)

        # Cerchio grafico (QLabel con border radius pari alla metà di larghezza/altezza)
        self.circle = QLabel(self.shortcut)
        self.circle.setFixedSize(40, 40)
        self.circle.setAlignment(Qt.AlignCenter)
        self.circle.setFont(QFont("Outfit", 12, QFont.Bold))
        
        # Colore cerchio in base a stato
        bg_opacity = "0.15" if self.status == "attivo" else "0.05"
        text_color = self.color_hex if self.status == "attivo" else "#6b7280"
        border_color = self.color_hex if self.status == "attivo" else "rgba(255, 255, 255, 0.08)"

        self.circle.setStyleSheet(f"""
            QLabel {{
                color: {text_color};
                background-color: rgba({self._hex_to_rgb(self.color_hex)}, {bg_opacity});
                border: 2px solid {border_color};
                border-radius: 20px;
            }}
            QLabel:hover {{
                background-color: rgba({self._hex_to_rgb(self.color_hex)}, 0.25);
                border: 2px solid #ffffff;
            }}
        """)
        layout.addWidget(self.circle)

        # Nome dello scanner sotto
        lbl_name = QLabel(self.name)
        lbl_name.setAlignment(Qt.AlignCenter)
        lbl_name.setFont(QFont("Outfit", 8, QFont.Medium))
        lbl_name.setStyleSheet("color: #9ca3af;")
        layout.addWidget(lbl_name)

    def _hex_to_rgb(self, hex_str: str) -> str:
        h = hex_str.lstrip('#')
        rgb = tuple(int(h[i:i+2], 16) for i in (0, 2, 4))
        return f"{rgb[0]}, {rgb[1]}, {rgb[2]}"


class ScannerStatusWidget(QWidget):
    """
    Pannello orizzontale che raggruppa lo stato di tutti gli scanner di sicurezza integrati.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        layout.setAlignment(Qt.AlignCenter)

        # Crea i cerchi per ogni scanner
        self.scanners = [
            ScannerCircle("Checkov", "CK", "attivo", self),
            ScannerCircle("Semgrep", "SG", "attivo", self),
            ScannerCircle("Spectral", "SP", "attivo", self),
            ScannerCircle("Zap_DAST", "ZP", "attivo", self),
            ScannerCircle("Shadow_API", "SD", "attivo", self)
        ]

        for sc in self.scanners:
            layout.addWidget(sc)
