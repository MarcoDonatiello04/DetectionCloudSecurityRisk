"""
Fornisce badge colorati e stilizzati per visualizzare i livelli di severità.
Responsabilità:
- Visualizzare etichette (CRITICAL, HIGH, ecc.) con stili moderni.
- Modificare dinamicamente i fogli di stile (QSS) in base alla severità fornita.
"""

from PySide6.QtWidgets import QLabel
from PySide6.QtCore import Qt
from cloud_security_analyzer.core.config import SEVERITY_COLORS

class SeverityBadge(QLabel):
    """
    Badge personalizzato che visualizza il livello di severità con colori a contrasto.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAlignment(Qt.AlignCenter)
        self.setFixedWidth(85)
        self.setFixedHeight(22)
        
        # Stile di base per il badge
        self.base_style = """
            QLabel {
                font-family: 'Outfit', sans-serif;
                font-size: 9px;
                font-weight: bold;
                border-radius: 11px;
                padding: 2px 8px;
                text-transform: uppercase;
            }
        """
        self.set_severity("INFO")

    def set_severity(self, severity: str):
        """
        Imposta il testo e i colori del badge in base alla severità.
        """
        sev_upper = severity.upper()
        self.setText(sev_upper)

        color_hex = SEVERITY_COLORS.get(sev_upper, "#6b7280")
        
        # Genera foglio di stile con background semitrasparente e bordo solido dello stesso colore
        qss = self.base_style + f"""
            QLabel {{
                color: {color_hex};
                background-color: rgba({self._hex_to_rgb(color_hex)}, 0.12);
                border: 1px solid rgba({self._hex_to_rgb(color_hex)}, 0.25);
            }}
        """
        self.setStyleSheet(qss)

    def _hex_to_rgb(self, hex_str: str) -> str:
        """
        Converte una stringa colore esadecimale (es. #fb7185) in una terna RGB CSV (es. 251, 113, 133).
        """
        h = hex_str.lstrip('#')
        rgb = tuple(int(h[i:i+2], 16) for i in (0, 2, 4))
        return f"{rgb[0]}, {rgb[1]}, {rgb[2]}"
