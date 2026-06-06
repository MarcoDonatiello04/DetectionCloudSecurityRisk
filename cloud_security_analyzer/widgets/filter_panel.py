"""
Gestisce il pannello dei filtri interattivo (Chips) della GUI.
Responsabilità:
- Presentare bottoni stile "chip" per filtrare i findings in base alla severità.
- Cambiare aspetto grafico (attivo/inattivo) in base alla selezione correntemente attiva nello StateService.
"""

from PySide6.QtWidgets import QWidget, QHBoxLayout, QPushButton
from PySide6.QtCore import Signal
from cloud_security_analyzer.core.config import SEVERITY_COLORS

class FilterChip(QPushButton):
    """
    Singolo bottone a pillola (Chip) per l'attivazione/disattivazione di un filtro.
    """

    def __init__(self, name: str, color_hex: str, parent=None):
        super().__init__(name, parent)
        self.name = name
        self.color_hex = color_hex
        self.is_active = False
        self.setCheckable(True)
        self.setFixedHeight(28)
        self._update_style()

    def set_active(self, active: bool):
        """
        Imposta lo stato attivo e aggiorna lo stile.
        """
        if self.is_active != active:
            self.is_active = active
            self.setChecked(active)
            self._update_style()

    def _update_style(self):
        """
        Aggiorna il foglio di stile (QSS) in base allo stato attivo/inattivo.
        """
        if self.is_active:
            # Stile attivo: background semitrasparente saturo e bordo visibile
            self.setStyleSheet(f"""
                QPushButton {{
                    font-family: 'Outfit', sans-serif;
                    font-size: 11px;
                    font-weight: bold;
                    color: {self.color_hex};
                    background-color: rgba({self._hex_to_rgb(self.color_hex)}, 0.16);
                    border: 1px solid {self.color_hex};
                    border-radius: 14px;
                    padding-left: 14px;
                    padding-right: 14px;
                }}
            """)
        else:
            # Stile inattivo: spento e con bordo leggero
            self.setStyleSheet(f"""
                QPushButton {{
                    font-family: 'Outfit', sans-serif;
                    font-size: 11px;
                    font-weight: 500;
                    color: #9ca3af;
                    background-color: rgba(20, 27, 45, 0.4);
                    border: 1px solid rgba(255, 255, 255, 0.05);
                    border-radius: 14px;
                    padding-left: 14px;
                    padding-right: 14px;
                }}
                QPushButton:hover {{
                    color: #f3f4f6;
                    background-color: rgba(255, 255, 255, 0.05);
                    border: 1px solid rgba(255, 255, 255, 0.15);
                }}
            """)

    def _hex_to_rgb(self, hex_str: str) -> str:
        h = hex_str.lstrip('#')
        rgb = tuple(int(h[i:i+2], 16) for i in (0, 2, 4))
        return f"{rgb[0]}, {rgb[1]}, {rgb[2]}"


class FilterPanel(QWidget):
    """
    Contenitore orizzontale di FilterChip per la selezione rapida delle severità.
    """
    
    # Segnale emesso al click di una chip (emette la stringa della severità)
    severity_toggled = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        self.chips = {}
        for sev, color in SEVERITY_COLORS.items():
            if sev == "UNTESTED":
                continue
            chip = FilterChip(sev, color, self)
            # Connette il click al gestore interno
            chip.clicked.connect(lambda checked=False, s=sev: self._on_chip_clicked(s))
            layout.addWidget(chip)
            self.chips[sev] = chip
            
        layout.addStretch()

    def update_states(self, active_severities: set):
        """
        Sincronizza lo stato visivo delle chip con il set fornito.
        """
        for sev, chip in self.chips.items():
            chip.set_active(sev in active_severities)

    def _on_chip_clicked(self, severity: str):
        self.severity_toggled.emit(severity)
