"""
Fornisce card metriche di riepilogo per la dashboard.
Responsabilità:
- Visualizzare contatori di vulnerabilità e indici di rischio in modalità sintetica.
- Utilizzare una grafica stile Glassmorphic con bordo colorato superiore di risalto.
- Nascondere il sottotitolo se vuoto per evitare lo schiacciamento del testo.
"""

from PySide6.QtWidgets import QFrame, QVBoxLayout, QLabel
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

class RiskCard(QFrame):
    """
    Card informativa premium per esporre metriche e contatori aggregati.
    """

    def __init__(self, title: str, value: str, color_hex: str = "#38bdf8", parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.StyledPanel)
        self.setLineWidth(1)
        self.setFixedHeight(110)

        # Layout interno con margini compatti per evitare schiacciamento
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 6, 12, 6)
        layout.setSpacing(2)

        # Label del Titolo
        self.title_label = QLabel(title.upper())
        self.title_label.setFont(QFont("Outfit", 9, QFont.Bold))
        self.title_label.setStyleSheet("color: #9ca3af; letter-spacing: 0.5px;")
        layout.addWidget(self.title_label)

        # Label del Valore Principale
        self.value_label = QLabel(value)
        self.value_label.setFont(QFont("Outfit", 22, QFont.ExtraBold))
        self.value_label.setStyleSheet(f"color: {color_hex};")
        layout.addWidget(self.value_label)

        # Label del Sottotitolo (opzionale, nascosto di default)
        self.sub_label = QLabel("")
        self.sub_label.setFont(QFont("Outfit", 8, QFont.Normal))
        self.sub_label.setStyleSheet("color: #6b7280;")
        self.sub_label.setVisible(False)
        layout.addWidget(self.sub_label)

        # Applica foglio di stile Glassmorphism con linea di glow superiore
        self.setStyleSheet(f"""
            RiskCard {{
                background-color: rgba(20, 27, 45, 0.65);
                border: 1px solid rgba(255, 255, 255, 0.05);
                border-top: 3px solid {color_hex};
                border-radius: 12px;
            }}
        """)

    def set_value(self, value: str):
        """
        Aggiorna il valore visualizzato nella card.
        """
        self.value_label.setText(value)

    def set_subtitle(self, text: str):
        """
        Imposta il testo di sotto-riepilogo e lo rende visibile se non vuoto.
        """
        self.sub_label.setText(text)
        self.sub_label.setVisible(bool(text.strip()))
