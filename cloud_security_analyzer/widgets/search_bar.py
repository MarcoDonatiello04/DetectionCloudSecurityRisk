"""
Gestisce la barra di ricerca integrata nella GUI.
Responsabilità:
- Fornire un componente QLineEdit moderno per l'input utente.
- Applicare stili moderni di focus e placeholder.
"""

from PySide6.QtWidgets import QLineEdit

class SearchBar(QLineEdit):
    """
    Casella di testo per la ricerca con stile custom e responsive.
    """

    def __init__(self, placeholder: str = "Cerca...", parent=None):
        super().__init__(parent)
        self.setPlaceholderText(placeholder)
        self.setFixedHeight(36)
        
        # Foglio di stile per la barra di ricerca (vetro opaco e transizione al focus)
        self.setStyleSheet("""
            QLineEdit {
                background-color: #161e31;
                border: 1px solid rgba(255, 255, 255, 0.08);
                border-radius: 8px;
                color: #f3f4f6;
                font-family: 'Outfit', sans-serif;
                font-size: 13px;
                padding-left: 12px;
                padding-right: 12px;
            }
            QLineEdit:focus {
                border: 1px solid rgba(56, 189, 248, 0.45);
                background-color: #1a2339;
            }
        """)
