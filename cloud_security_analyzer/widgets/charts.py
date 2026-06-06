"""
Fornisce widget grafici personalizzati (Donut e Bar charts) disegnati tramite QPainter.
Responsabilità:
- Disegnare un grafico a ciambella (DonutChartWidget) per la distribuzione delle severità.
- Disegnare un grafico a barre (BarChartWidget) per la distribuzione dei finding per sorgente.
- Fornire rendering anti-aliasing ad alte prestazioni e compatibile con tutti i sistemi.
"""

from PySide6.QtWidgets import QWidget
from PySide6.QtGui import QPainter, QPen, QColor, QFont, QLinearGradient, QBrush
from PySide6.QtCore import Qt, QRectF

class DonutChartWidget(QWidget):
    """
    Widget che disegna un grafico a ciambella (Donut Chart) con angoli smussati ed anti-aliasing.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.data = {}
        self.colors = {}
        self.setMinimumSize(200, 200)

    def set_data(self, data: dict, colors: dict):
        """
        Imposta i dati numerici e la palette di colori del grafico.
        data: es. {"CRITICAL": 5, "HIGH": 8, "MEDIUM": 12}
        colors: es. {"CRITICAL": "#fb7185", "HIGH": "#fbbf24"}
        """
        # Filtra i valori maggiori di zero
        self.data = {k: v for k, v in data.items() if v > 0}
        self.colors = colors
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        width = self.width()
        height = self.height()
        size = min(width, height) - 40
        if size <= 0:
            return

        rect = QRectF((width - size) / 2, (height - size) / 2, size, size)
        total = sum(self.data.values())

        if total == 0:
            # Disegna un cerchio vuoto grigio in assenza di dati
            pen = QPen(QColor("#20293a"), 24)
            painter.setPen(pen)
            painter.drawArc(rect, 0, 5760)
            
            # Testo centrale
            painter.setPen(QColor("#6b7280"))
            painter.setFont(QFont("Outfit", 11, QFont.Bold))
            painter.drawText(self.rect(), Qt.AlignCenter, "Nessun dato")
            return

        start_angle = 90 * 16  # Inizia dall'alto (90 gradi in 1/16 di grado)
        pen_width = size * 0.14  # Spessore della ciambella proporzionale alla dimensione
        
        # Riduci la dimensione del rect per compensare lo spessore della penna
        rect.adjust(pen_width/2, pen_width/2, -pen_width/2, -pen_width/2)

        for key, value in self.data.items():
            span_angle = -int((value / total) * 360 * 16)  # Segno negativo per senso orario
            
            color_hex = self.colors.get(key, "#6b7280")
            color = QColor(color_hex)
            
            pen = QPen(color, pen_width, Qt.SolidLine, Qt.FlatCap)
            painter.setPen(pen)
            painter.drawArc(rect, start_angle, span_angle)
            
            start_angle += span_angle

        # Disegna il testo del totale al centro
        painter.setPen(QColor("#f3f4f6"))
        
        font_total_val = QFont("Outfit", int(size * 0.12), QFont.Bold)
        font_total_lbl = QFont("Outfit", int(size * 0.05), QFont.Medium)
        
        # Testo del numero totale
        painter.setFont(font_total_val)
        val_rect = QRectF(self.rect())
        val_rect.adjust(0, 0, 0, -size * 0.08)
        painter.drawText(val_rect, Qt.AlignCenter, str(int(total)))

        # Testo dell'etichetta
        painter.setPen(QColor("#9ca3af"))
        painter.setFont(font_total_lbl)
        lbl_rect = QRectF(self.rect())
        lbl_rect.adjust(0, size * 0.12, 0, 0)
        painter.drawText(lbl_rect, Qt.AlignCenter, "FINDINGS")


class BarChartWidget(QWidget):
    """
    Widget che disegna un grafico a barre verticali con gradiente e angoli arrotondati.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.data = {}
        self.colors = {}
        self.setMinimumSize(220, 160)

    def set_data(self, data: dict, colors: dict):
        """
        Imposta i dati numerici e la palette di colori del grafico.
        data: es. {"CHECKOV": 14, "SEMGREP": 8, "SPECTRAL": 3}
        colors: es. {"CHECKOV": "#38bdf8", "SEMGREP": "#10b981"}
        """
        self.data = data
        self.colors = colors
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        if not self.data:
            painter.setPen(QColor("#6b7280"))
            painter.setFont(QFont("Outfit", 11, QFont.Bold))
            painter.drawText(self.rect(), Qt.AlignCenter, "Nessun dato")
            return

        max_val = max(self.data.values()) if self.data.values() else 0
        if max_val == 0:
            max_val = 1  # Evita divisioni per zero

        margin_left = 40
        margin_right = 20
        margin_top = 20
        margin_bottom = 30

        chart_width = self.width() - margin_left - margin_right
        chart_height = self.height() - margin_top - margin_bottom

        keys = list(self.data.keys())
        num_bars = len(keys)
        
        # Calcola la larghezza e lo spazio tra le barre
        bar_gap = 10
        total_gaps_width = bar_gap * (num_bars - 1)
        bar_width = (chart_width - total_gaps_width) / num_bars
        bar_width = max(10.0, bar_width)

        # Disegna le linee di griglia dello sfondo
        grid_pen = QPen(QColor("#20293a"), 1, Qt.DashLine)
        painter.setPen(grid_pen)
        
        grid_lines = 4
        for i in range(grid_lines + 1):
            y = margin_top + chart_height * (i / grid_lines)
            painter.drawLine(margin_left, y, self.width() - margin_right, y)
            
            # Etichette asse Y
            val = max_val - (max_val * (i / grid_lines))
            painter.setPen(QColor("#6b7280"))
            painter.setFont(QFont("Outfit", 8))
            painter.drawText(QRectF(5, y - 8, margin_left - 10, 16), Qt.AlignRight | Qt.AlignVCenter, f"{int(val)}")
            painter.setPen(grid_pen)

        for idx, key in enumerate(keys):
            val = self.data[key]
            if val == 0:
                continue

            # Altezza della barra proporzionale al valore massimo
            bar_h = chart_height * (val / max_val)
            
            x = margin_left + idx * (bar_width + bar_gap)
            y = margin_top + chart_height - bar_h

            bar_rect = QRectF(x, y, bar_width, bar_h)

            color_hex = self.colors.get(key, "#6b7280")
            base_color = QColor(color_hex)
            
            # Crea un gradiente lineare verticale
            gradient = QLinearGradient(x, y, x, y + bar_h)
            gradient.setColorAt(0, base_color)
            gradient.setColorAt(1, QColor(base_color.red(), base_color.green(), base_color.blue(), 60))

            painter.setPen(Qt.NoPen)
            painter.setBrush(QBrush(gradient))
            # Disegna la barra con angoli arrotondati in alto (r=6)
            painter.drawRoundedRect(bar_rect, 6, 6)

            # Valore sopra la barra
            painter.setPen(QColor("#f3f4f6"))
            painter.setFont(QFont("Outfit", 8, QFont.Bold))
            painter.drawText(QRectF(x - 5, y - 18, bar_width + 10, 15), Qt.AlignCenter, str(val))

            # Nome della sorgente sotto la barra
            painter.setPen(QColor("#9ca3af"))
            painter.setFont(QFont("Outfit", 8))
            lbl_rect = QRectF(x - 10, margin_top + chart_height + 5, bar_width + 20, 20)
            
            # Accorcia l'etichetta se troppo lunga
            lbl = key
            if len(lbl) > 8:
                lbl = lbl[:6] + ".."
            painter.drawText(lbl_rect, Qt.AlignCenter, lbl)
