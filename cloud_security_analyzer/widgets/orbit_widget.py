"""
Fornisce il widget visuale animato dello stato dell'ambiente target Cloud.
Responsabilità:
- Disegnare un'animazione QPainter 60FPS con nodi orbitanti attorno ad un bersaglio cloud centrale.
- Rappresentare graficamente i microservizi emulati (Keycloak, S3, API Gateway, Lambda).
- Aggiornare le posizioni tramite un QTimer interno.
"""

import math
from PySide6.QtWidgets import QWidget
from PySide6.QtCore import QTimer, Qt, QRectF, QPointF
from PySide6.QtGui import QPainter, QPen, QColor, QFont, QLinearGradient, QBrush

class OrbitWidget(QWidget):
    """
    Widget animato con nodi orbitanti per lo stato dell'infrastruttura Cloud target.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(250, 180)
        self.angle = 0.0

        # Nodi dell'infrastruttura: (Nome, raggio orbita in pixel, velocità di rotazione, colore)
        self.nodes = [
            {"name": "Keycloak", "radius": 75, "speed": 1.2, "color": "#fb7185", "offset": 0.0},
            {"name": "S3 Storage", "radius": 95, "speed": 0.8, "color": "#38bdf8", "offset": math.pi / 2},
            {"name": "API Gateway", "radius": 55, "speed": 1.5, "color": "#a78bfa", "offset": math.pi},
            {"name": "Lambda", "radius": 85, "speed": 1.0, "color": "#10b981", "offset": 3 * math.pi / 2}
        ]

        # Timer dell'animazione (60 FPS ~ 16ms)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._update_animation)
        self.timer.start(16)

    def _update_animation(self):
        # Incrementa l'angolo base
        self.angle += 0.015
        if self.angle >= 2 * math.pi:
            self.angle = 0.0
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        cx = self.width() / 2.0
        cy = self.height() / 2.0

        # 1. Disegna le orbite (cerchi concentrici trasparenti)
        orbit_pen = QPen(QColor(129, 140, 248, 40), 1, Qt.SolidLine)
        for node in self.nodes:
            r = node["radius"]
            painter.setPen(orbit_pen)
            painter.setBrush(Qt.NoBrush)
            painter.drawEllipse(QPointF(cx, cy), r, r * 0.45) # Ellissi per dare una prospettiva 3D!

        # 2. Disegna il Cloud Target Centrale
        cloud_rect = QRectF(cx - 30, cy - 20, 60, 40)
        cloud_grad = QLinearGradient(cx - 30, cy - 20, cx + 30, cy + 20)
        cloud_grad.setColorAt(0, QColor("#818cf8"))
        cloud_grad.setColorAt(1, QColor("#4338ca"))

        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(cloud_grad))
        painter.drawRoundedRect(cloud_rect, 15, 15)

        # Disegna icona cloud / testo centrale
        painter.setPen(QColor("#ffffff"))
        painter.setFont(QFont("Outfit", 8, QFont.Bold))
        painter.drawText(cloud_rect, Qt.AlignCenter, "CLOUD")

        # 3. Disegna i nodi orbitanti
        for node in self.nodes:
            # Calcola le coordinate sul piano ellittico con offset angolare
            theta = self.angle * node["speed"] + node["offset"]
            r_x = node["radius"]
            r_y = node["radius"] * 0.45
            
            x = cx + r_x * math.cos(theta)
            y = cy + r_y * math.sin(theta)

            node_color = QColor(node["color"])
            
            # Disegna il cerchietto del nodo
            painter.setPen(Qt.NoPen)
            painter.setBrush(QBrush(node_color))
            painter.drawEllipse(QPointF(x, y), 8, 8)

            # Etichetta di testo del nodo (visibile se non troppo ammassata)
            painter.setPen(QColor("#9ca3af"))
            painter.setFont(QFont("Outfit", 7, QFont.Medium))
            painter.drawText(QRectF(x - 40, y + 10, 80, 16), Qt.AlignCenter, node["name"])
