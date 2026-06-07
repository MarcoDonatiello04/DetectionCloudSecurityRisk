"""
Gestisce la visualizzazione degli endpoint API (Catalogo API).
Responsabilità:
- Visualizzare una tabella con gli endpoint rilevati dal framework.
- Distinguere graficamente tra API documentate e Shadow APIs (non documentate).
- Visualizzare lo stato BOLA (Vulnerabile, Sicuro, Non Testato) per ciascun endpoint.
- Fornire filtri rapidi per visualizzare solo Shadow APIs o specifici stati BOLA.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem, 
    QLabel, QHeaderView, QRadioButton, QButtonGroup, QPushButton
)
from PySide6.QtCore import Slot, Qt
from PySide6.QtGui import QFont, QColor

from cloud_security_analyzer.widgets.search_bar import SearchBar
from cloud_security_analyzer.controllers.endpoints_controller import EndpointsController
from cloud_security_analyzer.models.endpoint_model import EndpointModel

class EndpointsView(QWidget):
    """
    Vista responsabile della visualizzazione e conformità del catalogo API.
    """

    def __init__(self, controller: EndpointsController, parent=None):
        super().__init__(parent)
        self.controller = controller
        
        # Connette i segnali dello StateService
        self.controller.state.filters_changed.connect(self.refresh_table)

        self._init_ui()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 24, 24, 24)
        main_layout.setSpacing(16)

        # 1. Titolo e descrizione
        header_layout = QVBoxLayout()
        header_layout.setSpacing(2)
        lbl_title = QLabel("Catalogo Endpoint API")
        lbl_title.setFont(QFont("Outfit", 20, QFont.Bold))
        lbl_desc = QLabel("Inventario delle rotte esposte rilevate a codice o a runtime. Verifica la copertura e lo stato BOLA.")
        lbl_desc.setFont(QFont("Outfit", 12))
        lbl_desc.setStyleSheet("color: #9ca3af;")
        header_layout.addWidget(lbl_title)
        header_layout.addWidget(lbl_desc)
        main_layout.addLayout(header_layout)

        # 2. Barra di ricerca e filtri
        filters_layout = QHBoxLayout()
        filters_layout.setSpacing(16)

        self.search_bar = SearchBar("Cerca per path, metodo, descrizione...", self)
        self.search_bar.textChanged.connect(self.controller.set_search_query)
        filters_layout.addWidget(self.search_bar, 2)

        # Pulsanti radio per tipo API (Tutte, Documentate, Shadow)
        self.radio_group = QButtonGroup(self)
        
        self.r_all = QPushButton("Tutti gli Endpoint")
        self.r_all.setCheckable(True)
        self.r_all.setChecked(True)
        self.r_all.clicked.connect(self._on_type_changed)
        
        self.r_doc = QPushButton("Solo Documentati (OpenAPI)")
        self.r_doc.setCheckable(True)
        self.r_doc.clicked.connect(self._on_type_changed)
        
        self.r_shadow = QPushButton("Solo Shadow APIs")
        self.r_shadow.setCheckable(True)
        self.r_shadow.clicked.connect(self._on_type_changed)

        self.radio_group.addButton(self.r_all)
        self.radio_group.addButton(self.r_doc)
        self.radio_group.addButton(self.r_shadow)

        filters_layout.addWidget(self.r_all)
        filters_layout.addWidget(self.r_doc)
        filters_layout.addWidget(self.r_shadow)
        
        main_layout.addLayout(filters_layout)

        # 3. Tabella degli Endpoint
        self.table = QTableWidget(self)
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["METODO", "PATH ENDPOINT", "CONFORMITÀ CONTRATTO", "STATO BOLA (D-AST)", "VIOLAZIONI SPECTRAL"])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)

        # Ridimensionamento colonne
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        self.table.setColumnWidth(0, 80)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)

        main_layout.addWidget(self.table)

        self.refresh_table()

    def _on_type_changed(self):
        """
        Gestore della selezione dei filtri delle radio.
        """
        self.r_all.setStyleSheet("")
        self.r_doc.setStyleSheet("")
        self.r_shadow.setStyleSheet("")

        # Applica evidenziazione al bottone attivo
        active_style = "background-color: rgba(56, 189, 248, 0.12); color: #38bdf8; border: 1px solid #38bdf8;"
        if self.r_all.isChecked():
            self.r_all.setStyleSheet(active_style)
            self.controller.set_filter_shadow_only(False)
            self.controller.set_filter_documented_only(False)
        elif self.r_doc.isChecked():
            self.r_doc.setStyleSheet(active_style)
            self.controller.set_filter_shadow_only(False)
            self.controller.set_filter_documented_only(True)
        elif self.r_shadow.isChecked():
            self.r_shadow.setStyleSheet(active_style)
            self.controller.set_filter_shadow_only(True)
            self.controller.set_filter_documented_only(False)

    @Slot()
    def refresh_table(self):
        """
        Aggiorna le righe della tabella in base ai filtri attivi.
        """
        endpoints = self.controller.get_filtered_endpoints()
        self.table.setRowCount(len(endpoints))

        for row, ep in enumerate(endpoints):
            # 1. Metodo Badge
            method_item = QTableWidgetItem(ep.method)
            method_item.setTextAlignment(Qt.AlignCenter)
            method_item.setFont(QFont("Outfit", 9, QFont.Bold))
            method_item.setFlags(method_item.flags() & ~Qt.ItemIsEditable)
            
            # Colore specifico per il metodo HTTP
            method_colors = {
                "GET": "#10b981",     # Green
                "POST": "#fbbf24",    # Amber
                "PUT": "#38bdf8",     # Sky Blue
                "DELETE": "#fb7185",  # Rose Red
                "PATCH": "#a78bfa"    # Violet
            }
            m_color = method_colors.get(ep.method, "#9ca3af")
            method_item.setForeground(Qt.GlobalColor.white)
            method_item.setBackground(Qt.GlobalColor.transparent)
            self.table.setItem(row, 0, method_item)

            # 2. Path
            path_item = QTableWidgetItem(ep.path)
            path_item.setFont(QFont("JetBrains Mono", 10))
            path_item.setForeground(QColor("#e5e7eb"))
            path_item.setFlags(path_item.flags() & ~Qt.ItemIsEditable)
            self.table.setItem(row, 1, path_item)

            # 3. Conformità Contratto (Documented vs Shadow)
            comp_lbl = QLabel()
            comp_lbl.setAlignment(Qt.AlignCenter)
            comp_lbl.setFont(QFont("Outfit", 8, QFont.Bold))
            comp_lbl.setFixedHeight(20)
            if ep.shadow:
                comp_lbl.setText("SHADOW API")
                comp_lbl.setStyleSheet("color: #fbbf24; background-color: rgba(251, 191, 36, 0.12); border: 1px solid rgba(251, 191, 36, 0.2); border-radius: 4px; padding: 2px 6px;")
            else:
                comp_lbl.setText("DOCUMENTATO")
                comp_lbl.setStyleSheet("color: #a78bfa; background-color: rgba(167, 139, 250, 0.12); border: 1px solid rgba(167, 139, 250, 0.2); border-radius: 4px; padding: 2px 6px;")
            
            # Incolla il widget
            comp_container = QWidget()
            comp_layout = QHBoxLayout(comp_container)
            comp_layout.setContentsMargins(8, 2, 8, 2)
            comp_layout.addWidget(comp_lbl)
            self.table.setCellWidget(row, 2, comp_container)

            # 4. Stato BOLA (D-AST)
            bola_lbl = QLabel()
            bola_lbl.setAlignment(Qt.AlignCenter)
            bola_lbl.setFont(QFont("Outfit", 8, QFont.Bold))
            bola_lbl.setFixedHeight(20)
            
            bola_style_map = {
                "VULNERABLE": ("VULNERABILE", "color: #fb7185; background-color: rgba(251, 113, 133, 0.15); border: 1px solid rgba(251, 113, 133, 0.25); border-radius: 4px; padding: 2px 6px;"),
                "POTENTIAL": ("SOSPETTO", "color: #fbbf24; background-color: rgba(251, 191, 36, 0.12); border: 1px solid rgba(251, 191, 36, 0.2); border-radius: 4px; padding: 2px 6px;"),
                "SAFE": ("SICURO (OK)", "color: #10b981; background-color: rgba(16, 185, 129, 0.12); border: 1px solid rgba(16, 185, 129, 0.25); border-radius: 4px; padding: 2px 6px;"),
                "UNTESTED": ("NON TESTATO", "color: #6b7280; background-color: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 4px; padding: 2px 6px;")
            }
            lbl_txt, qss_style = bola_style_map.get(ep.bola_status, bola_style_map["UNTESTED"])
            bola_lbl.setText(lbl_txt)
            bola_lbl.setStyleSheet(qss_style)

            bola_container = QWidget()
            bola_layout = QHBoxLayout(bola_container)
            bola_layout.setContentsMargins(8, 2, 8, 2)
            bola_layout.addWidget(bola_lbl)
            self.table.setCellWidget(row, 3, bola_container)

            # 5. Violazioni Spectral
            viol_txt = f"{ep.violation_count} violazioni" if ep.violation_count > 0 else "Conforme"
            viol_item = QTableWidgetItem(viol_txt)
            viol_item.setFont(QFont("Outfit", 10))
            if ep.violation_count > 0:
                viol_item.setForeground(QColor("#fb7185"))
            else:
                viol_item.setForeground(QColor("#10b981"))
            viol_item.setFlags(viol_item.flags() & ~Qt.ItemIsEditable)
            self.table.setItem(row, 4, viol_item)
