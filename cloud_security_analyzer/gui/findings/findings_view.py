"""
Gestisce la visualizzazione dei findings in formato master-detail.
Responsabilità:
- Visualizzare una tabella con l'elenco dei findings rilevati (colonne: severità, ID, titolo, sorgente).
- Integrare la barra di ricerca ed il FilterPanel (chips di severità).
- Visualizzare i dettagli completi del finding selezionato (codice, mitigazione, evidenze).
"""

from typing import Optional
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTableWidget, 
    QTableWidgetItem, QTextBrowser, QLabel, QHeaderView, QFrame
)
from PySide6.QtCore import Qt, Slot
from PySide6.QtGui import QFont

from cloud_security_analyzer.core.config import SEVERITY_COLORS
from cloud_security_analyzer.widgets.search_bar import SearchBar
from cloud_security_analyzer.widgets.filter_panel import FilterPanel
from cloud_security_analyzer.widgets.severity_badge import SeverityBadge
from cloud_security_analyzer.controllers.findings_controller import FindingsController
from cloud_security_analyzer.models.finding_model import FindingModel

class FindingsView(QWidget):
    """
    Schermata Master-Detail per l'esplorazione, ricerca e mitigazione delle vulnerabilità.
    """

    def __init__(self, controller: FindingsController, parent=None):
        super().__init__(parent)
        self.controller = controller
        
        # Connessioni ai segnali dello StateService
        self.controller.state.filters_changed.connect(self.refresh_table)
        self.controller.state.selected_finding_changed.connect(self.display_details)

        self._init_ui()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 24, 24, 24)
        main_layout.setSpacing(16)

        # 1. Titolo e descrizione
        header_layout = QVBoxLayout()
        header_layout.setSpacing(2)
        lbl_title = QLabel("Findings di Sicurezza")
        lbl_title.setFont(QFont("Outfit", 20, QFont.Bold))
        lbl_desc = QLabel("Esplora e analizza le vulnerabilità rilevate nel codice sorgente e nell'infrastruttura.")
        lbl_desc.setFont(QFont("Outfit", 12))
        lbl_desc.setStyleSheet("color: #9ca3af;")
        header_layout.addWidget(lbl_title)
        header_layout.addWidget(lbl_desc)
        main_layout.addLayout(header_layout)

        # 2. Controlli Filtri (Cerca + Chips Severità)
        controls_layout = QHBoxLayout()
        controls_layout.setSpacing(16)

        self.search_bar = SearchBar("Cerca per titolo, file, risorsa, CVE...", self)
        self.search_bar.textChanged.connect(self.controller.set_search_query)
        controls_layout.addWidget(self.search_bar, 2)

        self.filter_panel = FilterPanel(self)
        self.filter_panel.severity_toggled.connect(self.controller.toggle_severity)
        controls_layout.addWidget(self.filter_panel, 3)

        main_layout.addLayout(controls_layout)

        # 3. Master-Detail Splitter
        splitter = QSplitter(Qt.Horizontal, self)
        splitter.setStyleSheet("QSplitter::handle { background-color: rgba(255, 255, 255, 0.05); width: 2px; }")

        # Sinistra: Tabella Master
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)

        self.table = QTableWidget(self)
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["SEVERITÀ", "ID FINDING", "TITOLO", "SORGENTE"])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.setAlternatingRowColors(False)
        
        # Ridimensionamento colonne
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        self.table.setColumnWidth(0, 100)
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        self.table.setColumnWidth(1, 130)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)

        self.table.itemSelectionChanged.connect(self._on_row_selected)
        left_layout.addWidget(self.table)
        splitter.addWidget(left_widget)

        # Destra: Dettagli Detail
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        
        lbl_detail_hdr = QLabel("DETTAGLIO E MITIGAZIONE")
        lbl_detail_hdr.setFont(QFont("Outfit", 10, QFont.Bold))
        lbl_detail_hdr.setStyleSheet("color: #9ca3af; letter-spacing: 1px; margin-bottom: 4px;")
        right_layout.addWidget(lbl_detail_hdr)

        self.details_pane = QTextBrowser(self)
        self.details_pane.setOpenExternalLinks(True)
        right_layout.addWidget(self.details_pane)
        
        splitter.addWidget(right_widget)
        
        # Imposta proporzione splitter (60% tabella, 40% dettagli)
        splitter.setSizes([600, 400])
        main_layout.addWidget(splitter)

        self.refresh_table()

    @Slot()
    def refresh_table(self):
        """
        Ricarica i dati nella tabella applicando i filtri.
        """
        # Sincronizza lo stato visivo delle chips
        self.filter_panel.update_states(self.controller.state.selected_severities)

        findings = self.controller.get_filtered_findings()
        self.table.setRowCount(len(findings))

        # Salva la lista filtrata corrente per indice
        self._current_findings = findings

        for row, f in enumerate(findings):
            # 1. Badge di Severità
            badge = SeverityBadge(self)
            badge.set_severity(f.severity)
            
            # Crea un contenitore centrato per il badge nella cella
            badge_container = QWidget()
            badge_layout = QHBoxLayout(badge_container)
            badge_layout.setContentsMargins(0, 4, 0, 4)
            badge_layout.setAlignment(Qt.AlignCenter)
            badge_layout.addWidget(badge)
            self.table.setCellWidget(row, 0, badge_container)

            # 2. ID Finding
            id_item = QTableWidgetItem(f.id)
            id_item.setFont(QFont("JetBrains Mono", 10))
            id_item.setFlags(id_item.flags() & ~Qt.ItemIsEditable)
            self.table.setItem(row, 1, id_item)

            # 3. Titolo
            title_item = QTableWidgetItem(f.title)
            title_item.setFlags(title_item.flags() & ~Qt.ItemIsEditable)
            self.table.setItem(row, 2, title_item)

            # 4. Sorgente
            src_item = QTableWidgetItem(f.source)
            src_item.setFlags(src_item.flags() & ~Qt.ItemIsEditable)
            self.table.setItem(row, 3, src_item)

        if not findings:
            self.details_pane.setHtml("<div style='color: #6b7280; font-family: sans-serif; text-align: center; margin-top: 50px;'>Nessun finding corrisponde ai filtri selezionati.</div>")
        else:
            # Ripristina la selezione del primo elemento se presente
            self.table.selectRow(0)

    def _on_row_selected(self):
        selected_ranges = self.table.selectedRanges()
        if not selected_ranges:
            self.controller.select_finding(None)
            return

        row = selected_ranges[0].topRow()
        if 0 <= row < len(self._current_findings):
            self.controller.select_finding(self._current_findings[row])

    @Slot(object)
    def display_details(self, finding: Optional[FindingModel]):
        """
        Visualizza i dettagli del finding nel pannello di destra.
        """
        if not finding:
            self.details_pane.setHtml("<div style='color: #6b7280; font-family: sans-serif; text-align: center; margin-top: 50px;'>Seleziona un finding per vederne i dettagli.</div>")
            return

        # Costruisce il layout in HTML Premium per il QTextBrowser
        severity_color = SEVERITY_COLORS.get(finding.severity, "#6b7280")
        
        # Sezione codice snippet
        snippet_html = ""
        if finding.code_snippet:
            snippet_html = f"""
            <h3>Codice Sorgente Rilevante</h3>
            <pre style='background-color: #080b11; border: 1px solid rgba(255,255,255,0.06); padding: 10px; border-radius: 6px; color: #a7f3d0; font-family: "JetBrains Mono", monospace; font-size: 11px; overflow-x: auto;'>{finding.code_snippet}</pre>
            """

        # Sezione evidenze dinamiche
        evidence_html = ""
        evidence = finding.evidence_details
        if evidence:
            rows = ""
            for k, v in evidence.items():
                rows += f"<tr><td style='padding: 6px 12px; font-weight: bold; width: 180px;'>{k}:</td><td style='padding: 6px 12px; font-family: monospace;'>{v}</td></tr>"
            evidence_html = f"""
            <h3>Evidenze Empiriche a Runtime (D-AST)</h3>
            <table style='width: 100%; border-collapse: collapse; border: 1px solid rgba(255,255,255,0.05); font-size: 12px; background: rgba(20,27,45,0.4);'>
                {rows}
            </table>
            """

        html = f"""
        <div style='font-family: sans-serif; color: #e5e7eb; line-height: 1.6; padding: 10px;'>
            
            <div style='border-bottom: 1px solid rgba(255,255,255,0.08); padding-bottom: 12px; margin-bottom: 16px;'>
                <span style='background-color: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 4px; padding: 2px 6px; font-size: 11px; font-family: monospace;'>{finding.id}</span>
                <h2 style='margin: 8px 0; color: #ffffff;'>{finding.title}</h2>
                <div style='margin-top: 8px;'>
                    <span style='color: {severity_color}; font-weight: bold; font-size: 11px; text-transform: uppercase;'>{finding.severity} (Score: {finding.risk_score})</span>
                    <span style='color: #9ca3af; margin: 0 8px;'>|</span>
                    <span style='color: #9ca3af; font-size: 12px;'>Sorgente: <strong>{finding.source}</strong></span>
                    <span style='color: #9ca3af; margin: 0 8px;'>|</span>
                    <span style='color: #9ca3af; font-size: 12px;'>Categoria: <strong>{finding.category}</strong></span>
                </div>
            </div>

            <h3>Descrizione della Vulnerabilità</h3>
            <p style='color: #d1d5db; font-size: 13px;'>{finding.description}</p>

            <table style='width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 12px; background: rgba(255,255,255,0.01);'>
                <tr>
                    <td style='padding: 6px 0; font-weight: bold; width: 120px; color: #9ca3af;'>File Rilevato:</td>
                    <td style='padding: 6px 0;'><code>{finding.file_path or "N/A"}</code></td>
                </tr>
                <tr>
                    <td style='padding: 6px 0; font-weight: bold; color: #9ca3af;'>Righe:</td>
                    <td style='padding: 6px 0;'>{finding.line_info}</td>
                </tr>
                <tr>
                    <td style='padding: 6px 0; font-weight: bold; color: #9ca3af;'>Risorsa Target:</td>
                    <td style='padding: 6px 0;'><code>{finding.resource}</code></td>
                </tr>
                {"<tr><td style='padding: 6px 0; font-weight: bold; color: #9ca3af;'>CWE:</td><td style='padding: 6px 0;'>CWE-" + finding.cwe + "</td></tr>" if finding.cwe else ""}
                {"<tr><td style='padding: 6px 0; font-weight: bold; color: #9ca3af;'>CVE:</td><td style='padding: 6px 0;'>" + finding.cve + "</td></tr>" if finding.cve else ""}
                {"<tr><td style='padding: 6px 0; font-weight: bold; color: #9ca3af;'>OWASP API:</td><td style='padding: 6px 0;'>" + finding.owasp_category + "</td></tr>" if finding.owasp_category else ""}
            </table>

            {snippet_html}
            {evidence_html}

            <div style='margin-top: 24px; padding: 16px; background-color: rgba(56, 189, 248, 0.08); border-left: 4px solid #38bdf8; border-radius: 4px;'>
                <h4 style='margin: 0 0 8px 0; color: #38bdf8; text-transform: uppercase; letter-spacing: 0.5px; font-size: 12px;'>Azione Correttiva Suggerita</h4>
                <p style='margin: 0; color: #e5e7eb; font-size: 13px;'>{finding.remediation}</p>
            </div>

            <div style='margin-top: 15px; font-size: 10px; color: #6b7280;'>
                Rilevato il: {finding.detected_at}
            </div>

        </div>
        """
        self.details_pane.setHtml(html)
