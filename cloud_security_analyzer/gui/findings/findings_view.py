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
from PySide6.QtGui import QFont, QColor

from cloud_security_analyzer.core.config import SEVERITY_COLORS
from cloud_security_analyzer.widgets.search_bar import SearchBar
from cloud_security_analyzer.widgets.filter_panel import FilterPanel
from cloud_security_analyzer.widgets.severity_badge import SeverityBadge
from cloud_security_analyzer.widgets.risk_card import RiskCard
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

        # 2. Controlli Filtri (Cerca + Chips Severità stacked verticalmente)
        controls_layout = QVBoxLayout()
        controls_layout.setSpacing(10)
        controls_layout.setContentsMargins(0, 0, 0, 0)

        # Cerca
        search_layout = QHBoxLayout()
        self.search_bar = SearchBar("Cerca per titolo, file, risorsa, CVE...", self)
        self.search_bar.textChanged.connect(self.controller.set_search_query)
        search_layout.addWidget(self.search_bar)
        controls_layout.addLayout(search_layout)

        # Chips di severità
        filter_layout = QHBoxLayout()
        self.filter_panel = FilterPanel(self)
        self.filter_panel.severity_toggled.connect(self.controller.toggle_severity)
        filter_layout.addWidget(self.filter_panel)
        filter_layout.addStretch()
        controls_layout.addLayout(filter_layout)

        main_layout.addLayout(controls_layout)

        # 2.5 Metrics Panel (RiskCards per remediation source - super compatte per evitare squeezing)
        self.metrics_layout = QHBoxLayout()
        self.metrics_layout.setSpacing(16)
        
        self.card_total = RiskCard("Totale Findings", "0", "#38bdf8", self)
        self.card_total.setFixedHeight(82)
        
        self.card_kb = RiskCard("KB Locale", "0", "#10b981", self)
        self.card_kb.setFixedHeight(82)
        
        self.card_llm = RiskCard("🦙 Llama LLM", "0", "#8b5cf6", self)
        self.card_llm.setFixedHeight(82)
        
        self.card_cache = RiskCard("Cache Locale", "0", "#06b6d4", self)
        self.card_cache.setFixedHeight(82)
        
        self.metrics_layout.addWidget(self.card_total)
        self.metrics_layout.addWidget(self.card_kb)
        self.metrics_layout.addWidget(self.card_llm)
        self.metrics_layout.addWidget(self.card_cache)
        
        main_layout.addLayout(self.metrics_layout)

        # 3. Master-Detail Splitter
        splitter = QSplitter(Qt.Horizontal, self)
        splitter.setStyleSheet("QSplitter::handle { background-color: rgba(255, 255, 255, 0.05); width: 2px; }")

        # Sinistra: Tabella Master
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)

        self.table = QTableWidget(self)
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["SEVERITÀ", "ID FINDING", "TITOLO", "SORGENTE", "RISOLUZIONE"])
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
        header.setSectionResizeMode(3, QHeaderView.Fixed)
        self.table.setColumnWidth(3, 110)
        header.setSectionResizeMode(4, QHeaderView.Fixed)
        self.table.setColumnWidth(4, 140)

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
        main_layout.addWidget(splitter, 1)

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

        total_count = len(findings)
        kb_count = 0
        llm_count = 0
        cache_count = 0
        fallback_count = 0

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
            id_item.setForeground(QColor("#e5e7eb"))
            id_item.setFlags(id_item.flags() & ~Qt.ItemIsEditable)
            self.table.setItem(row, 1, id_item)

            # 3. Titolo
            title_item = QTableWidgetItem(f.title)
            title_item.setForeground(QColor("#e5e7eb"))
            title_item.setFlags(title_item.flags() & ~Qt.ItemIsEditable)
            self.table.setItem(row, 2, title_item)

            # 4. Sorgente
            src_item = QTableWidgetItem(f.source)
            src_item.setForeground(QColor("#e5e7eb"))
            src_item.setFlags(src_item.flags() & ~Qt.ItemIsEditable)
            self.table.setItem(row, 3, src_item)

            # 5. Risoluzione
            res_source = self.controller.get_remediation_source_fast(f)
            if res_source == "knowledge_base":
                kb_count += 1
                res_text = "📖 KB Locale"
                res_color = "#10b981"
            elif res_source == "llm":
                llm_count += 1
                res_text = "🦙 Llama LLM"
                res_color = "#8b5cf6"
            elif res_source == "cache":
                cache_count += 1
                res_text = "💾 Cache Locale"
                res_color = "#06b6d4"
            else:
                fallback_count += 1
                res_text = "⚠️ Fallback"
                res_color = "#f59e0b"
            
            res_item = QTableWidgetItem(res_text)
            res_item.setForeground(QColor(res_color))
            res_item.setFont(QFont("Outfit", 9, QFont.Bold))
            res_item.setFlags(res_item.flags() & ~Qt.ItemIsEditable)
            self.table.setItem(row, 4, res_item)

        # Aggiorna le card delle metriche
        self.card_total.set_value(str(total_count))
        self.card_kb.set_value(str(kb_count))
        self.card_llm.set_value(str(llm_count))
        self.card_cache.set_value(str(cache_count))

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

        import html

        # Richiesta del modello arricchito di Remediation
        remediation_model = self.controller.get_remediation(finding)

        # Costruisce il layout in HTML Premium per il QTextBrowser
        severity_color = SEVERITY_COLORS.get(finding.severity, "#6b7280")
        
        # Sezione codice snippet
        snippet_html = ""
        if finding.code_snippet:
            escaped_snippet = html.escape(finding.code_snippet)
            snippet_html = f"""
            <h3>Codice Sorgente Rilevante</h3>
            <pre style='background-color: #080b11; border: 1px solid rgba(255,255,255,0.06); padding: 10px; border-radius: 6px; color: #a7f3d0; font-family: "JetBrains Mono", monospace; font-size: 11px; overflow-x: auto;'>{escaped_snippet}</pre>
            """

        # Sezione evidenze dinamiche
        evidence_html = ""
        evidence = finding.evidence_details
        if evidence:
            rows = ""
            for k, v in evidence.items():
                escaped_v = html.escape(str(v))
                rows += f"<tr><td style='padding: 6px 12px; font-weight: bold; width: 180px;'>{k}:</td><td style='padding: 6px 12px; font-family: monospace;'>{escaped_v}</td></tr>"
            evidence_html = f"""
            <h3>Evidenze Empiriche a Runtime (D-AST)</h3>
            <table style='width: 100%; border-collapse: collapse; border: 1px solid rgba(255,255,255,0.05); font-size: 12px; background: rgba(20,27,45,0.4);'>
                {rows}
            </table>
            """

        # Configurazione badge origine intelligence
        source_lower = remediation_model.source.lower()
        if "knowledge_base" in source_lower:
            source_text = "Knowledge Base Locale"
            source_badge_color = "#10b981"  # Emerald
            source_bg_color = "rgba(16, 185, 129, 0.08)"
        elif "llm" in source_lower:
            source_text = "LLM Ollama Offline"
            source_badge_color = "#8b5cf6"  # Purple
            source_bg_color = "rgba(139, 92, 246, 0.08)"
        elif "cache" in source_lower:
            source_text = "Cache Locale"
            source_badge_color = "#06b6d4"  # Cyan
            source_bg_color = "rgba(6, 182, 212, 0.08)"
        else:
            source_text = "Fallback Locale"
            source_badge_color = "#f59e0b"  # Amber
            source_bg_color = "rgba(245, 158, 11, 0.08)"

        confidence_percent = int(remediation_model.confidence * 100)

        # Sezione Impatto Sicurezza
        impact_html = ""
        if remediation_model.impact:
            is_high_risk = finding.severity.upper() in ["CRITICAL", "HIGH"]
            impact_border = "#ef4444" if is_high_risk else "#f59e0b"
            impact_bg = "rgba(239, 68, 68, 0.06)" if is_high_risk else "rgba(245, 158, 11, 0.06)"
            impact_html = f"""
            <div style='margin-top: 16px; padding: 14px; background-color: {impact_bg}; border-left: 4px solid {impact_border}; border-radius: 4px;'>
                <h4 style='margin: 0 0 6px 0; color: {impact_border}; text-transform: uppercase; letter-spacing: 0.5px; font-size: 11px; font-weight: bold;'>Impatto sulla Sicurezza</h4>
                <p style='margin: 0; color: #e5e7eb; font-size: 13px; line-height: 1.5;'>{html.escape(remediation_model.impact)}</p>
            </div>
            """

        # Sezione Passi di Remediation
        remediation_html = ""
        if remediation_model.remediation_steps:
            steps_items = ""
            for step in remediation_model.remediation_steps:
                steps_items += f"""
                <li style='margin-bottom: 8px; color: #d1d5db; font-size: 13px; line-height: 1.5;'>
                    <span style='color: #38bdf8; font-family: monospace; font-size: 14px; margin-right: 8px;'>[ ]</span> {html.escape(step)}
                </li>
                """
            remediation_html = f"""
            <div style='margin-top: 20px; padding: 16px; background-color: rgba(56, 189, 248, 0.04); border: 1px solid rgba(56, 189, 248, 0.15); border-radius: 6px;'>
                <h4 style='margin: 0 0 12px 0; color: #38bdf8; text-transform: uppercase; letter-spacing: 0.5px; font-size: 11px; font-weight: bold;'>Azioni di Remediation Consigliate (Checklist)</h4>
                <ul style='list-style-type: none; padding-left: 0; margin: 0;'>
                    {steps_items}
                </ul>
            </div>
            """
        else:
            remediation_html = f"""
            <div style='margin-top: 20px; padding: 16px; background-color: rgba(56, 189, 248, 0.08); border-left: 4px solid #38bdf8; border-radius: 4px;'>
                <h4 style='margin: 0 0 8px 0; color: #38bdf8; text-transform: uppercase; letter-spacing: 0.5px; font-size: 12px; font-weight: bold;'>Azione Correttiva Suggerita</h4>
                <p style='margin: 0; color: #e5e7eb; font-size: 13px; line-height: 1.5;'>{html.escape(finding.remediation)}</p>
            </div>
            """

        # Sezione Esempio Configurazione Corretta
        example_html = ""
        if remediation_model.example and remediation_model.example.strip():
            escaped_example = html.escape(remediation_model.example)
            example_html = f"""
            <div style='margin-top: 20px;'>
                <h4 style='margin: 0 0 8px 0; color: #9ca3af; text-transform: uppercase; letter-spacing: 0.5px; font-size: 11px; font-weight: bold;'>Esempio di Configurazione Sicura</h4>
                <pre style='background-color: #0b0f17; border: 1px solid rgba(56, 189, 248, 0.2); padding: 12px; border-radius: 6px; color: #a7f3d0; font-family: "JetBrains Mono", monospace; font-size: 11px; overflow-x: auto; line-height: 1.4;'>{escaped_example}</pre>
            </div>
            """

        # Descrizione arricchita
        description_text = remediation_model.description or finding.description

        html_content = f"""
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
                    <span style='color: #9ca3af; margin: 0 8px;'>|</span>
                    <span style='background-color: {source_bg_color}; border: 1px solid {source_badge_color}; border-radius: 4px; padding: 1px 5px; font-size: 10px; color: {source_badge_color}; font-weight: bold;'>{source_text} ({confidence_percent}%)</span>
                </div>
            </div>

            <h3>Descrizione della Vulnerabilità</h3>
            <p style='color: #d1d5db; font-size: 13px;'>{html.escape(description_text)}</p>

            <table style='width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 12px; background: rgba(255,255,255,0.01);'>
                <tr>
                    <td style='padding: 6px 0; font-weight: bold; width: 120px; color: #9ca3af;'>File Rilevato:</td>
                    <td style='padding: 6px 0;'><code>{html.escape(finding.file_path or "N/A")}</code></td>
                </tr>
                <tr>
                    <td style='padding: 6px 0; font-weight: bold; color: #9ca3af;'>Righe:</td>
                    <td style='padding: 6px 0;'>{finding.line_info}</td>
                </tr>
                <tr>
                    <td style='padding: 6px 0; font-weight: bold; color: #9ca3af;'>Risorsa Target:</td>
                    <td style='padding: 6px 0;'><code>{html.escape(finding.resource)}</code></td>
                </tr>
                {"<tr><td style='padding: 6px 0; font-weight: bold; color: #9ca3af;'>CWE:</td><td style='padding: 6px 0;'>CWE-" + html.escape(finding.cwe) + "</td></tr>" if finding.cwe else ""}
                {"<tr><td style='padding: 6px 0; font-weight: bold; color: #9ca3af;'>CVE:</td><td style='padding: 6px 0;'>" + html.escape(finding.cve) + "</td></tr>" if finding.cve else ""}
                {"<tr><td style='padding: 6px 0; font-weight: bold; color: #9ca3af;'>OWASP API:</td><td style='padding: 6px 0;'>" + html.escape(finding.owasp_category) + "</td></tr>" if finding.owasp_category else ""}
            </table>

            {snippet_html}
            {evidence_html}
            {impact_html}
            {remediation_html}
            {example_html}

            <div style='margin-top: 25px; font-size: 10px; color: #6b7280;'>
                Rilevato il: {finding.detected_at}
            </div>

        </div>
        """
        self.details_pane.setHtml(html_content)
