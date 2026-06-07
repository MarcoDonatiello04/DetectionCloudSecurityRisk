"""
Gestisce l'esportazione dei report di sicurezza.
Responsabilità:
- Generare report in formato HTML/Markdown riassuntivi a partire dai modelli correnti.
- Salvare i file all'interno della cartella dei report (reports/).
"""

import os
import logging
from datetime import datetime
from typing import List
from cloud_security_analyzer.models.finding_model import FindingModel
from cloud_security_analyzer.models.cloud_risk_model import CloudRiskModel

logger = logging.getLogger("SecurityPlatform.GUI.ExportService")

class ExportService:
    """
    Servizio per l'esportazione offline di report strutturati.
    """

    def __init__(self, reports_dir: str):
        """
        Inizializza con la directory dei report destinazione.
        """
        self.reports_dir = os.path.abspath(reports_dir)
        os.makedirs(self.reports_dir, exist_ok=True)

    def export_to_markdown(self, risk_model: CloudRiskModel, findings: List[FindingModel]) -> str:
        """
        Genera un report Markdown dettagliato dei findings correnti.
        Ritorna il percorso del file generato.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_summary_{timestamp}.md"
        filepath = os.path.join(self.reports_dir, filename)

        try:
            lines = [
                "# Rapporto di Sicurezza Cloud & API",
                f"Generato il: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "",
                "## 1. Riepilogo del Rischio",
                f"- **Indice di Rischio Globale:** {risk_model.global_risk_score}/10 ({risk_model.status_summary})",
                f"- **Totale Vulnerabilità:** {risk_model.total_findings}",
                f"  - 🔴 Critiche: {risk_model.critical_count}",
                f"  - 🟠 Alte: {risk_model.high_count}",
                f"  - 🟡 Medie: {risk_model.medium_count}",
                f"  - 🔵 Basse: {risk_model.low_count}",
                f"  - 🟢 Info: {risk_model.info_count}",
                f"- **Vulnerabilità Convalidate Empiricamente (CONFIRMED):** {risk_model.confirmed_count}",
                "",
                "## 2. Stato Catalogo API",
                f"- **Totale Endpoint Rilevati:** {risk_model.stats.get('api_total', 0)}",
                f"  - Documentati: {risk_model.stats.get('api_documented', 0)}",
                f"  - Non Documentati (Shadow APIs): {risk_model.stats.get('api_shadow', 0)}",
                f"  - Violazioni di conformità OpenAPI: {risk_model.stats.get('api_violations', 0)}",
                f"  - Endpoint Vulnerabili a BOLA: {risk_model.stats.get('bola_vulnerable', 0)}",
                "",
                "## 3. Dettaglio dei Findings Rilevati",
                "| ID | Sorgente | Severità | Categoria | Titolo | Stato |",
                "|---|---|---|---|---|---|",
            ]

            for f in findings:
                status_emoji = "🔴" if f.is_confirmed else "⚪"
                lines.append(f"| `{f.id}` | {f.source} | {f.severity} | {f.category} | {f.title} | {status_emoji} {f.validation_status} |")

            lines.append("\n## 4. Remediation consigliate")
            for f in findings:
                if f.severity in ["CRITICAL", "HIGH", "MEDIUM"]:
                    lines.extend([
                        f"### [{f.severity}] {f.title} (`{f.id}`)",
                        f"**Descrizione:** {f.description}",
                        f"**Posizione:** `{f.file_path}` {f.line_info}",
                        f"**Azione Correttiva:** {f.remediation}",
                        ""
                    ])

            with open(filepath, "w", encoding="utf-8") as file:
                file.write("\n".join(lines))

            logger.info(f"Esportato con successo il report Markdown in: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Errore durante la generazione del report markdown: {e}", exc_info=True)
            raise RuntimeError(f"Esportazione fallita: {str(e)}")

    def export_to_html(self, risk_model: CloudRiskModel, findings: List[FindingModel]) -> str:
        """
        Genera un report HTML premium stampabile dei findings correnti.
        Ritorna il percorso del file generato.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_summary_{timestamp}.html"
        filepath = os.path.join(self.reports_dir, filename)

        try:
            findings_rows = ""
            for f in findings:
                badge_class = f"badge-{f.severity.lower()}"
                status_badge = "badge-confirmed" if f.is_confirmed else "badge-unvalidated"
                findings_rows += f"""
                <tr>
                    <td><code>{f.id}</code></td>
                    <td>{f.source}</td>
                    <td><span class="badge {badge_class}">{f.severity}</span></td>
                    <td>{f.category}</td>
                    <td>{f.title}</td>
                    <td><span class="badge {status_badge}">{f.validation_status}</span></td>
                </tr>
                """

            remediation_cards = ""
            for f in findings:
                if f.severity in ["CRITICAL", "HIGH"]:
                    remediation_cards += f"""
                    <div class="card">
                        <div class="card-header">
                            <span class="badge badge-{f.severity.lower()}">{f.severity}</span>
                            <strong>{f.title}</strong> (<code>{f.id}</code>)
                        </div>
                        <div class="card-body">
                            <p><strong>Descrizione:</strong> {f.description}</p>
                            <p><strong>Posizione:</strong> <code>{f.file_path}</code> {f.line_info}</p>
                            <p class="remediation-text"><strong>Azione Correttiva:</strong> {f.remediation}</p>
                        </div>
                    </div>
                    """

            html_content = f"""<!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>Rapporto di Sicurezza Cloud Security Analyzer</title>
                <style>
                    body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #f4f6f9; color: #333; margin: 0; padding: 30px; }}
                    .container {{ max-width: 1100px; margin: 0 auto; background: #fff; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.05); }}
                    h1 {{ color: #0f172a; border-bottom: 2px solid #e2e8f0; padding-bottom: 15px; margin-top: 0; }}
                    h2 {{ color: #1e293b; margin-top: 30px; border-bottom: 1px solid #e2e8f0; padding-bottom: 10px; }}
                    .meta {{ font-size: 0.9em; color: #64748b; margin-bottom: 30px; }}
                    .grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 30px; }}
                    .stat-box {{ background: #f8fafc; border: 1px solid #e2e8f0; padding: 20px; border-radius: 8px; text-align: center; }}
                    .stat-value {{ font-size: 2em; font-weight: bold; color: #0f172a; margin-top: 10px; }}
                    .risk-badge {{ display: inline-block; padding: 5px 15px; border-radius: 30px; font-weight: bold; font-size: 0.9em; }}
                    .risk-crit {{ background-color: #fee2e2; color: #ef4444; }}
                    .risk-high {{ background-color: #fef3c7; color: #d97706; }}
                    .risk-med {{ background-color: #e0e7ff; color: #4f46e5; }}
                    .risk-low {{ background-color: #e0f2fe; color: #0284c7; }}
                    table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
                    th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }}
                    th {{ background-color: #f8fafc; color: #475569; }}
                    .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 0.75em; font-weight: bold; text-transform: uppercase; }}
                    .badge-critical {{ background: #fee2e2; color: #ef4444; }}
                    .badge-high {{ background: #ffedd5; color: #f97316; }}
                    .badge-medium {{ background: #e0e7ff; color: #6366f1; }}
                    .badge-low {{ background: #e0f2fe; color: #0ea5e9; }}
                    .badge-info {{ background: #f1f5f9; color: #64748b; }}
                    .badge-confirmed {{ background: #d1fae5; color: #10b981; }}
                    .badge-unvalidated {{ background: #f1f5f9; color: #94a3b8; }}
                    .card {{ border: 1px solid #e2e8f0; border-radius: 8px; margin-bottom: 15px; background: #fff; overflow: hidden; }}
                    .card-header {{ background: #f8fafc; padding: 12px 20px; border-bottom: 1px solid #e2e8f0; }}
                    .card-body {{ padding: 20px; }}
                    .remediation-text {{ background: #eff6ff; padding: 15px; border-radius: 6px; border-left: 4px solid #3b82f6; color: #1e3a8a; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Rapporto di Sicurezza Cloud &amp; API</h1>
                    <div class="meta">Generato in data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Piattaforma: Cloud Security Analyzer</div>
                    
                    <div class="grid">
                        <div class="stat-box">
                            <div>Indice di Rischio Globale</div>
                            <div class="stat-value">{risk_model.global_risk_score}/10</div>
                            <div style="margin-top: 10px;">
                                <span class="risk-badge risk-{"crit" if risk_model.global_risk_score >= 7.0 else "med" if risk_model.global_risk_score >= 4.5 else "low"}">{risk_model.status_summary}</span>
                            </div>
                        </div>
                        <div class="stat-box">
                            <div>Totale Vulnerabilità</div>
                            <div class="stat-value">{risk_model.total_findings}</div>
                            <div style="margin-top: 10px; font-size: 0.85em; color: #64748b;">Critiche/Alte: {risk_model.critical_count + risk_model.high_count}</div>
                        </div>
                        <div class="stat-box">
                            <div>Vulnerabilità Convalidate</div>
                            <div class="stat-value">{risk_model.confirmed_count}</div>
                            <div style="margin-top: 10px; font-size: 0.85em; color: #64748b;">Prove empiriche a runtime</div>
                        </div>
                    </div>

                    <h2>Vulnerabilità Rilevate</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>ID Finding</th>
                                <th>Sorgente</th>
                                <th>Severità</th>
                                <th>Categoria</th>
                                <th>Titolo</th>
                                <th>Stato Convalida</th>
                            </tr>
                        </thead>
                        <tbody>
                            {findings_rows}
                        </tbody>
                    </table>

                    <h2>Piani di Mitigazione Consigliati (Critici ed Alti)</h2>
                    {remediation_cards}
                </div>
            </body>
            </html>
            """

            with open(filepath, "w", encoding="utf-8") as file:
                file.write(html_content)

            logger.info(f"Esportato con successo il report HTML in: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Errore durante la generazione del report HTML: {e}", exc_info=True)
            raise RuntimeError(f"Esportazione fallita: {str(e)}")
