import os
import json
import logging
from typing import List, Dict, Any
from src.domain.entities import Finding

logger = logging.getLogger("SecurityPlatform.DashboardGenerator")


class APIDashboardGenerator:
    """
    Generatore di dashboard HTML/CSS/JS interattive Premium.
    Produce una visualizzazione ricca di informazioni per l'analisi dei rischi,
    con grafici CSS, filtri interattivi, dettagli dell'inventario API ed evidenze a runtime.
    """

    def __init__(self, findings: List[Finding]):
        self.findings = findings

    def generate(self, output_path: str):
        """Genera e salva la dashboard HTML con i dati incorporati."""
        serialized_findings = [f.to_dict() for f in self.findings]
        
        # Generiamo statistiche aggregate
        stats = self._calculate_stats(self.findings)
        
        html_content = self._get_template(
            json.dumps(serialized_findings, ensure_ascii=False),
            json.dumps(stats, ensure_ascii=False)
        )
        
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            logger.info(f"✨ Dashboard interattiva premium creata in: {output_path}")
        except Exception as e:
            logger.error(f"Errore durante la scrittura della dashboard: {e}", exc_info=True)

    def _calculate_stats(self, findings: List[Finding]) -> Dict[str, Any]:
        stats = {
            "total": len(findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "confirmed": 0,
            "static_only": 0,
            "runtime_only": 0,
            "categories": {}
        }
        
        for f in findings:
            # Severità
            sev_key = f.severity.value.lower()
            if sev_key in stats:
                stats[sev_key] += 1
                
            # Convalida
            if f.validation_status.value == "CONFIRMED":
                stats["confirmed"] += 1
            
            # Categoria
            cat_name = f.category.value
            stats["categories"][cat_name] = stats["categories"].get(cat_name, 0) + 1
            
            # Classificazione sorgenti
            if f.source.value in ("RUNTIME_VALIDATOR", "SHADOW_API", "ZAP_DAST"):
                stats["runtime_only"] += 1
            else:
                stats["static_only"] += 1
                
        return stats

    def _get_template(self, findings_json: str, stats_json: str) -> str:
        return f"""<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloud API Security & Risk Dashboard</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    
    <style>
        :root {{
            --bg-main: #0b0f19;
            --bg-card: rgba(30, 41, 59, 0.7);
            --bg-input: #1e293b;
            --border-color: rgba(255, 255, 255, 0.08);
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --color-sky: #38bdf8;
            --color-indigo: #6366f1;
            --color-emerald: #10b981;
            --color-rose: #f43f5e;
            --color-amber: #f59e0b;
            --glow-color: rgba(56, 189, 248, 0.15);
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Outfit', sans-serif;
        }}

        body {{
            background-color: var(--bg-main);
            color: var(--text-primary);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            overflow-x: hidden;
            background-image: 
                radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.1) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(56, 189, 248, 0.1) 0px, transparent 50%);
        }}

        header {{
            background: rgba(15, 23, 42, 0.8);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--border-color);
            padding: 1.2rem 2.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
        }}

        .logo-section {{
            display: flex;
            align-items: center;
            gap: 0.8rem;
        }}

        .logo-badge {{
            background: linear-gradient(135deg, var(--color-sky), var(--color-indigo));
            width: 40px;
            height: 40px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 800;
            font-size: 1.3rem;
            color: #fff;
            box-shadow: 0 0 15px rgba(56, 189, 248, 0.4);
        }}

        .logo-title h1 {{
            font-size: 1.4rem;
            font-weight: 700;
            background: linear-gradient(to right, #ffffff, #cbd5e1);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        .logo-title p {{
            font-size: 0.75rem;
            color: var(--color-sky);
            text-transform: uppercase;
            letter-spacing: 2px;
            font-weight: 600;
        }}

        main {{
            flex: 1;
            padding: 2rem 2.5rem;
            max-width: 1600px;
            width: 100%;
            margin: 0 auto;
        }}

        /* Grid per statistiche */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2.5rem;
        }}

        .stat-card {{
            background: var(--bg-card);
            backdrop-filter: blur(16px);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            transition: all 0.3s ease;
        }}

        .stat-card:hover {{
            transform: translateY(-4px);
            box-shadow: 0 10px 20px var(--glow-color);
            border-color: rgba(56, 189, 248, 0.2);
        }}

        .stat-label {{
            font-size: 0.8rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 0.5rem;
        }}

        .stat-value {{
            font-size: 2.4rem;
            font-weight: 800;
            background: linear-gradient(to right, #ffffff, #f1f5f9);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        .stat-card.stat-critical .stat-value {{ color: var(--color-rose); -webkit-text-fill-color: var(--color-rose); }}
        .stat-card.stat-high .stat-value {{ color: var(--color-amber); -webkit-text-fill-color: var(--color-amber); }}
        .stat-card.stat-confirmed .stat-value {{ color: var(--color-emerald); -webkit-text-fill-color: var(--color-emerald); }}

        /* Layout principale */
        .content-layout {{
            display: grid;
            grid-template-columns: 320px 1fr;
            gap: 2rem;
        }}

        .sidebar {{
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
        }}

        .sidebar-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 1.5rem;
        }}

        .sidebar-card h3 {{
            font-size: 1rem;
            font-weight: 700;
            margin-bottom: 1rem;
            color: #fff;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 0.5rem;
        }}

        /* Filtri */
        .filter-section {{
            display: flex;
            flex-direction: column;
            gap: 0.6rem;
        }}

        .filter-btn {{
            background: rgba(30, 41, 59, 0.3);
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            padding: 0.6rem 1rem;
            border-radius: 8px;
            cursor: pointer;
            text-align: left;
            font-size: 0.9rem;
            font-weight: 500;
            transition: all 0.2s ease;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .filter-btn:hover, .filter-btn.active {{
            color: #fff;
            background: var(--bg-input);
            border-color: var(--color-sky);
        }}

        .badge {{
            background: rgba(255,255,255,0.08);
            padding: 0.1rem 0.4rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-family: 'JetBrains Mono', monospace;
        }}

        /* Card dei Findings */
        .findings-list {{
            display: flex;
            flex-direction: column;
            gap: 1.2rem;
        }}

        .finding-card {{
            background: var(--bg-card);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 1.5rem;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }}

        .finding-card:hover {{
            border-color: rgba(99, 102, 241, 0.25);
            box-shadow: 0 8px 24px rgba(99, 102, 241, 0.05);
            transform: scale(1.005);
        }}

        .finding-card::before {{
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            bottom: 0;
            width: 4px;
        }}

        .finding-card.sev-critical::before {{ background-color: var(--color-rose); }}
        .finding-card.sev-high::before {{ background-color: var(--color-amber); }}
        .finding-card.sev-medium::before {{ background-color: var(--color-indigo); }}
        .finding-card.sev-low::before {{ background-color: var(--color-sky); }}
        .finding-card.sev-info::before {{ background-color: var(--text-secondary); }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 0.8rem;
            gap: 1rem;
        }}

        .finding-title {{
            font-size: 1.15rem;
            font-weight: 700;
            color: #fff;
        }}

        .finding-meta {{
            display: flex;
            align-items: center;
            gap: 0.6rem;
            flex-wrap: wrap;
        }}

        .severity-tag {{
            font-size: 0.75rem;
            font-weight: 700;
            padding: 0.2rem 0.6rem;
            border-radius: 30px;
            text-transform: uppercase;
        }}

        .sev-critical .severity-tag {{ background: rgba(244, 63, 94, 0.15); color: var(--color-rose); }}
        .sev-high .severity-tag {{ background: rgba(245, 158, 11, 0.15); color: var(--color-amber); }}
        .sev-medium .severity-tag {{ background: rgba(99, 102, 241, 0.15); color: var(--color-indigo); }}
        .sev-low .severity-tag {{ background: rgba(56, 189, 248, 0.15); color: var(--color-sky); }}
        .sev-info .severity-tag {{ background: rgba(255,255,255,0.08); color: var(--text-secondary); }}

        .source-tag {{
            background: rgba(255,255,255,0.05);
            font-size: 0.75rem;
            font-family: 'JetBrains Mono', monospace;
            padding: 0.2rem 0.5rem;
            border-radius: 6px;
            border: 1px solid rgba(255, 255, 255, 0.08);
        }}

        .validation-tag {{
            background: rgba(16, 185, 129, 0.1);
            color: var(--color-emerald);
            font-size: 0.75rem;
            font-weight: 600;
            padding: 0.2rem 0.5rem;
            border-radius: 6px;
            border: 1px solid rgba(16, 185, 129, 0.2);
        }}

        .finding-body {{
            font-size: 0.95rem;
            line-height: 1.5;
            color: var(--text-secondary);
            margin-bottom: 1rem;
        }}

        .finding-context {{
            background: rgba(15, 23, 42, 0.4);
            border-radius: 8px;
            border: 1px solid var(--border-color);
            padding: 0.8rem;
            margin-bottom: 1rem;
            font-size: 0.85rem;
            display: flex;
            flex-direction: column;
            gap: 0.4rem;
        }}

        .context-row span {{
            font-weight: 600;
            color: #fff;
        }}

        .context-code {{
            font-family: 'JetBrains Mono', monospace;
            background: #05070c;
            padding: 0.6rem;
            border-radius: 6px;
            border: 1px solid rgba(255,255,255,0.04);
            font-size: 0.8rem;
            color: #38bdf8;
            overflow-x: auto;
            margin-top: 0.4rem;
        }}

        .remediation-section {{
            background: rgba(16, 185, 129, 0.04);
            border: 1px solid rgba(16, 185, 129, 0.12);
            border-radius: 8px;
            padding: 0.8rem;
            font-size: 0.9rem;
            color: var(--text-primary);
        }}

        .remediation-section h4 {{
            font-size: 0.85rem;
            font-weight: 700;
            color: var(--color-emerald);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 0.3rem;
        }}

        .empty-state {{
            padding: 4rem;
            text-align: center;
            color: var(--text-secondary);
            background: var(--bg-card);
            border-radius: 16px;
            border: 1px solid var(--border-color);
        }}

        .empty-icon {{
            font-size: 3.5rem;
            margin-bottom: 1rem;
        }}

        /* Responsive */
        @media (max-width: 900px) {{
            .content-layout {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>

    <header>
        <div class="logo-section">
            <div class="logo-badge">🛡️</div>
            <div class="logo-title">
                <h1>Security Platform Core</h1>
                <p>Cloud Security Risk & Remediation</p>
            </div>
        </div>
        <div>
            <span class="badge" style="background: rgba(99, 102, 241, 0.2); color: #818cf8; padding: 0.4rem 0.8rem; border-radius: 30px;">
                v1.0.0 Stable
            </span>
        </div>
    </header>

    <main>
        <!-- Row statistiche -->
        <div class="stats-grid">
            <div class="stat-card">
                <span class="stat-label">Rischi Totali</span>
                <span class="stat-value" id="stats-total">0</span>
            </div>
            <div class="stat-card stat-critical">
                <span class="stat-label">Critici / Alti</span>
                <span class="stat-value" id="stats-critical-high">0</span>
            </div>
            <div class="stat-card stat-confirmed">
                <span class="stat-label">Convalidati Runtime</span>
                <span class="stat-value" id="stats-confirmed">0</span>
            </div>
            <div class="stat-card">
                <span class="stat-label">Static Only</span>
                <span class="stat-value" id="stats-static">0</span>
            </div>
        </div>

        <div class="content-layout">
            <!-- Sidebar filtri -->
            <div class="sidebar">
                <div class="sidebar-card">
                    <h3>Filtra per Severità</h3>
                    <div class="filter-section">
                        <button class="filter-btn active" onclick="filterSeverity('ALL', this)">
                            Tutte 
                        </button>
                        <button class="filter-btn" onclick="filterSeverity('CRITICAL', this)">
                            Critico <span class="badge" style="color: var(--color-rose);" id="count-crit">0</span>
                        </button>
                        <button class="filter-btn" onclick="filterSeverity('HIGH', this)">
                            Alto <span class="badge" style="color: var(--color-amber);" id="count-high">0</span>
                        </button>
                        <button class="filter-btn" onclick="filterSeverity('MEDIUM', this)">
                            Medio <span class="badge" style="color: var(--color-indigo);" id="count-med">0</span>
                        </button>
                    </div>
                </div>

                <div class="sidebar-card">
                    <h3>Filtra per Convalida</h3>
                    <div class="filter-section">
                        <button class="filter-btn active" onclick="filterValidation('ALL', this)">
                            Tutti
                        </button>
                        <button class="filter-btn" onclick="filterValidation('CONFIRMED', this)">
                            Solo Convalidati (Runtime)
                        </button>
                        <button class="filter-btn" onclick="filterValidation('NOT_VALIDATED', this)">
                            Solo Statici
                        </button>
                    </div>
                </div>
            </div>

            <!-- Lista dei Rischi -->
            <div>
                <div class="findings-list" id="findings-container">
                    <!-- Popolato via JS -->
                </div>
                
                <div class="empty-state" id="findings-empty" style="display: none;">
                    <div class="empty-icon">🟢</div>
                    <h3>Tutto Pulito!</h3>
                    <p style="margin-top: 0.5rem;">Nessun rischio di sicurezza corrisponde ai filtri impostati.</p>
                </div>
            </div>
        </div>
    </main>

    <script>
        const findingsData = {findings_json};
        const statsData = {stats_json};
        
        let activeSeverity = 'ALL';
        let activeValidation = 'ALL';

        document.addEventListener('DOMContentLoaded', () => {{
            renderStats();
            renderFindings();
        }});

        function renderStats() {{
            document.getElementById('stats-total').innerText = statsData.total;
            document.getElementById('stats-critical-high').innerText = statsData.critical + statsData.high;
            document.getElementById('stats-confirmed').innerText = statsData.confirmed;
            document.getElementById('stats-static').innerText = statsData.static_only;

            document.getElementById('count-crit').innerText = statsData.critical;
            document.getElementById('count-high').innerText = statsData.high;
            document.getElementById('count-med').innerText = statsData.medium;
        }}

        function filterSeverity(severity, btn) {{
            document.querySelectorAll('.sidebar-card:nth-child(1) .filter-btn').forEach(el => el.classList.remove('active'));
            btn.classList.add('active');
            activeSeverity = severity;
            renderFindings();
        }}

        function filterValidation(validation, btn) {{
            document.querySelectorAll('.sidebar-card:nth-child(2) .filter-btn').forEach(el => el.classList.remove('active'));
            btn.classList.add('active');
            activeValidation = validation;
            renderFindings();
        }}

        function renderFindings() {{
            const container = document.getElementById('findings-container');
            container.innerHTML = '';
            
            const filtered = findingsData.filter(f => {{
                const matchSev = activeSeverity === 'ALL' || f.severity === activeSeverity;
                const matchVal = activeValidation === 'ALL' || 
                                (activeValidation === 'CONFIRMED' && f.validation_status === 'CONFIRMED') ||
                                (activeValidation === 'NOT_VALIDATED' && f.validation_status !== 'CONFIRMED');
                return matchSev && matchVal;
            }});

            if (filtered.length === 0) {{
                document.getElementById('findings-empty').style.display = 'block';
                return;
            }}
            document.getElementById('findings-empty').style.display = 'none';

            filtered.forEach(f => {{
                const card = document.createElement('div');
                card.className = `finding-card sev-${{f.severity.toLowerCase()}}`;
                
                let contextHtml = '';
                if (f.api && f.api.endpoint) {{
                    contextHtml += `<div class="context-row"><span>Endpoint:</span> ${{f.api.method || 'GET'}} ${{f.api.endpoint}}</div>`;
                }}
                if (f.location && f.location.file_path) {{
                    const line = f.location.start_line ? ` (Linea ${{f.location.start_line}})` : '';
                    contextHtml += `<div class="context-row"><span>Sorgente:</span> ${{f.location.file_path}}${{line}}</div>`;
                }}
                if (f.resource_id) {{
                    contextHtml += `<div class="context-row"><span>Risorsa Cloud:</span> ${{f.resource_id}}</div>`;
                }}
                if (f.raw_data && f.raw_data.correlated_risk_score) {{
                    contextHtml += `<div class="context-row"><span>Punteggio Rischio Correlato:</span> <strong style="color: var(--color-rose);">${{f.raw_data.correlated_risk_score}} / 10.0</strong></div>`;
                }}

                let runtimeHtml = '';
                if (f.runtime_evidence) {{
                    runtimeHtml += `
                        <div class="context-code">
                            [Evidenza Runtime]<br>
                            URL Testato: ${{f.runtime_evidence.tested_url || 'N/D'}}<br>
                            Status Risposta: ${{f.runtime_evidence.http_status || 'N/D'}}<br>
                            ${{f.runtime_evidence.response_snippet ? 'Snippet Risposta: ' + f.runtime_evidence.response_snippet : ''}}
                        </div>`;
                }}

                let remediationHtml = '';
                if (f.remediation) {{
                    remediationHtml = `
                        <div class="remediation-section">
                            <h4>Rimedio Suggerito</h4>
                            <p>${{f.remediation}}</p>
                        </div>`;
                }}

                const validationTag = f.validation_status === 'CONFIRMED' 
                    ? `<span class="validation-tag">✓ Convalidato a Runtime</span>` 
                    : '';

                card.innerHTML = `
                    <div class="finding-header">
                        <div>
                            <span class="severity-tag">${{f.severity}}</span>
                            <span class="source-tag">${{f.source}}</span>
                            ${{validationTag}}
                        </div>
                        <div style="font-size: 0.8rem; color: var(--text-secondary);">
                            ${{new Date(f.detected_at).toLocaleDateString()}}
                        </div>
                    </div>
                    <div class="finding-title">${{f.title}}</div>
                    <div class="finding-body">${{f.description}}</div>
                    
                    ${{contextHtml || runtimeHtml ? `
                        <div class="finding-context">
                            ${{contextHtml}}
                            ${{runtimeHtml}}
                        </div>
                    ` : ''}}

                    ${{remediationHtml}}
                `;
                
                container.appendChild(card);
            }});
        }}
    </script>
</body>
</html>
"""
