import os
import json
import logging
from typing import List, Dict, Any
from src.domain.entities import Finding

logger = logging.getLogger("SecurityPlatform.DashboardGenerator")

# Sorgenti per sezione
STATIC_SOURCES   = {"CHECKOV", "SEMGREP"}
OPENAPI_SOURCES  = {"SPECTRAL"}
BOLA_SOURCES     = {"ZAP_DAST", "RUNTIME_VALIDATOR", "SHADOW_API"}


class APIDashboardGenerator:
    """
    Generatore di dashboard HTML/CSS/JS interattive Premium a 3 sezioni:
      1. Analisi Statica     (Checkov + Semgrep)
      2. Conformità OpenAPI  (Spectral contract linting)
      3. Analisi BOLA/D-AST  (ZAP DAST + Runtime Validator)
    """

    def __init__(self, findings: List[Finding]):
        self.findings = findings

    def generate(self, output_path: str):
        """Genera e salva la dashboard HTML con i dati incorporati."""
        serialized = [f.to_dict() for f in self.findings]
        stats = self._calculate_stats(self.findings)

        html_content = self._get_template(
            json.dumps(serialized, ensure_ascii=False),
            json.dumps(stats, ensure_ascii=False)
        )

        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            logger.info(f"✨ Dashboard premium a 3 sezioni creata in: {output_path}")
        except Exception as e:
            logger.error(f"Errore scrittura dashboard: {e}", exc_info=True)

    def _calculate_stats(self, findings: List[Finding]) -> Dict[str, Any]:
        stats = {
            "total":           len(findings),
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
            "confirmed": 0,
            # Contatori per sezione
            "static_total":   0, "static_critical": 0, "static_high": 0,
            "openapi_total":  0, "openapi_high": 0, "openapi_medium": 0,
            "bola_total":     0, "bola_confirmed": 0, "bola_critical": 0,
            "categories": {}
        }

        for f in findings:
            sev = f.severity.value.lower()
            if sev in stats:
                stats[sev] += 1

            if f.validation_status.value == "CONFIRMED":
                stats["confirmed"] += 1

            cat = f.category.value
            stats["categories"][cat] = stats["categories"].get(cat, 0) + 1

            src = f.source.value
            if src in STATIC_SOURCES:
                stats["static_total"] += 1
                if sev == "critical": stats["static_critical"] += 1
                if sev == "high":     stats["static_high"] += 1
            elif src in OPENAPI_SOURCES:
                stats["openapi_total"] += 1
                if sev == "high":   stats["openapi_high"] += 1
                if sev == "medium": stats["openapi_medium"] += 1
            elif src in BOLA_SOURCES:
                stats["bola_total"] += 1
                if f.validation_status.value == "CONFIRMED": stats["bola_confirmed"] += 1
                if sev == "critical": stats["bola_critical"] += 1

        return stats

    def _get_template(self, findings_json: str, stats_json: str) -> str:
        return f"""<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloud API Security &amp; Risk Dashboard</title>
    <meta name="description" content="Dashboard premium di analisi della sicurezza API cloud: analisi statica IaC, conformità OpenAPI e rilevamento BOLA/D-AST.">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">

    <style>
        /* ─── Design Tokens ─────────────────────────────────────────── */
        :root {{
            --bg-main:          #080c16;
            --bg-surface:       #0f1629;
            --bg-card:          rgba(22, 33, 62, 0.75);
            --bg-input:         #1a2744;
            --border:           rgba(255,255,255,0.07);
            --border-active:    rgba(56,189,248,0.35);

            --text-primary:     #f0f6ff;
            --text-secondary:   #7c93b8;
            --text-muted:       #4a6080;

            --sky:      #38bdf8;
            --indigo:   #818cf8;
            --violet:   #a78bfa;
            --emerald:  #10b981;
            --rose:     #fb7185;
            --amber:    #fbbf24;
            --orange:   #f97316;
            --teal:     #14b8a6;

            --glow-sky:     rgba(56,189,248,0.12);
            --glow-indigo:  rgba(129,140,248,0.12);
            --glow-rose:    rgba(251,113,133,0.12);

            /* Tab theme per sezione */
            --tab1-color: var(--sky);
            --tab1-glow:  rgba(56,189,248,0.15);
            --tab2-color: var(--violet);
            --tab2-glow:  rgba(167,139,250,0.15);
            --tab3-color: var(--rose);
            --tab3-glow:  rgba(251,113,133,0.15);
        }}

        *, *::before, *::after {{
            margin: 0; padding: 0;
            box-sizing: border-box;
            font-family: 'Outfit', sans-serif;
        }}

        body {{
            background-color: var(--bg-main);
            color: var(--text-primary);
            min-height: 100vh;
            overflow-x: hidden;
            background-image:
                radial-gradient(ellipse 80% 40% at 0% 0%,   rgba(99,102,241,0.08) 0, transparent 60%),
                radial-gradient(ellipse 60% 50% at 100% 0%, rgba(56,189,248,0.06) 0, transparent 60%),
                radial-gradient(ellipse 50% 40% at 50% 100%,rgba(251,113,133,0.06) 0, transparent 60%);
        }}

        /* ─── Header ────────────────────────────────────────────────── */
        header {{
            background: rgba(8,12,22,0.85);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid var(--border);
            padding: 0 2.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            height: 68px;
            position: sticky;
            top: 0;
            z-index: 200;
            box-shadow: 0 1px 0 rgba(56,189,248,0.05);
        }}

        .logo-section {{
            display: flex;
            align-items: center;
            gap: 0.9rem;
        }}

        .logo-badge {{
            background: linear-gradient(135deg, var(--sky), var(--indigo));
            width: 44px; height: 44px;
            border-radius: 14px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.4rem;
            box-shadow: 0 0 20px rgba(56,189,248,0.35);
            flex-shrink: 0;
        }}

        .logo-title h1 {{
            font-size: 1.3rem;
            font-weight: 700;
            background: linear-gradient(90deg, #ffffff, #94b4d8);
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        .logo-title p {{
            font-size: 0.7rem;
            color: var(--sky);
            text-transform: uppercase;
            letter-spacing: 2.5px;
            font-weight: 600;
            margin-top: 1px;
        }}

        .header-right {{
            display: flex;
            align-items: center;
            gap: 1rem;
        }}

        .version-badge {{
            background: rgba(129,140,248,0.15);
            color: var(--indigo);
            border: 1px solid rgba(129,140,248,0.2);
            padding: 0.3rem 0.8rem;
            border-radius: 30px;
            font-size: 0.75rem;
            font-weight: 600;
        }}

        .scan-time {{
            font-size: 0.72rem;
            color: var(--text-muted);
            font-family: 'JetBrains Mono', monospace;
        }}

        /* ─── Main Layout ────────────────────────────────────────────── */
        main {{
            max-width: 1700px;
            margin: 0 auto;
            padding: 2.5rem 2.5rem 4rem;
        }}

        /* ─── Top Stats Row ──────────────────────────────────────────── */
        .global-stats {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1.2rem;
            margin-bottom: 2.5rem;
        }}

        .gstat {{
            background: var(--bg-card);
            backdrop-filter: blur(16px);
            border: 1px solid var(--border);
            border-radius: 18px;
            padding: 1.4rem 1.6rem;
            position: relative;
            overflow: hidden;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }}

        .gstat:hover {{
            transform: translateY(-3px);
        }}

        .gstat::after {{
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 2px;
            border-radius: 18px 18px 0 0;
        }}

        .gstat-total::after  {{ background: linear-gradient(90deg, var(--sky), var(--indigo)); }}
        .gstat-danger::after {{ background: linear-gradient(90deg, var(--rose), var(--orange)); box-shadow: 0 0 12px var(--glow-rose); }}
        .gstat-conf::after   {{ background: linear-gradient(90deg, var(--emerald), var(--teal)); }}
        .gstat-static::after {{ background: linear-gradient(90deg, var(--sky), var(--teal)); }}

        .gstat-danger:hover  {{ box-shadow: 0 8px 30px var(--glow-rose); }}
        .gstat-total:hover   {{ box-shadow: 0 8px 30px var(--glow-sky); }}
        .gstat-conf:hover    {{ box-shadow: 0 8px 30px rgba(16,185,129,0.12); }}

        .gstat-label {{
            font-size: 0.72rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 1.5px;
            font-weight: 600;
            margin-bottom: 0.6rem;
        }}

        .gstat-value {{
            font-size: 2.8rem;
            font-weight: 800;
            line-height: 1;
            background: linear-gradient(135deg, #ffffff, #c0d4f0);
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        .gstat-danger  .gstat-value {{ background: linear-gradient(135deg, var(--rose), var(--orange)); -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent; }}
        .gstat-conf    .gstat-value {{ background: linear-gradient(135deg, var(--emerald), var(--teal));  -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent; }}

        .gstat-sub {{
            font-size: 0.75rem;
            color: var(--text-muted);
            margin-top: 0.3rem;
        }}

        /* ─── Tab Navigation ─────────────────────────────────────────── */
        .tab-nav {{
            display: flex;
            gap: 0.6rem;
            margin-bottom: 1.8rem;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 0.5rem;
        }}

        .tab-btn {{
            flex: 1;
            background: transparent;
            border: 1px solid transparent;
            color: var(--text-secondary);
            padding: 0.9rem 1.5rem;
            border-radius: 14px;
            cursor: pointer;
            font-size: 0.9rem;
            font-weight: 600;
            transition: all 0.25s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.6rem;
            position: relative;
        }}

        .tab-btn:hover {{
            color: var(--text-primary);
            background: rgba(255,255,255,0.04);
        }}

        .tab-btn.active-tab1 {{
            background: rgba(56,189,248,0.1);
            border-color: rgba(56,189,248,0.25);
            color: var(--sky);
            box-shadow: 0 0 20px rgba(56,189,248,0.08);
        }}

        .tab-btn.active-tab2 {{
            background: rgba(167,139,250,0.1);
            border-color: rgba(167,139,250,0.25);
            color: var(--violet);
            box-shadow: 0 0 20px rgba(167,139,250,0.08);
        }}

        .tab-btn.active-tab3 {{
            background: rgba(251,113,133,0.1);
            border-color: rgba(251,113,133,0.25);
            color: var(--rose);
            box-shadow: 0 0 20px rgba(251,113,133,0.08);
        }}

        .tab-icon {{
            font-size: 1.1rem;
        }}

        .tab-count {{
            background: rgba(255,255,255,0.1);
            padding: 0.15rem 0.5rem;
            border-radius: 30px;
            font-size: 0.72rem;
            font-family: 'JetBrains Mono', monospace;
            font-weight: 700;
        }}

        .active-tab1 .tab-count {{ background: rgba(56,189,248,0.2); color: var(--sky); }}
        .active-tab2 .tab-count {{ background: rgba(167,139,250,0.2); color: var(--violet); }}
        .active-tab3 .tab-count {{ background: rgba(251,113,133,0.2); color: var(--rose); }}

        /* ─── Tab Content ────────────────────────────────────────────── */
        .tab-panel {{
            display: none;
            animation: fadeIn 0.3s ease;
        }}

        .tab-panel.active {{
            display: block;
        }}

        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(8px); }}
            to   {{ opacity: 1; transform: translateY(0); }}
        }}

        /* ─── Section Header ─────────────────────────────────────────── */
        .section-header {{
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 1.8rem;
            padding-bottom: 1.2rem;
            border-bottom: 1px solid var(--border);
        }}

        .section-icon {{
            width: 48px; height: 48px;
            border-radius: 14px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.4rem;
            flex-shrink: 0;
        }}

        .icon-static  {{ background: rgba(56,189,248,0.12);  box-shadow: 0 0 16px rgba(56,189,248,0.15); }}
        .icon-openapi {{ background: rgba(167,139,250,0.12); box-shadow: 0 0 16px rgba(167,139,250,0.15); }}
        .icon-bola    {{ background: rgba(251,113,133,0.12); box-shadow: 0 0 16px rgba(251,113,133,0.15); }}

        .section-header h2 {{
            font-size: 1.4rem;
            font-weight: 800;
        }}

        .section-header p {{
            font-size: 0.82rem;
            color: var(--text-secondary);
            margin-top: 0.15rem;
        }}

        /* ─── Section Stats ──────────────────────────────────────────── */
        .section-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}

        .sstat {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 1.1rem 1.3rem;
            transition: all 0.25s ease;
        }}

        .sstat:hover {{
            transform: translateY(-2px);
        }}

        .sstat-label {{
            font-size: 0.7rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 600;
            margin-bottom: 0.4rem;
        }}

        .sstat-value {{
            font-size: 2rem;
            font-weight: 800;
        }}

        /* ─── Layout Sidebar + Content ───────────────────────────────── */
        .panel-layout {{
            display: grid;
            grid-template-columns: 260px 1fr;
            gap: 1.5rem;
            align-items: start;
        }}

        .panel-sidebar {{
            position: sticky;
            top: 88px;
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }}

        .sidebar-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 1.2rem;
        }}

        .sidebar-card h3 {{
            font-size: 0.8rem;
            font-weight: 700;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 0.8rem;
            padding-bottom: 0.6rem;
            border-bottom: 1px solid var(--border);
        }}

        .filter-group {{
            display: flex;
            flex-direction: column;
            gap: 0.4rem;
        }}

        .flt-btn {{
            background: rgba(255,255,255,0.02);
            border: 1px solid transparent;
            color: var(--text-secondary);
            padding: 0.55rem 0.9rem;
            border-radius: 10px;
            cursor: pointer;
            font-size: 0.83rem;
            font-weight: 500;
            text-align: left;
            transition: all 0.2s ease;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .flt-btn:hover {{
            color: var(--text-primary);
            background: rgba(255,255,255,0.05);
            border-color: var(--border);
        }}

        .flt-btn.flt-active1 {{ color: var(--sky);    background: rgba(56,189,248,0.08);  border-color: rgba(56,189,248,0.2); }}
        .flt-btn.flt-active2 {{ color: var(--violet); background: rgba(167,139,250,0.08); border-color: rgba(167,139,250,0.2); }}
        .flt-btn.flt-active3 {{ color: var(--rose);   background: rgba(251,113,133,0.08); border-color: rgba(251,113,133,0.2); }}

        .fc {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.72rem;
            background: rgba(255,255,255,0.07);
            padding: 0.1rem 0.4rem;
            border-radius: 6px;
        }}

        /* ─── Search ─────────────────────────────────────────────────── */
        .search-wrap {{
            position: relative;
            margin-bottom: 1rem;
        }}

        .search-wrap input {{
            width: 100%;
            background: var(--bg-input);
            border: 1px solid var(--border);
            border-radius: 12px;
            color: var(--text-primary);
            font-size: 0.85rem;
            padding: 0.7rem 1rem 0.7rem 2.5rem;
            outline: none;
            transition: border-color 0.2s;
        }}

        .search-wrap input:focus {{
            border-color: var(--border-active);
            box-shadow: 0 0 0 3px rgba(56,189,248,0.06);
        }}

        .search-wrap::before {{
            content: '⌕';
            position: absolute;
            left: 0.75rem;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-muted);
            font-size: 1rem;
            pointer-events: none;
        }}

        /* ─── Findings List ──────────────────────────────────────────── */
        .findings-list {{
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }}

        /* ─── Finding Card ───────────────────────────────────────────── */
        .fcard {{
            background: var(--bg-card);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border);
            border-radius: 18px;
            padding: 1.4rem 1.6rem;
            position: relative;
            overflow: hidden;
            transition: all 0.3s ease;
            cursor: pointer;
        }}

        .fcard:hover {{
            border-color: rgba(255,255,255,0.12);
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
            transform: translateY(-1px);
        }}

        /* Barra laterale colorata per severità */
        .fcard::before {{
            content: '';
            position: absolute;
            left: 0; top: 0; bottom: 0;
            width: 3px;
            border-radius: 18px 0 0 18px;
        }}

        .sev-critical::before {{ background: var(--rose);    box-shadow: 2px 0 12px rgba(251,113,133,0.4); }}
        .sev-high::before     {{ background: var(--amber);   box-shadow: 2px 0 12px rgba(251,191,36,0.3); }}
        .sev-medium::before   {{ background: var(--indigo);  }}
        .sev-low::before      {{ background: var(--sky);     }}
        .sev-info::before     {{ background: var(--text-muted); }}

        /* Glow sottile per critical */
        .sev-critical {{ box-shadow: inset 0 0 30px rgba(251,113,133,0.03); }}
        .sev-high     {{ box-shadow: inset 0 0 30px rgba(251,191,36,0.02); }}

        .fcard-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 0.7rem;
            gap: 1rem;
        }}

        .fcard-title {{
            font-size: 1.05rem;
            font-weight: 700;
            color: var(--text-primary);
            line-height: 1.3;
        }}

        .fcard-tags {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            flex-wrap: wrap;
            flex-shrink: 0;
        }}

        .tag {{
            font-size: 0.7rem;
            font-weight: 700;
            padding: 0.2rem 0.6rem;
            border-radius: 30px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .tag-sev-critical {{ background: rgba(251,113,133,0.15); color: var(--rose);   border: 1px solid rgba(251,113,133,0.25); }}
        .tag-sev-high     {{ background: rgba(251,191,36,0.12);  color: var(--amber);  border: 1px solid rgba(251,191,36,0.2); }}
        .tag-sev-medium   {{ background: rgba(129,140,248,0.12); color: var(--indigo); border: 1px solid rgba(129,140,248,0.2); }}
        .tag-sev-low      {{ background: rgba(56,189,248,0.1);   color: var(--sky);    border: 1px solid rgba(56,189,248,0.2); }}
        .tag-sev-info     {{ background: rgba(255,255,255,0.06); color: var(--text-secondary); border: 1px solid var(--border); }}

        .tag-source {{
            background: rgba(255,255,255,0.04);
            color: var(--text-secondary);
            border: 1px solid var(--border);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.68rem;
            text-transform: none;
            font-weight: 500;
        }}

        .tag-confirmed {{
            background: rgba(16,185,129,0.12);
            color: var(--emerald);
            border: 1px solid rgba(16,185,129,0.25);
        }}

        .tag-bola {{
            background: rgba(251,113,133,0.12);
            color: var(--rose);
            border: 1px solid rgba(251,113,133,0.2);
        }}

        .fcard-desc {{
            font-size: 0.88rem;
            color: var(--text-secondary);
            line-height: 1.55;
            margin-bottom: 0.8rem;
        }}

        .fcard-meta {{
            background: rgba(10,16,35,0.5);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 0.8rem 1rem;
            display: flex;
            flex-direction: column;
            gap: 0.35rem;
            font-size: 0.8rem;
            margin-bottom: 0.8rem;
        }}

        .meta-row {{
            display: flex;
            gap: 0.5rem;
        }}

        .meta-key {{
            color: var(--text-muted);
            font-weight: 600;
            min-width: 90px;
        }}

        .meta-val {{
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.78rem;
            word-break: break-all;
        }}

        .code-block {{
            background: #040810;
            border: 1px solid rgba(255,255,255,0.05);
            border-radius: 8px;
            padding: 0.7rem 0.9rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.77rem;
            color: var(--sky);
            overflow-x: auto;
            margin-top: 0.4rem;
        }}

        .remediation-box {{
            background: rgba(16,185,129,0.05);
            border: 1px solid rgba(16,185,129,0.15);
            border-radius: 10px;
            padding: 0.8rem 1rem;
            margin-top: 0.8rem;
        }}

        .remediation-box h4 {{
            font-size: 0.72rem;
            font-weight: 700;
            color: var(--emerald);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 0.3rem;
        }}

        .remediation-box p {{
            font-size: 0.85rem;
            color: var(--text-primary);
            line-height: 1.5;
        }}

        /* ─── OpenAPI Endpoint Table ─────────────────────────────────── */
        .endpoint-grid {{
            display: flex;
            flex-direction: column;
            gap: 0.8rem;
        }}

        .ep-row {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 1rem 1.3rem;
            display: grid;
            grid-template-columns: 80px 1fr auto;
            gap: 1rem;
            align-items: center;
            transition: all 0.2s ease;
        }}

        .ep-row:hover {{
            border-color: rgba(167,139,250,0.2);
            background: rgba(167,139,250,0.03);
        }}

        .ep-method {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.78rem;
            font-weight: 700;
            padding: 0.3rem 0.6rem;
            border-radius: 8px;
            text-align: center;
        }}

        .method-get    {{ background: rgba(16,185,129,0.15);  color: var(--emerald); }}
        .method-post   {{ background: rgba(56,189,248,0.15);  color: var(--sky); }}
        .method-put    {{ background: rgba(251,191,36,0.15);  color: var(--amber); }}
        .method-delete {{ background: rgba(251,113,133,0.15); color: var(--rose); }}
        .method-patch  {{ background: rgba(167,139,250,0.15); color: var(--violet); }}

        .ep-path {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            color: var(--text-primary);
        }}

        .ep-rule {{
            font-size: 0.78rem;
            color: var(--text-secondary);
        }}

        /* ─── BOLA diff badge ────────────────────────────────────────── */
        .bola-badge {{
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
            padding: 0.3rem 0.7rem;
            border-radius: 30px;
            font-size: 0.73rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .bola-vuln    {{ background: rgba(251,113,133,0.15); color: var(--rose);    border: 1px solid rgba(251,113,133,0.3); }}
        .bola-partial {{ background: rgba(251,191,36,0.12);  color: var(--amber);   border: 1px solid rgba(251,191,36,0.25); }}
        .bola-safe    {{ background: rgba(16,185,129,0.1);   color: var(--emerald); border: 1px solid rgba(16,185,129,0.2); }}

        .risk-score {{
            display: inline-flex;
            align-items: center;
            gap: 0.3rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            font-weight: 700;
        }}

        /* ─── Empty state ────────────────────────────────────────────── */
        .empty-state {{
            padding: 4rem 2rem;
            text-align: center;
            color: var(--text-secondary);
            background: var(--bg-card);
            border-radius: 18px;
            border: 1px dashed var(--border);
        }}

        .empty-state .empty-icon {{ font-size: 3rem; margin-bottom: 1rem; }}
        .empty-state h3 {{ font-size: 1.1rem; font-weight: 700; color: var(--text-primary); }}
        .empty-state p  {{ font-size: 0.85rem; margin-top: 0.4rem; }}

        /* ─── Result count ───────────────────────────────────────────── */
        .result-count {{
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-bottom: 0.8rem;
            font-family: 'JetBrains Mono', monospace;
        }}

        /* ─── Responsive ─────────────────────────────────────────────── */
        @media (max-width: 1100px) {{
            .panel-layout {{ grid-template-columns: 1fr; }}
            .panel-sidebar {{ position: static; }}
            .global-stats {{ grid-template-columns: repeat(2, 1fr); }}
        }}

        @media (max-width: 680px) {{
            main {{ padding: 1.2rem; }}
            .global-stats {{ grid-template-columns: 1fr 1fr; }}
            .tab-btn span:not(.tab-icon):not(.tab-count) {{ display: none; }}
        }}

        /* ─── Scrollbar ──────────────────────────────────────────────── */
        ::-webkit-scrollbar {{ width: 6px; height: 6px; }}
        ::-webkit-scrollbar-track {{ background: transparent; }}
        ::-webkit-scrollbar-thumb {{ background: rgba(255,255,255,0.1); border-radius: 3px; }}
    </style>
</head>
<body>

    <header>
        <div class="logo-section">
            <div class="logo-badge">🛡️</div>
            <div class="logo-title">
                <h1>Security Platform Core</h1>
                <p>Cloud API Risk &amp; Remediation Dashboard</p>
            </div>
        </div>
        <div class="header-right">
            <span class="scan-time" id="scan-timestamp"></span>
            <span class="version-badge">v2.0.0 · 3-Panel View</span>
        </div>
    </header>

    <main>
        <!-- ╔══ GLOBAL STATS ══╗ -->
        <div class="global-stats">
            <div class="gstat gstat-total">
                <div class="gstat-label">Finding Totali</div>
                <div class="gstat-value" id="gs-total">0</div>
                <div class="gstat-sub">tutte le sorgenti</div>
            </div>
            <div class="gstat gstat-danger">
                <div class="gstat-label">Critici / Alti</div>
                <div class="gstat-value" id="gs-danger">0</div>
                <div class="gstat-sub">richiedono attenzione immediata</div>
            </div>
            <div class="gstat gstat-conf">
                <div class="gstat-label">Confermati Runtime</div>
                <div class="gstat-value" id="gs-confirmed">0</div>
                <div class="gstat-sub">validati con evidenza DAST</div>
            </div>
            <div class="gstat gstat-static">
                <div class="gstat-label">Analisi Statica</div>
                <div class="gstat-value" id="gs-static">0</div>
                <div class="gstat-sub">Checkov + Semgrep</div>
            </div>
        </div>

        <!-- ╔══ TAB NAVIGATION ══╗ -->
        <nav class="tab-nav" role="tablist" aria-label="Sezioni dashboard">
            <button id="tab-btn-1" class="tab-btn active-tab1" role="tab"
                    aria-selected="true" aria-controls="panel-1"
                    onclick="switchTab(1)">
                <span class="tab-icon">🔬</span>
                <span>Analisi Statica</span>
                <span class="tab-count" id="tab-count-1">0</span>
            </button>
            <button id="tab-btn-2" class="tab-btn" role="tab"
                    aria-selected="false" aria-controls="panel-2"
                    onclick="switchTab(2)">
                <span class="tab-icon">📋</span>
                <span>Conformità OpenAPI</span>
                <span class="tab-count" id="tab-count-2">0</span>
            </button>
            <button id="tab-btn-3" class="tab-btn" role="tab"
                    aria-selected="false" aria-controls="panel-3"
                    onclick="switchTab(3)">
                <span class="tab-icon">🎯</span>
                <span>Analisi BOLA / D-AST</span>
                <span class="tab-count" id="tab-count-3">0</span>
            </button>
        </nav>

        <!-- ═══════════════════════════════════════════════════════════ -->
        <!-- PANEL 1 · ANALISI STATICA (Checkov + Semgrep)              -->
        <!-- ═══════════════════════════════════════════════════════════ -->
        <div id="panel-1" class="tab-panel active" role="tabpanel" aria-labelledby="tab-btn-1">
            <div class="section-header">
                <div class="section-icon icon-static">🔬</div>
                <div>
                    <h2 style="background: linear-gradient(90deg, var(--sky), var(--indigo)); -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;">
                        Analisi Statica IaC &amp; AST
                    </h2>
                    <p>Scansione infrastruttura Terraform con <strong>Checkov</strong> e analisi del codice sorgente con <strong>Semgrep</strong></p>
                </div>
            </div>

            <div class="section-stats" id="static-section-stats"></div>

            <div class="panel-layout">
                <div class="panel-sidebar">
                    <div class="sidebar-card">
                        <h3>Severità</h3>
                        <div class="filter-group" id="filter-static-sev"></div>
                    </div>
                    <div class="sidebar-card">
                        <h3>Sorgente</h3>
                        <div class="filter-group" id="filter-static-src"></div>
                    </div>
                    <div class="sidebar-card">
                        <h3>Categoria</h3>
                        <div class="filter-group" id="filter-static-cat"></div>
                    </div>
                </div>

                <div>
                    <div class="search-wrap">
                        <input type="text" id="search-static" placeholder="Cerca rule, risorsa, percorso…"
                               oninput="renderStatic()" aria-label="Cerca nei finding statici">
                    </div>
                    <div class="result-count" id="static-result-count"></div>
                    <div class="findings-list" id="static-list"></div>
                    <div class="empty-state" id="static-empty" style="display:none;">
                        <div class="empty-icon">🟢</div>
                        <h3>Nessun problema rilevato!</h3>
                        <p>Nessun finding corrisponde ai filtri correnti.</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- ═══════════════════════════════════════════════════════════ -->
        <!-- PANEL 2 · CONFORMITÀ OPENAPI (Spectral)                    -->
        <!-- ═══════════════════════════════════════════════════════════ -->
        <div id="panel-2" class="tab-panel" role="tabpanel" aria-labelledby="tab-btn-2">
            <div class="section-header">
                <div class="section-icon icon-openapi">📋</div>
                <div>
                    <h2 style="background: linear-gradient(90deg, var(--violet), var(--indigo)); -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;">
                        Conformità Contratto OpenAPI
                    </h2>
                    <p>Linting del contratto <strong>problema_api/openapi.yaml</strong> con <strong>Stoplight Spectral</strong> — regole OWASP API Top 10</p>
                </div>
            </div>

            <div class="section-stats" id="openapi-section-stats"></div>

            <div class="panel-layout">
                <div class="panel-sidebar">
                    <div class="sidebar-card">
                        <h3>Severità</h3>
                        <div class="filter-group" id="filter-openapi-sev"></div>
                    </div>
                    <div class="sidebar-card">
                        <h3>Categoria</h3>
                        <div class="filter-group" id="filter-openapi-cat"></div>
                    </div>
                </div>

                <div>
                    <div class="search-wrap">
                        <input type="text" id="search-openapi" placeholder="Cerca rule ID, endpoint, messaggio…"
                               oninput="renderOpenAPI()" aria-label="Cerca nei finding OpenAPI">
                    </div>
                    <div class="result-count" id="openapi-result-count"></div>
                    <div id="openapi-ep-summary" style="margin-bottom:1.2rem;"></div>
                    <div class="findings-list" id="openapi-list"></div>
                    <div class="empty-state" id="openapi-empty" style="display:none;">
                        <div class="empty-icon">✅</div>
                        <h3>Contratto Conforme!</h3>
                        <p>Nessuna violazione OpenAPI rilevata da Spectral.</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- ═══════════════════════════════════════════════════════════ -->
        <!-- PANEL 3 · BOLA / D-AST (ZAP + Runtime Validator)           -->
        <!-- ═══════════════════════════════════════════════════════════ -->
        <div id="panel-3" class="tab-panel" role="tabpanel" aria-labelledby="tab-btn-3">
            <div class="section-header">
                <div class="section-icon icon-bola">🎯</div>
                <div>
                    <h2 style="background: linear-gradient(90deg, var(--rose), var(--orange)); -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;">
                        Analisi BOLA &amp; D-AST
                    </h2>
                    <p>Test differenziale di autorizzazione <strong>BOLA/IDOR</strong> — rilevamento con <strong>OWASP ZAP</strong> e <strong>Runtime Validator</strong> tramite token Keycloak</p>
                </div>
            </div>

            <div class="section-stats" id="bola-section-stats"></div>

            <div id="bola-summary-banner" style="margin-bottom:1.5rem;"></div>

            <div class="panel-layout">
                <div class="panel-sidebar">
                    <div class="sidebar-card">
                        <h3>Stato</h3>
                        <div class="filter-group" id="filter-bola-status"></div>
                    </div>
                    <div class="sidebar-card">
                        <h3>Sorgente</h3>
                        <div class="filter-group" id="filter-bola-src"></div>
                    </div>
                    <div class="sidebar-card">
                        <h3>Severità</h3>
                        <div class="filter-group" id="filter-bola-sev"></div>
                    </div>
                </div>

                <div>
                    <div class="search-wrap">
                        <input type="text" id="search-bola" placeholder="Cerca endpoint, URL, evidenza…"
                               oninput="renderBola()" aria-label="Cerca nei finding BOLA">
                    </div>
                    <div class="result-count" id="bola-result-count"></div>
                    <div class="findings-list" id="bola-list"></div>
                    <div class="empty-state" id="bola-empty" style="display:none;">
                        <div class="empty-icon">🔒</div>
                        <h3>Nessun BOLA rilevato!</h3>
                        <p>Nessun finding corrisponde ai filtri correnti.</p>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <script>
    /* ================================================================ */
    /* DATA                                                              */
    /* ================================================================ */
    const ALL_FINDINGS = {findings_json};
    const STATS        = {stats_json};

    const STATIC_SOURCES  = new Set(["CHECKOV", "SEMGREP"]);
    const OPENAPI_SOURCES = new Set(["SPECTRAL"]);
    const BOLA_SOURCES    = new Set(["ZAP_DAST", "RUNTIME_VALIDATOR", "SHADOW_API"]);

    const staticFindings  = ALL_FINDINGS.filter(f => STATIC_SOURCES.has(f.source));
    const openapiFindings = ALL_FINDINGS.filter(f => OPENAPI_SOURCES.has(f.source));
    const bolaFindings    = ALL_FINDINGS.filter(f => BOLA_SOURCES.has(f.source));

    /* ─── Active filters state ────────────────────────────────────── */
    const state = {{
        static:  {{ sev: 'ALL', src: 'ALL', cat: 'ALL' }},
        openapi: {{ sev: 'ALL', cat: 'ALL' }},
        bola:    {{ status: 'ALL', src: 'ALL', sev: 'ALL' }}
    }};

    /* ================================================================ */
    /* INIT                                                              */
    /* ================================================================ */
    document.addEventListener('DOMContentLoaded', () => {{
        // Timestamp
        const d = new Date();
        document.getElementById('scan-timestamp').textContent =
            'Generata: ' + d.toLocaleDateString('it-IT') + ' ' + d.toLocaleTimeString('it-IT', {{hour:'2-digit', minute:'2-digit'}});

        // Global stats
        document.getElementById('gs-total').textContent     = STATS.total;
        document.getElementById('gs-danger').textContent    = STATS.critical + STATS.high;
        document.getElementById('gs-confirmed').textContent = STATS.confirmed;
        document.getElementById('gs-static').textContent    = STATS.static_total;

        // Tab counts
        document.getElementById('tab-count-1').textContent = staticFindings.length;
        document.getElementById('tab-count-2').textContent = openapiFindings.length;
        document.getElementById('tab-count-3').textContent = bolaFindings.length;

        buildStaticUI();
        buildOpenAPIUI();
        buildBolaUI();
    }});

    /* ================================================================ */
    /* TAB SWITCHING                                                     */
    /* ================================================================ */
    function switchTab(n) {{
        [1,2,3].forEach(i => {{
            document.getElementById('panel-' + i).classList.remove('active');
            const btn = document.getElementById('tab-btn-' + i);
            btn.classList.remove('active-tab1','active-tab2','active-tab3');
            btn.setAttribute('aria-selected','false');
        }});
        document.getElementById('panel-' + n).classList.add('active');
        const activeBtn = document.getElementById('tab-btn-' + n);
        activeBtn.classList.add('active-tab' + n);
        activeBtn.setAttribute('aria-selected','true');
    }}

    /* ================================================================ */
    /* HELPERS                                                           */
    /* ================================================================ */
    function sevTag(sev) {{
        return `<span class="tag tag-sev-${{sev.toLowerCase()}}">${{sev}}</span>`;
    }}

    function srcTag(src) {{
        return `<span class="tag tag-source">${{src}}</span>`;
    }}

    function countBy(arr, keyFn) {{
        const m = {{}};
        arr.forEach(x => {{ const k = keyFn(x); m[k] = (m[k]||0)+1; }});
        return m;
    }}

    function buildFilterBtns(containerId, items, activeClass, onClickFn, currentGetter) {{
        const el = document.getElementById(containerId);
        el.innerHTML = '';
        [['ALL','Tutti'],...items].forEach(([val, label]) => {{
            const btn = document.createElement('button');
            btn.className = 'flt-btn' + (currentGetter() === val ? ' ' + activeClass : '');
            btn.innerHTML = `${{label}} <span class="fc">${{val === 'ALL' ? items.reduce((s,[,,,c])=>s+(c||0),0) : ''}}</span>`;
            btn.onclick = () => {{ onClickFn(val); }};
            el.appendChild(btn);
        }});
    }}

    function buildSevFilters(containerId, findings, activeClass, stateName, subKey, renderFn) {{
        const counts = countBy(findings, f => f.severity);
        const sevs = ['CRITICAL','HIGH','MEDIUM','LOW','INFO']
            .filter(s => counts[s])
            .map(s => [s, s[0]+s.slice(1).toLowerCase(), null, counts[s]]);

        const el = document.getElementById(containerId);
        el.innerHTML = '';
        [['ALL','Tutte', null, findings.length], ...sevs].forEach(([val, label,,cnt]) => {{
            const btn = document.createElement('button');
            btn.className = 'flt-btn' + (state[stateName][subKey] === val ? ' '+activeClass : '');
            btn.innerHTML = `${{label}} <span class="fc">${{cnt ?? ''}}</span>`;
            btn.onclick = () => {{ state[stateName][subKey] = val; renderFn(); buildSevFilters(containerId, findings, activeClass, stateName, subKey, renderFn); }};
            el.appendChild(btn);
        }});
    }}

    function buildSrcFilters(containerId, findings, activeClass, stateName, subKey, renderFn) {{
        const counts = countBy(findings, f => f.source);
        const srcs = Object.entries(counts).map(([k,v]) => [k,k,null,v]);
        const el = document.getElementById(containerId);
        el.innerHTML = '';
        [['ALL','Tutte', null, findings.length], ...srcs].forEach(([val,label,,cnt]) => {{
            const btn = document.createElement('button');
            btn.className = 'flt-btn' + (state[stateName][subKey] === val ? ' '+activeClass : '');
            btn.innerHTML = `${{label}} <span class="fc">${{cnt ?? ''}}</span>`;
            btn.onclick = () => {{ state[stateName][subKey] = val; renderFn(); buildSrcFilters(containerId, findings, activeClass, stateName, subKey, renderFn); }};
            el.appendChild(btn);
        }});
    }}

    function buildCatFilters(containerId, findings, activeClass, stateName, subKey, renderFn) {{
        const counts = countBy(findings, f => f.category);
        const cats = Object.entries(counts).map(([k,v]) => [k, k.replace(/_/g,' '), null, v]);
        const el = document.getElementById(containerId);
        el.innerHTML = '';
        [['ALL','Tutte', null, findings.length], ...cats].forEach(([val,label,,cnt]) => {{
            const btn = document.createElement('button');
            btn.className = 'flt-btn' + (state[stateName][subKey] === val ? ' '+activeClass : '');
            btn.innerHTML = `${{label}} <span class="fc">${{cnt ?? ''}}</span>`;
            btn.onclick = () => {{ state[stateName][subKey] = val; renderFn(); buildCatFilters(containerId, findings, activeClass, stateName, subKey, renderFn); }};
            el.appendChild(btn);
        }});
    }}

    function makeSectionStats(containerId, statsArr) {{
        const el = document.getElementById(containerId);
        el.innerHTML = statsArr.map(([label, val, color]) =>
            `<div class="sstat">
                <div class="sstat-label">${{label}}</div>
                <div class="sstat-value" style="color:${{color||'var(--text-primary)'}}">${{val}}</div>
            </div>`
        ).join('');
    }}

    function renderFindingCard(f, extra='') {{
        const sevCls = 'sev-' + f.severity.toLowerCase();
        const confirmed = f.validation_status === 'CONFIRMED';
        let meta = '';
        if (f.api?.endpoint)        meta += `<div class="meta-row"><span class="meta-key">Endpoint</span><span class="meta-val">${{f.api.method||'?'}} ${{f.api.endpoint}}</span></div>`;
        if (f.location?.file_path)  meta += `<div class="meta-row"><span class="meta-key">Sorgente</span><span class="meta-val">${{f.location.file_path}}${{f.location.start_line?' :'+f.location.start_line:''}}</span></div>`;
        if (f.resource_id)          meta += `<div class="meta-row"><span class="meta-key">Risorsa</span><span class="meta-val">${{f.resource_id}}</span></div>`;
        if (f.rule_id)              meta += `<div class="meta-row"><span class="meta-key">Rule ID</span><span class="meta-val">${{f.rule_id}}</span></div>`;
        if (f.raw_data?.correlated_risk_score != null)
            meta += `<div class="meta-row"><span class="meta-key">Risk Score</span><span class="meta-val" style="color:var(--rose);font-weight:700">${{f.raw_data.correlated_risk_score}} / 10</span></div>`;
        let runtime = '';
        if (f.runtime_evidence) {{
            const re = f.runtime_evidence;
            runtime = `<div class="code-block">
                [Evidenza Runtime]<br>
                URL: ${{re.tested_url||'N/D'}}<br>
                Status: ${{re.http_status||'N/D'}}<br>
                ${{re.accessible_without_auth != null ? 'Accessibile senza auth: '+re.accessible_without_auth+'<br>' : ''}}
                ${{re.response_snippet ? 'Snippet: '+re.response_snippet : ''}}
            </div>`;
        }}
        const remediation = f.remediation
            ? `<div class="remediation-box"><h4>Rimedio Suggerito</h4><p>${{f.remediation}}</p></div>` : '';

        return `<div class="fcard ${{sevCls}}">
            <div class="fcard-header">
                <div class="fcard-title">${{f.title}}</div>
                <div class="fcard-tags">
                    ${{sevTag(f.severity)}}
                    ${{srcTag(f.source)}}
                    ${{confirmed ? '<span class="tag tag-confirmed">✓ Confermato</span>' : ''}}
                    ${{extra}}
                </div>
            </div>
            <div class="fcard-desc">${{f.description}}</div>
            ${{meta ? '<div class="fcard-meta">'+meta+'</div>' : ''}}
            ${{runtime}}
            ${{remediation}}
        </div>`;
    }}

    /* ================================================================ */
    /* PANEL 1 — STATIC                                                  */
    /* ================================================================ */
    function buildStaticUI() {{
        const cr = staticFindings.filter(f => f.severity==='CRITICAL').length;
        const hi = staticFindings.filter(f => f.severity==='HIGH').length;
        const src = countBy(staticFindings, f => f.source);
        makeSectionStats('static-section-stats', [
            ['Finding Totali',    staticFindings.length,   'var(--sky)'],
            ['Critici',           cr,                       'var(--rose)'],
            ['Alti',              hi,                       'var(--amber)'],
            ['Checkov',           src['CHECKOV']||0,        'var(--teal)'],
            ['Semgrep',           src['SEMGREP']||0,        'var(--violet)'],
        ]);
        buildSevFilters('filter-static-sev', staticFindings, 'flt-active1', 'static', 'sev', renderStatic);
        buildSrcFilters('filter-static-src', staticFindings, 'flt-active1', 'static', 'src', renderStatic);
        buildCatFilters('filter-static-cat', staticFindings, 'flt-active1', 'static', 'cat', renderStatic);
        renderStatic();
    }}

    function renderStatic() {{
        const q = (document.getElementById('search-static').value||'').toLowerCase();
        const filtered = staticFindings.filter(f => {{
            if (state.static.sev !== 'ALL' && f.severity !== state.static.sev) return false;
            if (state.static.src !== 'ALL' && f.source   !== state.static.src) return false;
            if (state.static.cat !== 'ALL' && f.category !== state.static.cat) return false;
            if (q && !(f.title+f.description+(f.rule_id||'')+(f.resource_id||'')+(f.location?.file_path||'')).toLowerCase().includes(q)) return false;
            return true;
        }});

        document.getElementById('static-result-count').textContent =
            filtered.length + ' di ' + staticFindings.length + ' finding';

        const container = document.getElementById('static-list');
        const empty     = document.getElementById('static-empty');
        if (filtered.length === 0) {{
            container.innerHTML = '';
            empty.style.display = 'block';
            return;
        }}
        empty.style.display = 'none';
        container.innerHTML = filtered.map(f => renderFindingCard(f)).join('');
    }}

    /* ================================================================ */
    /* PANEL 2 — OPENAPI                                                 */
    /* ================================================================ */
    function buildOpenAPIUI() {{
        const hi = openapiFindings.filter(f => f.severity==='HIGH').length;
        const me = openapiFindings.filter(f => f.severity==='MEDIUM').length;
        const cats = countBy(openapiFindings, f => f.category);
        const endpts = new Set(openapiFindings.filter(f => f.api?.endpoint).map(f => f.api.endpoint));

        makeSectionStats('openapi-section-stats', [
            ['Violazioni Totali',  openapiFindings.length, 'var(--violet)'],
            ['Alta Severità',      hi,                      'var(--rose)'],
            ['Media Severità',     me,                      'var(--amber)'],
            ['Endpoint Coinvolti', endpts.size,             'var(--sky)'],
            ['Spec Analizzata',    '1',                     'var(--emerald)'],
        ]);

        // Endpoint summary bar
        if (openapiFindings.length > 0) {{
            const epSummary = document.getElementById('openapi-ep-summary');
            const epMap = {{}};
            openapiFindings.forEach(f => {{
                if (!f.api?.endpoint) return;
                const k = (f.api.method||'ANY') + ' ' + f.api.endpoint;
                epMap[k] = (epMap[k]||0)+1;
            }});
            if (Object.keys(epMap).length > 0) {{
                epSummary.innerHTML = `
                    <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:14px;padding:1rem 1.3rem;">
                        <div style="font-size:0.75rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:0.8rem;font-weight:700;">Endpoint con Violazioni</div>
                        <div class="endpoint-grid">
                            ${{Object.entries(epMap).map(([ep, cnt]) => {{
                                const parts = ep.split(' ');
                                const meth  = parts[0];
                                const path  = parts.slice(1).join(' ');
                                return `<div class="ep-row">
                                    <span class="ep-method method-${{meth.toLowerCase()}}">${{meth}}</span>
                                    <span class="ep-path">${{path}}</span>
                                    <span class="ep-rule">${{cnt}} violaz.</span>
                                </div>`;
                            }}).join('')}}
                        </div>
                    </div>`;
            }}
        }}

        buildSevFilters('filter-openapi-sev', openapiFindings, 'flt-active2', 'openapi', 'sev', renderOpenAPI);
        buildCatFilters('filter-openapi-cat', openapiFindings, 'flt-active2', 'openapi', 'cat', renderOpenAPI);
        renderOpenAPI();
    }}

    function renderOpenAPI() {{
        const q = (document.getElementById('search-openapi').value||'').toLowerCase();
        const filtered = openapiFindings.filter(f => {{
            if (state.openapi.sev !== 'ALL' && f.severity !== state.openapi.sev) return false;
            if (state.openapi.cat !== 'ALL' && f.category !== state.openapi.cat) return false;
            if (q && !(f.title+f.description+(f.rule_id||'')+(f.api?.endpoint||'')).toLowerCase().includes(q)) return false;
            return true;
        }});

        document.getElementById('openapi-result-count').textContent =
            filtered.length + ' di ' + openapiFindings.length + ' violazioni';

        const container = document.getElementById('openapi-list');
        const empty     = document.getElementById('openapi-empty');

        if (openapiFindings.length === 0) {{
            container.innerHTML = '';
            empty.style.display = 'block';
            return;
        }}

        if (filtered.length === 0) {{
            container.innerHTML = '';
            empty.style.display = 'block';
            return;
        }}
        empty.style.display = 'none';
        container.innerHTML = filtered.map(f => {{
            const ruleTag = f.rule_id ? `<span class="tag tag-source">#${{f.rule_id}}</span>` : '';
            return renderFindingCard(f, ruleTag);
        }}).join('');
    }}

    /* ================================================================ */
    /* PANEL 3 — BOLA                                                    */
    /* ================================================================ */
    function buildBolaUI() {{
        const confirmed = bolaFindings.filter(f => f.validation_status==='CONFIRMED').length;
        const critical  = bolaFindings.filter(f => f.severity==='CRITICAL').length;
        const zap       = bolaFindings.filter(f => f.source==='ZAP_DAST').length;
        const rval      = bolaFindings.filter(f => f.source==='RUNTIME_VALIDATOR').length;
        const shadow    = bolaFindings.filter(f => f.source==='SHADOW_API').length;

        makeSectionStats('bola-section-stats', [
            ['Finding BOLA',       bolaFindings.length, 'var(--rose)'],
            ['Confermati',         confirmed,            'var(--emerald)'],
            ['Critici',            critical,             'var(--rose)'],
            ['ZAP D-AST',          zap,                  'var(--amber)'],
            ['Runtime Validator',  rval,                 'var(--violet)'],
            ['Shadow API',         shadow,               'var(--sky)'],
        ]);

        // Banner riassuntivo BOLA
        if (bolaFindings.length > 0) {{
            const pct = Math.round(confirmed / bolaFindings.length * 100);
            const banner = document.getElementById('bola-summary-banner');
            const alertClass = confirmed > 0 ? 'bola-vuln' : 'bola-safe';
            const alertText  = confirmed > 0 ?
                `⚠️ ${{confirmed}} endpoint BOLA confermati con evidenza runtime (${{pct}}% del totale)` :
                `✅ Nessun BOLA confermato a runtime — potenziali finding da verificare manualmente`;
            banner.innerHTML = `
                <div style="background:${{confirmed>0?'rgba(251,113,133,0.06)':'rgba(16,185,129,0.06)'}};border:1px solid ${{confirmed>0?'rgba(251,113,133,0.2)':'rgba(16,185,129,0.2)'}};border-radius:14px;padding:1rem 1.4rem;display:flex;align-items:center;gap:1rem;">
                    <span style="font-size:1.5rem;">${{confirmed>0?'🔴':'🟢'}}</span>
                    <div>
                        <div style="font-weight:700;color:${{confirmed>0?'var(--rose)':'var(--emerald)'}};">${{alertText}}</div>
                        <div style="font-size:0.8rem;color:var(--text-muted);margin-top:0.2rem;">
                            Test differenziale con token admin vs anonimo — autenticazione Keycloak
                        </div>
                    </div>
                </div>`;
        }}

        // Filtri status
        const statusEl = document.getElementById('filter-bola-status');
        const statusItems = [
            ['ALL','Tutti',        bolaFindings.length],
            ['CONFIRMED','Confermati', confirmed],
            ['NOT_VALIDATED','Non Validati', bolaFindings.filter(f=>f.validation_status!=='CONFIRMED').length],
        ];
        statusEl.innerHTML = statusItems.map(([val,label,cnt]) =>
            `<button class="flt-btn ${{state.bola.status===val?'flt-active3':''}}"
                onclick="state.bola.status='${{val}}';renderBola();buildBolaUI();">
                ${{label}} <span class="fc">${{cnt}}</span>
             </button>`
        ).join('');

        buildSrcFilters('filter-bola-src', bolaFindings, 'flt-active3', 'bola', 'src', renderBola);
        buildSevFilters('filter-bola-sev', bolaFindings, 'flt-active3', 'bola', 'sev', renderBola);
        renderBola();
    }}

    function renderBola() {{
        const q = (document.getElementById('search-bola').value||'').toLowerCase();
        const filtered = bolaFindings.filter(f => {{
            if (state.bola.status !== 'ALL') {{
                if (state.bola.status==='CONFIRMED'     && f.validation_status!=='CONFIRMED') return false;
                if (state.bola.status==='NOT_VALIDATED' && f.validation_status==='CONFIRMED') return false;
            }}
            if (state.bola.src !== 'ALL' && f.source   !== state.bola.src) return false;
            if (state.bola.sev !== 'ALL' && f.severity !== state.bola.sev) return false;
            if (q && !(f.title+f.description+(f.api?.endpoint||'')+(f.runtime_evidence?.tested_url||'')).toLowerCase().includes(q)) return false;
            return true;
        }});

        document.getElementById('bola-result-count').textContent =
            filtered.length + ' di ' + bolaFindings.length + ' finding BOLA';

        const container = document.getElementById('bola-list');
        const empty     = document.getElementById('bola-empty');

        if (bolaFindings.length === 0 || filtered.length === 0) {{
            container.innerHTML = '';
            empty.style.display = 'block';
            return;
        }}
        empty.style.display = 'none';

        container.innerHTML = filtered.map(f => {{
            const isBola = f.category === 'AUTHORIZATION' || f.owasp_api_category?.includes('BOLA') || f.title?.toLowerCase().includes('bola') || f.title?.toLowerCase().includes('idor');
            const bolaTag = isBola ? '<span class="tag tag-bola bola-badge">🎯 BOLA/IDOR</span>' : '';
            const riskScore = f.raw_data?.correlated_risk_score;
            const riskEl = riskScore != null ?
                `<span class="risk-score" style="color:${{riskScore>=7?'var(--rose)':riskScore>=4?'var(--amber)':'var(--emerald)'}};margin-left:0.5rem;">⚡ ${{riskScore}}/10</span>` : '';
            return renderFindingCard(f, bolaTag + riskEl);
        }}).join('');
    }}
    </script>
</body>
</html>"""
