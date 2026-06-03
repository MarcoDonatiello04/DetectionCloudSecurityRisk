import os
import json
import logging
import yaml
from typing import List, Dict, Any
from src.domain.entities import Finding

logger = logging.getLogger("SecurityPlatform.DashboardGenerator")

# Sorgenti per sezione
STATIC_SOURCES   = {"CHECKOV", "SEMGREP"}
OPENAPI_SOURCES  = {"SPECTRAL", "SHADOW_API"}
BOLA_SOURCES     = {"ZAP_DAST", "RUNTIME_VALIDATOR"}


class APIDashboardGenerator:
    """
    Generatore di dashboard HTML/CSS/JS interattive Premium a 3 sezioni riprogettate:
      1. Analisi IaC (Checkov)
      2. Catalogo API & Conformità OpenAPI (Documentati vs Shadow vs Violazioni Spectral)
      3. Analisi BOLA su Endpoint Dinamici (Test differenziali ZAP/Runtime Validator)
    """

    def __init__(self, findings: List[Finding]):
        self.findings = findings

    def generate(self, output_path: str):
        """Genera e salva la dashboard HTML con i dati incorporati."""
        serialized = [f.to_dict() for f in self.findings]
        endpoints = self._build_endpoint_catalog(self.findings)
        stats = self._calculate_stats(self.findings, endpoints)

        html_content = self._get_template(
            json.dumps(serialized, ensure_ascii=False),
            json.dumps(endpoints, ensure_ascii=False),
            json.dumps(stats, ensure_ascii=False)
        )

        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            logger.info(f"✨ Dashboard premium a 3 sezioni riprogettata in: {output_path}")
        except Exception as e:
            logger.error(f"Errore scrittura dashboard: {e}", exc_info=True)

    def _parse_openapi_spec(self) -> List[Dict[str, Any]]:
        """Carica ed estrae le rotte definite nel file openapi.yaml."""
        spec_paths = [
            "problema_api/openapi.yaml",
            "../problema_api/openapi.yaml",
            "./openapi.yaml"
        ]
        for p in spec_paths:
            if os.path.exists(p):
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        spec = yaml.safe_load(f)
                        paths = spec.get("paths", {})
                        endpoints = []
                        for path, path_item in paths.items():
                            if not path_item:
                                continue
                            for method in ["get", "post", "put", "delete", "patch", "options", "head"]:
                                if method in path_item:
                                    endpoints.append({
                                        "path": path,
                                        "method": method.upper(),
                                        "summary": path_item[method].get("summary", ""),
                                        "description": path_item[method].get("description", ""),
                                        "documented": True
                                    })
                        return endpoints
                except Exception as e:
                    logger.error(f"Errore caricamento spec OpenAPI da {p}: {e}")
        return []

    def _build_endpoint_catalog(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Costruisce il catalogo completo degli endpoint incrociando specifiche e findings."""
        # 1. Carica endpoint documentati in OpenAPI
        documented_endpoints = self._parse_openapi_spec()

        catalog = {}
        for ep in documented_endpoints:
            key = f"{ep['method']} {ep['path']}"
            catalog[key] = {
                "method": ep["method"],
                "path": ep["path"],
                "summary": ep["summary"],
                "description": ep["description"],
                "documented": True,
                "shadow": False,
                "violations": [],
                "bola_status": "UNTESTED",  # UNTESTED, SAFE, VULNERABLE, POTENTIAL
                "bola_findings": []
            }

        # 2. Analizza i findings per popolare violazioni, shadow api e bola
        from src.normalization.normalizer import APIEndpointNormalizer
        for f in findings:
            if not f.api or not f.api.endpoint:
                continue

            method = (f.api.method or "GET").upper()
            norm_path = APIEndpointNormalizer.normalize_path(f.api.endpoint)
            key = f"{method} {norm_path}"

            matched_key = None
            if key in catalog:
                matched_key = key
            else:
                for cat_key, cat_ep in catalog.items():
                    if cat_ep["method"] == method:
                        if APIEndpointNormalizer.normalize_path(cat_ep["path"]) == norm_path:
                            matched_key = cat_key
                            break

            if not matched_key:
                # È un endpoint non documentato (Shadow API)
                matched_key = key
                catalog[matched_key] = {
                    "method": method,
                    "path": norm_path,
                    "summary": f.title if f.source.value == "SHADOW_API" else "Endpoint Rilevato",
                    "description": f.description,
                    "documented": False,
                    "shadow": True,
                    "violations": [],
                    "bola_status": "UNTESTED",
                    "bola_findings": []
                }

            ep_entry = catalog[matched_key]

            # Spectral violations
            if f.source.value == "SPECTRAL":
                ep_entry["violations"].append({
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "line": f.location.start_line if f.location else None
                })

            # BOLA / D-AST
            is_bola = (
                f.category.value == "AUTHORIZATION" or 
                f.category.value == "AUTHENTICATION" or
                "bola" in f.title.lower() or 
                "idor" in f.title.lower() or
                f.source.value in ("ZAP_DAST", "RUNTIME_VALIDATOR")
            )
            if is_bola:
                ep_entry["bola_findings"].append(f.to_dict())
                if f.rule_id == "dynamic-test-secure":
                    if ep_entry["bola_status"] not in ("VULNERABLE", "POTENTIAL"):
                        ep_entry["bola_status"] = "SAFE"
                else:
                    if f.validation_status.value == "CONFIRMED":
                        ep_entry["bola_status"] = "VULNERABLE"
                    elif ep_entry["bola_status"] not in ("VULNERABLE", "SAFE"):
                        ep_entry["bola_status"] = "POTENTIAL"

        # 3. Imposta stato test BOLA per gli endpoint dinamici
        for ep_entry in catalog.values():
            path = ep_entry["path"]
            is_dynamic = "{" in path or "<" in path or ":" in path or "id" in path.lower()
            ep_entry["is_dynamic"] = is_dynamic
            
            # Controlla se abbiamo ricevuto evidenza di sbarramento (status 401 o 403) o se l'assertion engine lo ritiene sicuro
            has_blocking_evidence = False
            for f in ep_entry["bola_findings"]:
                if f.get("rule_id") == "dynamic-test-secure":
                    has_blocking_evidence = True
                    break
                re = f.get("runtime_evidence")
                if re:
                    status = re.get("http_status")
                    if status in (401, 403):
                        has_blocking_evidence = True
                        break
            
            if is_dynamic:
                if ep_entry["bola_status"] in ("UNTESTED", "SAFE"):
                    if ep_entry["bola_status"] == "SAFE" or has_blocking_evidence:
                        ep_entry["bola_status"] = "SAFE"
                    else:
                        ep_entry["bola_status"] = "UNTESTED"

        return sorted(list(catalog.values()), key=lambda x: (x["path"], x["method"]))

    def _calculate_stats(self, findings: List[Finding], endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
        stats = {
            "total":           len(findings),
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
            "confirmed": 0,
            # Contatori Checkov
            "checkov_total": 0, "checkov_critical": 0, "checkov_high": 0, "checkov_medium": 0, "checkov_low": 0,
            # Contatori OpenAPI
            "openapi_total": len(endpoints),
            "openapi_documented": sum(1 for e in endpoints if e["documented"]),
            "openapi_shadow": sum(1 for e in endpoints if e["shadow"]),
            "openapi_violations": sum(len(e["violations"]) for e in endpoints),
            # Contatori BOLA
            "bola_total": sum(1 for e in endpoints if e["is_dynamic"]),
            "bola_vulnerable": sum(1 for e in endpoints if e["is_dynamic"] and e["bola_status"] == "VULNERABLE"),
            "bola_potential": sum(1 for e in endpoints if e["is_dynamic"] and e["bola_status"] == "POTENTIAL"),
            "bola_safe": sum(1 for e in endpoints if e["is_dynamic"] and e["bola_status"] == "SAFE")
        }

        for f in findings:
            sev = f.severity.value.lower()
            if sev in stats:
                stats[sev] += 1

            if f.validation_status.value == "CONFIRMED":
                stats["confirmed"] += 1

            if f.source.value == "CHECKOV":
                stats["checkov_total"] += 1
                if sev in ["critical", "high", "medium", "low"]:
                    stats[f"checkov_{sev}"] += 1

        return stats

    def _get_template(self, findings_json: str, endpoints_json: str, stats_json: str) -> str:
        return f"""<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloud API Security &amp; Risk Dashboard</title>
    <meta name="description" content="Dashboard premium di analisi della sicurezza: Checkov IaC, Conformità OpenAPI e Analisi BOLA.">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">

    <style>
        /* ─── Design Tokens ─────────────────────────────────────────── */
        :root {{
            --bg-main:          #080b11;
            --bg-surface:       #0e1320;
            --bg-card:          rgba(20, 27, 45, 0.7);
            --bg-input:         #161e31;
            --border:           rgba(255,255,255,0.06);
            --border-hover:     rgba(255,255,255,0.12);
            --border-active:    rgba(56,189,248,0.35);

            --text-primary:     #f3f4f6;
            --text-secondary:   #9ca3af;
            --text-muted:       #6b7280;

            --sky:      #38bdf8;
            --indigo:   #818cf8;
            --violet:   #a78bfa;
            --emerald:  #10b981;
            --rose:     #fb7185;
            --amber:    #fbbf24;
            --orange:   #f97316;
            --teal:     #14b8a6;

            --glow-sky:     rgba(56,189,248,0.12);
            --glow-violet:  rgba(167,139,250,0.12);
            --glow-rose:    rgba(251,113,133,0.12);

            --tab1-color: var(--sky);
            --tab2-color: var(--violet);
            --tab3-color: var(--rose);
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
            background: rgba(8,11,17,0.85);
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
        }}

        .fcard:hover {{
            border-color: rgba(255,255,255,0.12);
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
            transform: translateY(-1px);
        }}

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
            min-width: 100px;
        }}

        .meta-val {{
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.78rem;
            word-break: break-all;
        }}

        .code-block {{
            background: #04060b;
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

        /* ─── OpenAPI Master Table ────────────────────────────────────── */
        .endpoint-list {{
            display: flex;
            flex-direction: column;
            gap: 0.8rem;
        }}

        .ep-row {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 1.1rem 1.4rem;
            display: flex;
            flex-direction: column;
            gap: 0.8rem;
            transition: all 0.25s ease;
        }}

        .ep-row:hover {{
            border-color: rgba(167,139,250,0.15);
            background: rgba(167,139,250,0.01);
        }}

        .ep-main-info {{
            display: flex;
            align-items: center;
            gap: 1rem;
            cursor: pointer;
            user-select: none;
        }}

        .ep-method {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.78rem;
            font-weight: 700;
            padding: 0.35rem 0.7rem;
            border-radius: 8px;
            text-align: center;
            min-width: 80px;
            flex-shrink: 0;
        }}

        .method-get    {{ background: rgba(16,185,129,0.15);  color: var(--emerald); }}
        .method-post   {{ background: rgba(56,189,248,0.15);  color: var(--sky); }}
        .method-put    {{ background: rgba(251,191,36,0.15);  color: var(--amber); }}
        .method-delete {{ background: rgba(251,113,133,0.15); color: var(--rose); }}
        .method-patch  {{ background: rgba(167,139,250,0.15); color: var(--violet); }}

        .ep-path {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
            color: var(--text-primary);
            font-weight: 600;
            flex-grow: 1;
        }}

        .ep-status-badges {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}

        .ep-status-tag {{
            font-size: 0.73rem;
            font-weight: 700;
            padding: 0.25rem 0.65rem;
            border-radius: 30px;
            text-transform: uppercase;
        }}

        .status-compliant   {{ background: rgba(16,185,129,0.12); color: var(--emerald); border: 1px solid rgba(16,185,129,0.2); }}
        .status-shadow      {{ background: rgba(249,115,22,0.12);  color: var(--orange);  border: 1px solid rgba(249,115,22,0.25); }}
        .status-violating   {{ background: rgba(251,113,133,0.12); color: var(--rose);    border: 1px solid rgba(251,113,133,0.25); }}

        .ep-chevron {{
            font-size: 0.9rem;
            color: var(--text-muted);
            transition: transform 0.2s;
        }}

        .ep-row.expanded .ep-chevron {{
            transform: rotate(90deg);
        }}

        .ep-details {{
            display: none;
            border-top: 1px solid var(--border);
            padding-top: 0.9rem;
            animation: fadeIn 0.25s ease;
        }}

        .ep-row.expanded .ep-details {{
            display: block;
        }}

        .detail-card {{
            background: rgba(10,16,35,0.4);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 1rem;
            margin-bottom: 0.8rem;
        }}

        .detail-card h4 {{
            font-size: 0.8rem;
            color: var(--text-secondary);
            margin-bottom: 0.5rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        /* Violations list */
        .violation-item {{
            border-left: 2px solid var(--rose);
            padding-left: 0.8rem;
            margin-bottom: 0.8rem;
        }}

        .violation-item:last-child {{
            margin-bottom: 0;
        }}

        .violation-title {{
            font-size: 0.85rem;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 0.2rem;
            font-family: 'JetBrains Mono', monospace;
        }}

        .violation-desc {{
            font-size: 0.82rem;
            color: var(--text-secondary);
            line-height: 1.4;
        }}

        /* ─── BOLA Status Badges ──────────────────────────────────────── */
        .bola-status-badge {{
            font-size: 0.72rem;
            font-weight: 700;
            padding: 0.25rem 0.65rem;
            border-radius: 30px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .bola-vulnerable {{ background: rgba(251,113,133,0.15); color: var(--rose);    border: 1px solid rgba(251,113,133,0.3); }}
        .bola-potential  {{ background: rgba(251,191,36,0.12);  color: var(--amber);   border: 1px solid rgba(251,191,36,0.25); }}
        .bola-safe       {{ background: rgba(16,185,129,0.1);   color: var(--emerald); border: 1px solid rgba(16,185,129,0.2); }}
        .bola-untested   {{ background: rgba(255,255,255,0.06); color: var(--text-muted); border: 1px solid var(--border); }}

        /* Empty state */
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

        .result-count {{
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-bottom: 0.8rem;
            font-family: 'JetBrains Mono', monospace;
        }}

        /* Responsive */
        @media (max-width: 1100px) {{
            .panel-layout {{ grid-template-columns: 1fr; }}
            .panel-sidebar {{ position: static; }}
            .global-stats {{ grid-template-columns: repeat(2, 1fr); }}
        }}

        @media (max-width: 680px) {{
            main {{ padding: 1.2rem; }}
            .global-stats {{ grid-template-columns: 1fr; }}
            .tab-btn span:not(.tab-icon):not(.tab-count) {{ display: none; }}
        }}

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
            <span class="version-badge">v3.0.0 · Core Engine</span>
        </div>
    </header>

    <main>
        <!-- ╔══ GLOBAL STATS ══╗ -->
        <div class="global-stats">
            <div class="gstat gstat-total">
                <div class="gstat-label">Findings Totali</div>
                <div class="gstat-value" id="gs-total">0</div>
                <div class="gstat-sub">infrastruttura &amp; codice</div>
            </div>
            <div class="gstat gstat-danger">
                <div class="gstat-label">Critici / Alti</div>
                <div class="gstat-value" id="gs-danger">0</div>
                <div class="gstat-sub">richiedono intervento</div>
            </div>
            <div class="gstat gstat-conf">
                <div class="gstat-label">Confermati Runtime</div>
                <div class="gstat-value" id="gs-confirmed">0</div>
                <div class="gstat-sub">exploit validati con test</div>
            </div>
            <div class="gstat gstat-static">
                <div class="gstat-label">Rotte API Catalogate</div>
                <div class="gstat-value" id="gs-static">0</div>
                <div class="gstat-sub">OpenAPI + scoperte</div>
            </div>
        </div>

        <!-- ╔══ TAB NAVIGATION ══╗ -->
        <nav class="tab-nav" role="tablist" aria-label="Sezioni dashboard">
            <button id="tab-btn-1" class="tab-btn active-tab1" role="tab"
                    aria-selected="true" aria-controls="panel-1"
                    onclick="switchTab(1)">
                <span class="tab-icon">🔬</span>
                <span>Analisi IaC (Checkov)</span>
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
                <span>Analisi BOLA</span>
                <span class="tab-count" id="tab-count-3">0</span>
            </button>
        </nav>

        <!-- ═══════════════════════════════════════════════════════════ -->
        <!-- PANEL 1 · ANALISI IAC (Checkov)                            -->
        <!-- ═══════════════════════════════════════════════════════════ -->
        <div id="panel-1" class="tab-panel active" role="tabpanel" aria-labelledby="tab-btn-1">
            <div class="section-header">
                <div class="section-icon icon-static">🔬</div>
                <div>
                    <h2 style="background: linear-gradient(90deg, var(--sky), var(--indigo)); -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;">
                        Analisi Infrastrutturale IaC (Checkov)
                    </h2>
                    <p>Rilevamento di misconfiguration e vulnerabilità statiche in file Terraform tramite <strong>Checkov</strong></p>
                </div>
            </div>

            <div class="section-stats" id="checkov-section-stats"></div>

            <div class="panel-layout">
                <div class="panel-sidebar">
                    <div class="sidebar-card">
                        <h3>Severità</h3>
                        <div class="filter-group" id="filter-checkov-sev"></div>
                    </div>
                    <div class="sidebar-card">
                        <h3>Categoria</h3>
                        <div class="filter-group" id="filter-checkov-cat"></div>
                    </div>
                </div>

                <div>
                    <div class="search-wrap">
                        <input type="text" id="search-checkov" placeholder="Cerca risorsa, regola, file…"
                               oninput="renderCheckov()" aria-label="Cerca nei finding Checkov">
                    </div>
                    <div class="result-count" id="checkov-result-count"></div>
                    <div class="findings-list" id="checkov-list"></div>
                    <div class="empty-state" id="checkov-empty" style="display:none;">
                        <div class="empty-icon">🟢</div>
                        <h3>Nessun problema rilevato!</h3>
                        <p>Nessun finding Checkov corrisponde ai filtri impostati.</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- ═══════════════════════════════════════════════════════════ -->
        <!-- PANEL 2 · CONFORMITÀ OPENAPI & CATALOGO API                -->
        <!-- ═══════════════════════════════════════════════════════════ -->
        <div id="panel-2" class="tab-panel" role="tabpanel" aria-labelledby="tab-btn-2">
            <div class="section-header">
                <div class="section-icon icon-openapi">📋</div>
                <div>
                    <h2 style="background: linear-gradient(90deg, var(--violet), var(--indigo)); -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;">
                        Catalogo API &amp; Conformità Contratto
                    </h2>
                    <p>Linting del contratto con <strong>Spectral</strong>, classificazione degli endpoint e rilevamento delle <strong>Shadow APIs</strong></p>
                </div>
            </div>

            <div class="section-stats" id="openapi-section-stats"></div>

            <div class="panel-layout">
                <div class="panel-sidebar">
                    <div class="sidebar-card">
                        <h3>Stato Endpoint</h3>
                        <div class="filter-group" id="filter-openapi-status">
                            <button class="flt-btn flt-active2" onclick="setOpenAPIStatus('ALL')">Tutti</button>
                            <button class="flt-btn" onclick="setOpenAPIStatus('DOCUMENTED')">Documentati</button>
                            <button class="flt-btn" onclick="setOpenAPIStatus('SHADOW')">Shadow API</button>
                            <button class="flt-btn" onclick="setOpenAPIStatus('VIOLATING')">Con Violazioni</button>
                        </div>
                    </div>
                </div>

                <div>
                    <div class="search-wrap">
                        <input type="text" id="search-openapi" placeholder="Cerca endpoint, path, violazione o metodo…"
                               oninput="renderOpenAPI()" aria-label="Cerca nel catalogo API">
                    </div>
                    <div class="result-count" id="openapi-result-count"></div>
                    <div class="endpoint-list" id="openapi-endpoints-list"></div>
                    <div class="empty-state" id="openapi-empty" style="display:none;">
                        <div class="empty-icon">🔍</div>
                        <h3>Nessun endpoint trovato</h3>
                        <p>Nessun endpoint corrisponde ai criteri di ricerca.</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- ═══════════════════════════════════════════════════════════ -->
        <!-- PANEL 3 · ANALISI BOLA SU ENDPOINT DINAMICI                -->
        <!-- ═══════════════════════════════════════════════════════════ -->
        <div id="panel-3" class="tab-panel" role="tabpanel" aria-labelledby="tab-btn-3">
            <div class="section-header">
                <div class="section-icon icon-bola">🎯</div>
                <div>
                    <h2 style="background: linear-gradient(90deg, var(--rose), var(--orange)); -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;">
                        Analisi BOLA su Endpoint Dinamici
                    </h2>
                    <p>Testing differenziale di autorizzazione (BOLA/IDOR/Auth Bypass) degli endpoint dinamici a runtime con <strong>ZAP</strong> e <strong>Validator</strong></p>
                </div>
            </div>

            <div class="section-stats" id="bola-section-stats"></div>

            <div class="panel-layout">
                <div class="panel-sidebar">
                    <div class="sidebar-card">
                        <h3>Stato Test BOLA</h3>
                        <div class="filter-group" id="filter-bola-status">
                            <button class="flt-btn flt-active3" onclick="setBolaStatus('ALL')">Tutti</button>
                            <button class="flt-btn" onclick="setBolaStatus('VULNERABLE')">Vulnerabili</button>
                            <button class="flt-btn" onclick="setBolaStatus('POTENTIAL')">Potenziali</button>
                            <button class="flt-btn" onclick="setBolaStatus('SAFE')">Sicuri / Protetti</button>
                        </div>
                    </div>
                </div>

                <div>
                    <div class="search-wrap">
                        <input type="text" id="search-bola" placeholder="Cerca path, evidenza, status…"
                               oninput="renderBola()" aria-label="Cerca nei test BOLA">
                    </div>
                    <div class="result-count" id="bola-result-count"></div>
                    <div class="endpoint-list" id="bola-endpoints-list"></div>
                    <div class="empty-state" id="bola-empty" style="display:none;">
                        <div class="empty-icon">🛡️</div>
                        <h3>Nessun endpoint dinamico</h3>
                        <p>Nessun endpoint dinamico corrisponde ai filtri correnti.</p>
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
    const ENDPOINTS    = {endpoints_json};
    const STATS        = {stats_json};

    const checkovFindings = ALL_FINDINGS.filter(f => f.source === "CHECKOV");

    const state = {{
        checkov: {{ sev: 'ALL', cat: 'ALL' }},
        openapi: {{ status: 'ALL' }},
        bola:    {{ status: 'ALL' }}
    }};

    /* ================================================================ */
    /* INIT                                                              */
    /* ================================================================ */
    document.addEventListener('DOMContentLoaded', () => {{
        const d = new Date();
        document.getElementById('scan-timestamp').textContent =
            'Generata: ' + d.toLocaleDateString('it-IT') + ' ' + d.toLocaleTimeString('it-IT', {{hour:'2-digit', minute:'2-digit'}});

        // Global stats
        document.getElementById('gs-total').textContent     = STATS.total;
        document.getElementById('gs-danger').textContent    = STATS.critical + STATS.high;
        document.getElementById('gs-confirmed').textContent = STATS.confirmed;
        document.getElementById('gs-static').textContent    = ENDPOINTS.length;

        // Tab counts
        document.getElementById('tab-count-1').textContent = checkovFindings.length;
        document.getElementById('tab-count-2').textContent = ENDPOINTS.length;
        document.getElementById('tab-count-3').textContent = STATS.bola_total;

        buildCheckovUI();
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

    function countBy(arr, keyFn) {{
        const m = {{}};
        arr.forEach(x => {{ const k = keyFn(x); m[k] = (m[k]||0)+1; }});
        return m;
    }}

    function toggleRow(element) {{
        element.classList.toggle('expanded');
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

    function renderFindingCard(f) {{
        const sevCls = 'sev-' + f.severity.toLowerCase();
        let meta = '';
        if (f.resource_id)          meta += `<div class="meta-row"><span class="meta-key">Risorsa</span><span class="meta-val">${{f.resource_id}}</span></div>`;
        if (f.location?.file_path)  meta += `<div class="meta-row"><span class="meta-key">File</span><span class="meta-val">${{f.location.file_path}}${{f.location.start_line?' :'+f.location.start_line:''}}</span></div>`;
        if (f.rule_id)              meta += `<div class="meta-row"><span class="meta-key">Regola Checkov</span><span class="meta-val">${{f.rule_id}}</span></div>`;
        
        const remediation = f.remediation
            ? `<div class="remediation-box"><h4>Rimedio Suggerito</h4><p>${{f.remediation}}</p></div>` : '';

        return `<div class="fcard ${{sevCls}}">
            <div class="fcard-header">
                <div class="fcard-title">${{f.title}}</div>
                <div class="fcard-tags">
                    ${{sevTag(f.severity)}}
                </div>
            </div>
            <div class="fcard-desc">${{f.description}}</div>
            ${{meta ? '<div class="fcard-meta">'+meta+'</div>' : ''}}
            ${{remediation}}
        </div>`;
    }}

    /* ================================================================ */
    /* PANEL 1 — CHECKOV                                                */
    /* ================================================================ */
    function buildCheckovUI() {{
        makeSectionStats('checkov-section-stats', [
            ['Findings Checkov', checkovFindings.length,  'var(--sky)'],
            ['Critico',          STATS.checkov_critical,  'var(--rose)'],
            ['Alto',             STATS.checkov_high,      'var(--amber)'],
            ['Medio',            STATS.checkov_medium,    'var(--indigo)'],
            ['Basso',            STATS.checkov_low,       'var(--teal)'],
        ]);
        
        buildSevFilters('filter-checkov-sev', checkovFindings, 'flt-active1', 'checkov', 'sev', renderCheckov);
        buildCatFilters('filter-checkov-cat', checkovFindings, 'flt-active1', 'checkov', 'cat', renderCheckov);
        renderCheckov();
    }}

    function buildSevFilters(containerId, findings, activeClass, stateName, subKey, renderFn) {{
        const counts = countBy(findings, f => f.severity);
        const sevs = ['CRITICAL','HIGH','MEDIUM','LOW','INFO']
            .filter(s => counts[s])
            .map(s => [s, s[0]+s.slice(1).toLowerCase(), counts[s]]);

        const el = document.getElementById(containerId);
        el.innerHTML = '';
        [['ALL','Tutte', findings.length], ...sevs].forEach(([val, label, cnt]) => {{
            const btn = document.createElement('button');
            btn.className = 'flt-btn' + (state[stateName][subKey] === val ? ' '+activeClass : '');
            btn.innerHTML = `${{label}} <span class="fc">${{cnt}}</span>`;
            btn.onclick = () => {{ 
                state[stateName][subKey] = val; 
                renderFn(); 
                buildSevFilters(containerId, findings, activeClass, stateName, subKey, renderFn); 
            }};
            el.appendChild(btn);
        }});
    }}

    function buildCatFilters(containerId, findings, activeClass, stateName, subKey, renderFn) {{
        const counts = countBy(findings, f => f.category);
        const cats = Object.entries(counts).map(([k,v]) => [k, k.replace(/_/g,' '), v]);
        const el = document.getElementById(containerId);
        el.innerHTML = '';
        [['ALL','Tutte', findings.length], ...cats].forEach(([val,label,cnt]) => {{
            const btn = document.createElement('button');
            btn.className = 'flt-btn' + (state[stateName][subKey] === val ? ' '+activeClass : '');
            btn.innerHTML = `${{label}} <span class="fc">${{cnt}}</span>`;
            btn.onclick = () => {{ 
                state[stateName][subKey] = val; 
                renderFn(); 
                buildCatFilters(containerId, findings, activeClass, stateName, subKey, renderFn); 
            }};
            el.appendChild(btn);
        }});
    }}

    function renderCheckov() {{
        const q = (document.getElementById('search-checkov').value||'').toLowerCase();
        const filtered = checkovFindings.filter(f => {{
            if (state.checkov.sev !== 'ALL' && f.severity !== state.checkov.sev) return false;
            if (state.checkov.cat !== 'ALL' && f.category !== state.checkov.cat) return false;
            if (q && !(f.title+f.description+(f.rule_id||'')+(f.resource_id||'')).toLowerCase().includes(q)) return false;
            return true;
        }});

        document.getElementById('checkov-result-count').textContent =
            filtered.length + ' di ' + checkovFindings.length + ' findings';

        const container = document.getElementById('checkov-list');
        const empty     = document.getElementById('checkov-empty');
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
        makeSectionStats('openapi-section-stats', [
            ['Rotte Totali',    STATS.openapi_total,      'var(--violet)'],
            ['Documentate',     STATS.openapi_documented, 'var(--emerald)'],
            ['Shadow API',      STATS.openapi_shadow,     'var(--orange)'],
            ['Violazioni Spec', STATS.openapi_violations, 'var(--rose)'],
        ]);
        renderOpenAPI();
    }}

    function setOpenAPIStatus(status) {{
        state.openapi.status = status;
        const btns = document.querySelectorAll('#filter-openapi-status .flt-btn');
        btns.forEach((btn, idx) => {{
            const val = ['ALL', 'DOCUMENTED', 'SHADOW', 'VIOLATING'][idx];
            if (val === status) btn.classList.add('flt-active2');
            else btn.classList.remove('flt-active2');
        }});
        renderOpenAPI();
    }}

    function renderOpenAPI() {{
        const q = (document.getElementById('search-openapi').value||'').toLowerCase();
        const filtered = ENDPOINTS.filter(e => {{
            if (state.openapi.status === 'DOCUMENTED' && !e.documented) return false;
            if (state.openapi.status === 'SHADOW' && !e.shadow) return false;
            if (state.openapi.status === 'VIOLATING' && e.violations.length === 0) return false;
            
            if (q && !(e.path + e.method + (e.summary||'') + (e.description||'')).toLowerCase().includes(q)) return false;
            return true;
        }});

        document.getElementById('openapi-result-count').textContent =
            filtered.length + ' di ' + ENDPOINTS.length + ' endpoint catalogati';

        const container = document.getElementById('openapi-endpoints-list');
        const empty     = document.getElementById('openapi-empty');

        if (filtered.length === 0) {{
            container.innerHTML = '';
            empty.style.display = 'block';
            return;
        }}
        empty.style.display = 'none';

        container.innerHTML = filtered.map(e => {{
            let statusTag = '';
            if (e.shadow) {{
                statusTag = '<span class="ep-status-tag status-shadow">👻 Shadow API</span>';
            }} else if (e.violations.length > 0) {{
                statusTag = `<span class="ep-status-tag status-violating">⚠️ ${{e.violations.length}} Violazioni Contratto</span>`;
            }} else {{
                statusTag = '<span class="ep-status-tag status-compliant">🟢 Documentato &amp; Conforme</span>';
            }}

            let detailsHtml = '';
            if (e.shadow) {{
                detailsHtml = `
                    <div class="detail-card" style="border-left: 2px solid var(--orange);">
                        <h4>Evidenza Endpoint Shadow</h4>
                        <p>Questo endpoint è stato scoperto dinamicamente intercettando il traffico applicativo reale, ma non è documentato nelle specifiche OpenAPI ufficiale (openapi.yaml).</p>
                        <p style="margin-top: 0.4rem; font-size: 0.8rem; color: var(--text-muted);">Azione consigliata: Documentare il percorso nella specifica OpenAPI per prevenire problemi di tracciabilità delle API.</p>
                    </div>`;
            }} else if (e.violations.length > 0) {{
                detailsHtml = `
                    <div class="detail-card">
                        <h4>Violazioni di Conformità Spectral</h4>
                        <div style="display:flex; flex-direction:column; gap:0.6rem;">
                            ${{e.violations.map(v => `
                                <div class="violation-item">
                                    <div class="violation-title">${{v.rule_id}}</div>
                                    <div class="violation-desc">${{v.description}}</div>
                                    <div style="font-size:0.75rem; color:var(--text-muted); margin-top:0.15rem;">
                                        Severità: ${{v.severity}} ${{v.line ? '· Riga: ' + v.line : ''}}
                                    </div>
                                </div>
                            `).join('')}}
                        </div>
                    </div>`;
            }} else {{
                detailsHtml = `
                    <div class="detail-card" style="border-left: 2px solid var(--emerald);">
                        <p>L'endpoint rispetta tutte le regole del contratto previste da Stoplight Spectral (Nessuna violazione OWASP API).</p>
                    </div>`;
            }}

            return `
                <div class="ep-row">
                    <div class="ep-main-info" onclick="toggleRow(this.parentElement)">
                        <span class="ep-method method-${{e.method.toLowerCase()}}">${{e.method}}</span>
                        <span class="ep-path">${{e.path}}</span>
                        <div class="ep-status-badges">
                            ${{statusTag}}
                        </div>
                        <span class="ep-chevron">▶</span>
                    </div>
                    <div class="ep-details">
                        <p style="font-size:0.83rem; color:var(--text-secondary); margin-bottom: 0.8rem;">
                            <strong>Summary:</strong> ${{e.summary || 'Nessun sommario'}}<br>
                            ${{e.description ? '<strong>Description:</strong> ' + e.description : ''}}
                        </p>
                        ${{detailsHtml}}
                    </div>
                </div>`;
        }}).join('');
    }}

    /* ================================================================ */
    /* PANEL 3 — BOLA                                                    */
    /* ================================================================ */
    function buildBolaUI() {{
        makeSectionStats('bola-section-stats', [
            ['Endpoint Dinamici', STATS.bola_total,      'var(--rose)'],
            ['BOLA Vulnerabili',  STATS.bola_vulnerable,   'var(--rose)'],
            ['BOLA Potenziali',   STATS.bola_potential,    'var(--amber)'],
            ['Test Sicuri',       STATS.bola_safe,         'var(--emerald)'],
        ]);
        renderBola();
    }}

    function setBolaStatus(status) {{
        state.bola.status = status;
        const btns = document.querySelectorAll('#filter-bola-status .flt-btn');
        btns.forEach((btn, idx) => {{
            const val = ['ALL', 'VULNERABLE', 'POTENTIAL', 'SAFE'][idx];
            if (val === status) btn.classList.add('flt-active3');
            else btn.classList.remove('flt-active3');
        }});
        renderBola();
    }}

    function renderBola() {{
        const q = (document.getElementById('search-bola').value||'').toLowerCase();
        
        const filtered = ENDPOINTS.filter(e => {{
            if (!e.is_dynamic) return false;
            if (state.bola.status !== 'ALL' && e.bola_status !== state.bola.status) return false;
            if (q && !(e.path + e.method + e.bola_status).toLowerCase().includes(q)) return false;
            return true;
        }});

        document.getElementById('bola-result-count').textContent =
            filtered.length + ' di ' + STATS.bola_total + ' endpoint dinamici analizzati';

        const container = document.getElementById('bola-endpoints-list');
        const empty     = document.getElementById('bola-empty');

        if (filtered.length === 0) {{
            container.innerHTML = '';
            empty.style.display = 'block';
            return;
        }}
        empty.style.display = 'none';

        container.innerHTML = filtered.map(e => {{
            let statusTag = '';
            if (e.bola_status === 'VULNERABLE') {{
                statusTag = '<span class="bola-status-badge bola-vulnerable">🔴 BOLA Rilevato</span>';
            }} else if (e.bola_status === 'POTENTIAL') {{
                statusTag = '<span class="bola-status-badge bola-potential">🟡 Potenziale BOLA</span>';
            }} else if (e.bola_status === 'SAFE') {{
                statusTag = '<span class="bola-status-badge bola-safe">🟢 Protetto / Sicuro</span>';
            }} else {{
                statusTag = '<span class="bola-status-badge bola-untested">⚪ Non Testato</span>';
            }}

            let testEvidenceHtml = '';
            if (e.bola_findings.length > 0) {{
                testEvidenceHtml = e.bola_findings.map(f => {{
                    const isConfirmed = f.validation_status === 'CONFIRMED';
                    let evidenceSnippet = '';
                    if (f.runtime_evidence) {{
                        const re = f.runtime_evidence;
                        evidenceSnippet = `
                            <div class="code-block">
                                [Evidenza di exploit a Runtime]<br>
                                URL Testato: ${{re.tested_url || 'N/D'}}<br>
                                Status Risposta: ${{re.http_status || 'N/D'}}<br>
                                ${{re.accessible_without_auth != null ? 'Accessibile senza autorizzazione: ' + re.accessible_without_auth + '<br>' : ''}}
                                ${{re.response_snippet ? 'Risposta payload: ' + re.response_snippet : ''}}
                            </div>`;
                    }}
                    return `
                        <div style="border-left: 2px solid ${{isConfirmed ? 'var(--rose)' : 'var(--amber)'}}; padding-left: 0.8rem; margin-bottom: 0.8rem;">
                            <div style="font-weight: 700; font-size: 0.85rem;">${{f.title}}</div>
                            <div style="font-size: 0.82rem; color: var(--text-secondary); margin-top: 0.15rem;">${{f.description}}</div>
                            ${{evidenceSnippet}}
                            ${{f.remediation ? `<div class="remediation-box" style="margin-top:0.4rem;"><h4>Mitigazione</h4><p>${{f.remediation}}</p></div>` : ''}}
                        </div>`;
                }}).join('');
            }} else if (e.bola_status === 'SAFE') {{
                testEvidenceHtml = `
                    <div style="border-left: 2px solid var(--emerald); padding-left: 0.8rem;">
                        <div style="font-weight: 700; font-size: 0.85rem; color: var(--emerald);">L'endpoint è protetto</div>
                        <div style="font-size: 0.82rem; color: var(--text-secondary); margin-top: 0.15rem;">
                            I test di tampering effettuati con token utente differenti (User A vs User B) e sessioni anonime sono stati rifiutati correttamente dall'applicazione con codici di stato di sicurezza (es. 403 Forbidden o 401 Unauthorized).
                        </div>
                    </div>`;
            }} else {{
                testEvidenceHtml = `
                    <div style="border-left: 2px solid var(--text-muted); padding-left: 0.8rem; color: var(--text-muted); font-size:0.82rem;">
                        Nessun test dinamico eseguito per questo endpoint.
                    </div>`;
            }}

            return `
                <div class="ep-row">
                    <div class="ep-main-info" onclick="toggleRow(this.parentElement)">
                        <span class="ep-method method-${{e.method.toLowerCase()}}">${{e.method}}</span>
                        <span class="ep-path">${{e.path}}</span>
                        <div class="ep-status-badges">
                            ${{statusTag}}
                        </div>
                        <span class="ep-chevron">▶</span>
                    </div>
                    <div class="ep-details">
                        <div class="detail-card">
                            <h4>Dettaglio Testing Sicurezza Autorizzazioni</h4>
                            ${{testEvidenceHtml}}
                        </div>
                    </div>
                </div>`;
        }}).join('');
    }}
    </script>
</body>
</html>"""
