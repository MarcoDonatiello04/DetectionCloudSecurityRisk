import json
from typing import List, Dict, Any
from src.normalization.normalizer import APIEndpointNormalizer

class APICorrelationEngine:
    """
    Motore di Correlazione e Scoring per API Discovery.
    Unisce gli endpoint estratti dall'analisi statica (Semgrep) con quelli catturati
    a runtime (Mitmproxy), classificandoli ed aggregando metadati di sicurezza.
    """
    
    def __init__(self):
        self.unified_inventory: List[Dict[str, Any]] = []

    def correlate(self, static_endpoints: List[Dict[str, Any]], runtime_endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        self.unified_inventory = []
        
        # Mappa dei record indicizzati per chiave unica "METHOD:PATH"
        registry: Dict[str, Dict[str, Any]] = {}

        # 1. Inseriamo gli endpoint statici nel registro
        for se in static_endpoints:
            path = APIEndpointNormalizer.normalize_path(se.get("path", ""))
            method = se.get("method", "GET").upper()
            key = f"{method}:{path}"

            if key not in registry:
                registry[key] = {
                    "path": path,
                    "method": method,
                    "sources": ["static"],
                    "static_metadata": {
                        "file": se.get("file", ""),
                        "framework": se.get("framework", "unknown"),
                        "route_parameters": se.get("route_parameters", [])
                    },
                    "runtime_metadata": None,
                    "auth_detected": se.get("auth_detected", False),
                    "auth_sources": ["static"] if se.get("auth_detected") else [],
                    "query_params": [],
                    "body_params": [],
                    "observed_status_codes": [],
                    "classification": "STATIC_ONLY",
                    "confidence_score": 0.8
                }

        # 2. Correliamo con gli endpoint di runtime
        for re_ep in runtime_endpoints:
            path = APIEndpointNormalizer.normalize_path(re_ep.get("path", ""))
            method = re_ep.get("method", "GET").upper()
            key = f"{method}:{path}"

            # Controlla se a runtime è stata usata autenticazione
            has_runtime_auth = bool(re_ep.get("auth_header") or re_ep.get("headers", {}).get("Authorization"))
            
            # Estrazione parametri reali osservati
            q_params = list(re_ep.get("query_params", {}).keys())
            b_params = list(re_ep.get("body_params", {}).keys())
            status = re_ep.get("status")

            if key in registry:
                entry = registry[key]
                # Caso: CONFIRMED (Presente sia staticamente che runtime)
                if "static" in entry["sources"]:
                    if "runtime" not in entry["sources"]:
                        entry["sources"].append("runtime")
                    entry["classification"] = "CONFIRMED"
                    entry["confidence_score"] = 1.0
                else:
                    # Già inserito come RUNTIME_ONLY (Shadow API), rimane RUNTIME_ONLY
                    entry["classification"] = "RUNTIME_ONLY"
                    entry["confidence_score"] = 0.7
                
                # Iniezione metadati runtime
                entry["runtime_metadata"] = {
                    "last_seen_url": re_ep.get("full_url", ""),
                    "content_type": re_ep.get("content_type", "")
                }
                
                # Aggregazione indicatori auth
                if has_runtime_auth:
                    entry["auth_detected"] = True
                    if "runtime" not in entry["auth_sources"]:
                        entry["auth_sources"].append("runtime")
                
                # Aggregazione parametri
                entry["query_params"] = list(set(entry["query_params"] + q_params))
                entry["body_params"] = list(set(entry["body_params"] + b_params))
                if status and status not in entry["observed_status_codes"]:
                    entry["observed_status_codes"].append(status)
            else:
                # Caso: RUNTIME_ONLY (Shadow API - Trovato a runtime ma assente nel codice statico analizzato!)
                registry[key] = {
                    "path": path,
                    "method": method,
                    "sources": ["runtime"],
                    "static_metadata": None,
                    "runtime_metadata": {
                        "last_seen_url": re_ep.get("full_url", ""),
                        "content_type": re_ep.get("content_type", "")
                    },
                    "auth_detected": has_runtime_auth,
                    "auth_sources": ["runtime"] if has_runtime_auth else [],
                    "query_params": q_params,
                    "body_params": b_params,
                    "observed_status_codes": [status] if status else [],
                    "classification": "RUNTIME_ONLY",
                    "confidence_score": 0.7
                }

        self.unified_inventory = list(registry.values())
        return self.unified_inventory

    def generate_report(self) -> str:
        """Ritorna una stringa formattata contenente il report di correlazione raggruppato."""
        total = len(self.unified_inventory)
        confirmed_eps = [e for e in self.unified_inventory if e["classification"] == "CONFIRMED"]
        static_only_eps = [e for e in self.unified_inventory if e["classification"] == "STATIC_ONLY"]
        runtime_only_eps = [e for e in self.unified_inventory if e["classification"] == "RUNTIME_ONLY"]
        
        report = []
        report.append("="*80)
        report.append("📊 REPORT DI CORRELAZIONE & UNIFIED API INVENTORY")
        report.append("="*80)
        report.append(f"Totale Endpoint Unificati Rilevati: {total}")
        report.append(f" - [CONFIRMED]   Endpoint trovati in Codice e confermati a Runtime: {len(confirmed_eps)}")
        report.append(f" - [STATIC_ONLY] Endpoint definiti nel Codice ma MAI chiamati a Runtime: {len(static_only_eps)}")
        report.append(f" - [RUNTIME_ONLY] Shadow API (Rilevate SOLO da traffico Runtime!): {len(runtime_only_eps)}\n")
        
        # ----------------------------------------------------
        # Sezione 1: CONFIRMED
        # ----------------------------------------------------
        report.append("="*80)
        report.append("🟢 [CONFIRMED] ENDPOINT VERIFICATI (Rilevati in Codice + Traffico Runtime)")
        report.append("="*80)
        if not confirmed_eps:
            report.append("  Nessun endpoint confermato.")
        for idx, ep in enumerate(confirmed_eps, 1):
            report.append(f"  {idx}. {ep['method']} {ep['path']}")
            sources_desc = []
            if ep["static_metadata"]:
                fw_list = [f.strip() for f in ep["static_metadata"]["framework"].split(",")]
                for fw in fw_list:
                    if fw == "python-semgrep":
                        sources_desc.append("Semgrep (route-detect)")
                    else:
                        sources_desc.append(f"AST Heuristic ({fw})")
            sources_desc.append("ZAP Spider & Mitmproxy (Runtime)")
            report.append(f"     ↳ Rilevato tramite: {', '.join(sources_desc)}")
            if ep['static_metadata']:
                report.append(f"     ↳ Codice: File={ep['static_metadata']['file']}")
            if ep['runtime_metadata']:
                report.append(f"     ↳ Traffico: URL={ep['runtime_metadata']['last_seen_url']} | Status={ep['observed_status_codes']}")
            report.append("  " + "-"*50)
            
        report.append("")
        
        # ----------------------------------------------------
        # Sezione 2: RUNTIME_ONLY (Shadow APIs & Probes)
        # ----------------------------------------------------
        report.append("="*80)
        report.append("🔥 [RUNTIME_ONLY] SHADOW API & PROBES (Rilevati SOLO da ZAP/Mitmproxy - Assenti da Semgrep/Codice)")
        report.append("="*80)
        if not runtime_only_eps:
            report.append("  Nessuna Shadow API rilevata.")
        for idx, ep in enumerate(runtime_only_eps, 1):
            report.append(f"  {idx}. {ep['method']} {ep['path']}")
            report.append("     ↳ Rilevato tramite: ZAP Spider & Mitmproxy (Runtime) [ASSENTE da Semgrep e AST statici]")
            if ep['runtime_metadata']:
                report.append(f"     ↳ Dettagli Traffico: URL={ep['runtime_metadata']['last_seen_url']} | Status={ep['observed_status_codes']}")
            report.append("  " + "-"*50)
            
        report.append("")
        
        # ----------------------------------------------------
        # Sezione 3: STATIC_ONLY
        # ----------------------------------------------------
        report.append("="*80)
        report.append("🟡 [STATIC_ONLY] ENDPOINT INATTIVI (Rilevati SOLO da Semgrep/AST - Mai chiamati a Runtime)")
        report.append("="*80)
        if not static_only_eps:
            report.append("  Nessun endpoint statico inattivo.")
        for idx, ep in enumerate(static_only_eps, 1):
            report.append(f"  {idx}. {ep['method']} {ep['path']}")
            sources_desc = []
            if ep["static_metadata"]:
                fw_list = [f.strip() for f in ep["static_metadata"]["framework"].split(",")]
                for fw in fw_list:
                    if fw == "python-semgrep":
                        sources_desc.append("Semgrep (route-detect)")
                    else:
                        sources_desc.append(f"AST Heuristic ({fw})")
            report.append(f"     ↳ Rilevato tramite: {', '.join(sources_desc)} [MAI chiamato a Runtime]")
            if ep['static_metadata']:
                report.append(f"     ↳ Codice: File={ep['static_metadata']['file']}")
            report.append("  " + "-"*50)
            
        return "\n".join(report)
