import logging
from typing import List, Dict, Any, Set
from src.domain.interfaces import IDetector
from src.domain.entities import Finding, FindingSource, FindingCategory, Severity, APIContext, RuntimeEvidence, RiskContext
from src.domain.events import EVENT_STATIC_SCAN_COMPLETED, EVENT_TRAFFIC_CAPTURED
from src.normalization.normalizer import APIEndpointNormalizer

logger = logging.getLogger("SecurityPlatform.Plugins.ShadowAPIDetector")


class ShadowAPIDetectorPlugin(IDetector):
    """
    Detector Plugin per la rilevazione di Shadow APIs (API non documentate).
    Confronta gli endpoint osservati a runtime con le rotte dichiarate nei sorgenti.
    Qualsiasi traffico runtime verso percorsi non mappati staticamente solleva un alert critico.
    """

    def __init__(self):
        # Insieme degli endpoint statici noti in formato "METHOD:PATH"
        self._static_routes: Set[str] = set()

    @property
    def name(self) -> str:
        return "Shadow-API-Hunter-Plugin"

    @property
    def subscribed_events(self) -> List[str]:
        return [EVENT_STATIC_SCAN_COMPLETED, EVENT_TRAFFIC_CAPTURED]

    def analyze(self, payload: Any) -> List[Finding]:
        findings: List[Finding] = []
        
        # 1. Carica le rotte statiche note
        if "static_findings" in payload:
            logger.info("🕵️‍♂️ [Shadow API Plugin] Registrazione rotte statiche note...")
            static_findings = payload.get("static_findings", [])
            for sf in static_findings:
                # Estraiamo informazioni sull'API se presenti
                api_data = sf.get("api")
                if api_data and api_data.get("endpoint"):
                    norm_path = APIEndpointNormalizer.normalize_path(api_data["endpoint"])
                    method = (api_data.get("method") or "GET").upper()
                    self._static_routes.add(f"{method}:{norm_path}")
            logger.info(f"   Mappate {len(self._static_routes)} rotte statiche nel plugin.")

        # 2. Cerca Shadow API confrontando il traffico reale
        elif "traffic" in payload:
            logger.info("🕵️‍♂️ [Shadow API Plugin] Scansione traffico catturato per identificare rotte non documentate...")
            traffic = payload.get("traffic", [])
            findings.extend(self._hunt_shadow_apis(traffic))

        return findings

    def _hunt_shadow_apis(self, traffic: List[Dict[str, Any]]) -> List[Finding]:
        findings = []
        seen_shadows = set()

        for req in traffic:
            method = req.get("method", "GET").upper()
            raw_path = req.get("path", "")
            
            # Filtra path rumorosi o file statici standard
            if any(term in raw_path.lower() for term in ["robots.txt", "favicon.ico", "sitemap.xml"]):
                continue
                
            norm_path = APIEndpointNormalizer.normalize_path(raw_path)
            route_key = f"{method}:{norm_path}"
            
            # Se la rotta a runtime NON è presente nell'insieme statico, è una Shadow API!
            if route_key not in self._static_routes and route_key not in seen_shadows:
                seen_shadows.add(route_key)
                logger.warning(f"🔥 Rilevata Shadow API non documentata: {method} {norm_path}")
                
                api_ctx = APIContext(
                    endpoint=norm_path,
                    method=method,
                    base_url=req.get("full_url", "").replace(raw_path, "")
                )
                
                evidence = RuntimeEvidence(
                    tested_url=req.get("full_url"),
                    http_status=req.get("status")
                )
                
                finding = Finding.create(
                    source=FindingSource.SHADOW_API,
                    category=FindingCategory.API_EXPOSURE,
                    title="Shadow API (Endpoint non documentato rilevato a runtime)",
                    description=f"Rilevata chiamata HTTP verso '{method} {norm_path}' nel traffico di runtime, ma nessun endpoint corrispondente è stato trovato nel codice sorgente analizzato. Questo indica la presenza di una Shadow API non tracciata o di una potenziale backdoor.",
                    severity=Severity.HIGH,
                    confidence=0.9,
                    rule_id="shadow-api-detected",
                    target_identifier=route_key,
                    rule_name="Shadow API Detection",
                    api=api_ctx,
                    runtime_evidence=evidence,
                    risk_context=RiskContext(internet_exposed=True),
                    correlation_key=f"api:{method}:{norm_path}",
                    raw_data=req
                )
                findings.append(finding)
                
        return findings
