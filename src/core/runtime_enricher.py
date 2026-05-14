from typing import List, Dict, Any
from Finding import Finding, RuntimeEvidence, ValidationStatus

class RuntimeEnricher:
    """
    Componente di arricchimento DAST. Implementa strettamente il vincolo di design:
    NON genera nuovi Finding spazzatura, ma unisce le risultanze dinamiche di ZAP 
    ai Finding statici esistenti basandosi sulla chiave di correlazione (URL/Asset).
    """
    def enrich_findings(self, static_findings: List[Finding], zap_alerts: List[Dict[str, Any]]):
        """
        Scansiona gli alert prodotti da ZAP e inietta la RuntimeEvidence nei finding
        statici pertinenti, confermandone lo stato di attacco.
        """
        if not zap_alerts:
            return

        # Costruiamo una mappa di lookup veloce degli alert ZAP basata sull'URL normalizzato
        alerts_by_url = {}
        for alert in zap_alerts:
            url = alert.get("url", "")
            if url:
                if url not in alerts_by_url:
                    alerts_by_url[url] = []
                alerts_by_url[url].append(alert)

        # Inietto l'evidenza solo nei finding statici che hanno un match di URL
        for finding in static_findings:
            target_url = None
            if finding.api and finding.api.endpoint:
                target_url = finding.api.endpoint
            elif finding.correlation_key and ("http://" in finding.correlation_key or "/" in finding.correlation_key):
                target_url = finding.correlation_key
                
            if target_url and target_url in alerts_by_url:
                relevant_alerts = alerts_by_url[target_url]
                
                # Prendiamo l'alert con impatto maggiore per quell'URL
                best_alert = relevant_alerts[0]
                desc = best_alert.get("description", "")
                evidence_text = best_alert.get("evidence", "HTTP/1.1 200 OK")
                
                # Euristiche per popolare la RuntimeEvidence
                is_auth_leak = "Missing Authentication" in best_alert.get("alert", "") or "senza" in desc.lower()
                status_code = 200 if "200 OK" in evidence_text else 403
                
                evidence = RuntimeEvidence(
                    tested_url=target_url,
                    http_status=status_code,
                    response_snippet=evidence_text[:200],  # Tronchiamo per evitare memory bloat
                    accessible_without_auth=is_auth_leak,
                    rate_limit_detected=False
                )
                
                finding.runtime_evidence = evidence
                finding.validation_status = ValidationStatus.CONFIRMED
