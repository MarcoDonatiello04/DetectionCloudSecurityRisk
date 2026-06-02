import json
import urllib.request
import urllib.parse
import urllib.error
import time
import logging
from typing import List, Dict, Any
from src.domain.interfaces import IScanner
from src.domain.entities import Finding, FindingSource, FindingCategory, Severity, APIContext, RiskContext

logger = logging.getLogger("SecurityPlatform.ZapAdapter")

# Configurazione default di esecuzione per ZAP Daemon
DEFAULT_ZAP_URL = "http://localhost:8090"
API_CALL_TIMEOUT_SECONDS = 10
SPIDER_POLL_INTERVAL_SECONDS = 1


class ZapClientAdapter(IScanner):
    """
    Adapter DAST per OWASP ZAP Daemon.
    Stimola l'applicazione target generando traffico e raccoglie gli Alert DAST
    trasformandoli nel modello di Finding del Dominio.
    """

    def __init__(self, zap_url: str = DEFAULT_ZAP_URL, api_key: str = ""):
        """
        Inizializza l'adattatore ZapClientAdapter con l'URL del demone e la chiave API.

        Args:
            zap_url (str): L'URL completo del demone ZAP.
            api_key (str): Chiave API opzionale per l'autenticazione su ZAP.
        """
        self.zap_url = zap_url.rstrip("/")
        self.api_key = api_key

    def _call_api(self, endpoint: str, params: Dict[str, str] = {}) -> Dict[str, Any]:
        """
        Esegue una chiamata HTTP GET JSON verso l'API REST di OWASP ZAP.

        Args:
            endpoint (str): Il percorso dell'endpoint API di ZAP (es. spider/view/status/).
            params (Dict[str, str]): Parametri di query aggiuntivi.

        Returns:
            Dict[str, Any]: I dati JSON deserializzati restituiti da ZAP, o un dizionario vuoto in caso di errore.
        """
        try:
            url = f"{self.zap_url}/JSON/{endpoint}"
            query_parts = []
            if self.api_key:
                query_parts.append(f"apikey={self.api_key}")
            for k, v in params.items():
                query_parts.append(f"{k}={urllib.parse.quote(str(v))}")
                
            if query_parts:
                url += "?" + "&".join(query_parts)
                
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=API_CALL_TIMEOUT_SECONDS) as response:
                return json.loads(response.read().decode('utf-8'))
        except (urllib.error.URLError, json.JSONDecodeError, OSError, Exception) as e:
            logger.debug(f"Chiamata API ZAP fallita ({endpoint}): {e}")
            return {}

    def is_alive(self) -> bool:
        """
        Controlla se il demone OWASP ZAP è attivo e raggiungibile.

        Returns:
            bool: True se ZAP risponde correttamente, altrimenti False.
        """
        resp = self._call_api("core/view/version/")
        return "version" in resp

    def scan(self, target_url: str) -> List[Finding]:
        """
        Esegue lo spidering su target_url per stimolare le API 
        e raccoglie i findings/alert generati da ZAP.

        Args:
            target_url (str): L'URL completo dell'applicazione target da scansionare.

        Returns:
            List[Finding]: Lista di Finding generati dagli alert di sicurezza di ZAP.
        """
        logger.info(f"🚀 Avvio scansione attiva DAST tramite ZAP su: {target_url}")
        if not self.is_alive():
            logger.warning(f"OWASP ZAP Daemon non raggiungibile su {self.zap_url}. DAST saltato.")
            return []

        # 1. Avvia Spidering
        resp = self._call_api("spider/action/scan/", {"url": target_url})
        scan_id = resp.get("scan")
        if scan_id is not None:
            logger.info("🕸️ Avviato ZAP Spider...")
            while True:
                status_resp = self._call_api("spider/view/status/", {"scanId": scan_id})
                status = int(status_resp.get("status", 100))
                if status >= 100:
                    break
                time.sleep(SPIDER_POLL_INTERVAL_SECONDS)
        
        # 2. Recupero degli Alert registrati da ZAP
        findings: List[Finding] = []
        alerts_resp = self._call_api("core/view/alerts/", {"baseurl": target_url})
        alerts = alerts_resp.get("alerts", [])
        
        logger.info(f"Rilevati {len(alerts)} alert grezzi da ZAP.")
        for alert in alerts:
            alert_id = alert.get("id", "zap-alert")
            alert_name = alert.get("alert", "Vulnerabilità DAST")
            description = alert.get("description", "")
            url = alert.get("url", "")
            method = alert.get("method", "GET")
            param = alert.get("param", "")
            evidence = alert.get("evidence", "")
            
            # Mappatura della severità ZAP (High, Medium, Low, Informational)
            risk = alert.get("risk", "Informational")
            severity = Severity.INFO
            if risk == "High":
                severity = Severity.HIGH
            elif risk == "Medium":
                severity = Severity.MEDIUM
            elif risk == "Low":
                severity = Severity.LOW

            # Mappatura categoria
            category = FindingCategory.RUNTIME_EXPOSURE
            alert_name_lower = alert_name.lower()
            if "sql" in alert_name_lower or "injection" in alert_name_lower:
                category = FindingCategory.INJECTION
            elif "xss" in alert_name_lower or "cross-site scripting" in alert_name_lower:
                category = FindingCategory.INPUT_VALIDATION
            elif "auth" in alert_name_lower or "session" in alert_name_lower:
                category = FindingCategory.AUTHENTICATION
            elif "header" in alert_name_lower:
                category = FindingCategory.SECURITY_HEADERS

            path = urllib.parse.urlparse(url).path
            api_ctx = APIContext(
                endpoint=path,
                method=method,
                base_url=target_url
            )
            
            finding = Finding.create(
                source=FindingSource.ZAP_DAST,
                category=category,
                title=alert_name,
                description=f"{description}\nParametro affetto: {param}\nEvidenza: {evidence}",
                severity=severity,
                confidence=0.9,
                rule_id=alert.get("pluginId", alert_id),
                target_identifier=f"{method}:{path}:{alert_name}",
                rule_name=alert_name,
                api=api_ctx,
                risk_context=RiskContext(exploitable=True, internet_exposed=True),
                raw_data=alert
            )
            findings.append(finding)

        return findings
