import logging
import time
import urllib.parse

from zapv2 import ZAPv2

from src.domain.entities import (
    APIContext,
    Finding,
    FindingCategory,
    FindingSource,
    RiskContext,
    Severity,
)
from src.domain.interfaces import IScanner

logger = logging.getLogger("SecurityPlatform.ZapAdapter")

from src.core.config import DEFAULT_ZAP_URL
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
        # Configura ZAPv2 per usare il proxy
        self.zap = ZAPv2(proxies={"http": self.zap_url, "https": self.zap_url}, apikey=api_key)

    def is_alive(self) -> bool:
        """
        Controlla se il demone OWASP ZAP è attivo e raggiungibile.

        Returns:
            bool: True se ZAP risponde correttamente, altrimenti False.
        """
        try:
            version = self.zap.core.version
            return version is not None
        except Exception as e:
            logger.debug(f"Connessione ZAP fallita: {e}")
            return False

    def scan(self, target_url: str) -> list[Finding]:
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
        try:
            resp = self.zap.spider.scan(url=target_url)
            # Gestiamo sia dizionari che stringhe di risposta
            scan_id = resp.get("scan") if isinstance(resp, dict) else resp
            if scan_id is not None:
                logger.info("🕸️ Avviato ZAP Spider...")
                while True:
                    status = int(self.zap.spider.status(scanid=scan_id))
                    if status >= 100:
                        break
                    time.sleep(SPIDER_POLL_INTERVAL_SECONDS)
        except Exception as e:
            logger.warning(f"Spidering ZAP fallito o saltato: {e}")

        # 2. Recupero degli Alert registrati da ZAP
        findings: list[Finding] = []
        try:
            alerts = self.zap.core.alerts(baseurl=target_url)
            logger.info(f"Rilevati {len(alerts)} alert grezzi da ZAP per target {target_url}.")

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
                api_ctx = APIContext(endpoint=path, method=method, base_url=target_url)

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
                    raw_data=alert,
                )
                findings.append(finding)
        except Exception as e:
            logger.error(f"Errore recupero alert da ZAP: {e}", exc_info=True)

        return findings


ZapScannerAdapter = ZapClientAdapter
ZapAdapter = ZapClientAdapter


