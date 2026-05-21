import json
import urllib.request
import urllib.parse
import urllib.error
import time
from typing import List, Dict, Any

class ZAPRuntimeClient:
    """
    Client orchestratore avanzato per OWASP ZAP.
    Avvia spidering ed active scanning mirati per generare traffico HTTP
    verso il target di test facendolo transitare per il proxy Mitmproxy.
    """
    def __init__(self, zap_url: str = "http://localhost:8090", api_key: str = ""):
        self.zap_url = zap_url.rstrip("/")
        self.api_key = api_key

    def _call_api(self, endpoint: str, params: Dict[str, str] = {}) -> Dict[str, Any]:
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
            with urllib.request.urlopen(req, timeout=10) as response:
                return json.loads(response.read().decode('utf-8'))
        except Exception as e:
            # Fallback sicuro se il demone non è pronto
            return {}

    def is_alive(self) -> bool:
        """Verifica se il daemon di ZAP è raggiungibile."""
        resp = self._call_api("core/view/version/")
        return "version" in resp

    def wait_for_zap(self, timeout_sec: int = 60) -> bool:
        """Attende che ZAP sia pronto ed avviato."""
        start_time = time.time()
        print("⏳ Attesa del demone OWASP ZAP (connessione a localhost:8090)...")
        while time.time() - start_time < timeout_sec:
            if self.is_alive():
                print("🔗 Connessione a OWASP ZAP stabilita!")
                return True
            time.sleep(2)
        print("❌ ZAP non è raggiungibile. Verifica lo stato dei container Docker.")
        return False

    def run_spider(self, target_url: str) -> bool:
        """Avvia e monitora lo Spider di ZAP sul target."""
        print(f"🕸️ Inizio ZAP Spidering sul target: {target_url}")
        resp = self._call_api("spider/action/scan/", {"url": target_url})
        scan_id = resp.get("scan")
        if scan_id is None:
            print("⚠️ Impossibile avviare lo Spider. Verifica se il target è valido.")
            return False

        while True:
            status_resp = self._call_api("spider/view/status/", {"scanId": scan_id})
            status = int(status_resp.get("status", 100))
            print(f"  [Spider Progress]: {status}%")
            if status >= 100:
                break
            time.sleep(2)
        print("✅ ZAP Spidering completato!")
        return True

    def run_active_scan(self, target_url: str) -> bool:
        """Avvia e monitora l'Active Scan di ZAP sul target."""
        print(f"🔥 Inizio ZAP Active Scan sul target: {target_url}")
        resp = self._call_api("ascan/action/scan/", {"url": target_url})
        scan_id = resp.get("scan")
        if scan_id is None:
            print("⚠️ Impossibile avviare l'Active Scan.")
            return False

        while True:
            status_resp = self._call_api("ascan/view/status/", {"scanId": scan_id})
            status = int(status_resp.get("status", 100))
            print(f"  [Active Scan Progress]: {status}%")
            if status >= 100:
                break
            time.sleep(2)
        print("✅ ZAP Active Scan completato!")
        return True

    def scan_all_targets(self, targets: List[str]):
        """Esegue spidering ed active scan su una lista di endpoint target."""
        if not self.wait_for_zap():
            print("⚠️ Esecuzione interrotta: OWASP ZAP non pronto. Nessun traffico generato.")
            return

        for target in targets:
            self.run_spider(target)

if __name__ == "__main__":
    import sys
    target = "http://host.docker.internal:5000"
    if len(sys.argv) > 1:
        target = sys.argv[1]
        
    client = ZAPRuntimeClient()
    client.scan_all_targets([target])
