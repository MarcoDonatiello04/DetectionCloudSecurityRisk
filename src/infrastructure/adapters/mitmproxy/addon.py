import contextlib
import json
import os

from mitmproxy import http  # type: ignore[attr-defined]

# Percorso di log di default per il container mitmproxy
DEFAULT_TRAFFIC_LOG_PATH = "/home/mitmproxy/output/raw_traffic.json"


class TrafficLogger:
    """
    Componente Addon di Mitmproxy per intercettare e registrare richieste e risposte HTTP.
    Filtra le chiamate dirette all'ambiente lab per l'analisi dinamica (D-AST).
    """

    def __init__(self):
        """
        Inizializza il TrafficLogger caricando lo storico del traffico esistente se presente.
        """
        self.output_path = DEFAULT_TRAFFIC_LOG_PATH
        self.requests = []
        os.makedirs(os.path.dirname(self.output_path), exist_ok=True)

        # Carica traffico esistente se presente
        if os.path.exists(self.output_path):
            try:
                with open(self.output_path, encoding="utf-8") as f:
                    self.requests = json.load(f)
            except Exception:
                self.requests = []

    def response(self, flow: http.HTTPFlow) -> None:
        """
        Callback invocata da Mitmproxy alla ricezione di una risposta HTTP.
        Estrae informazioni utili come metodo, url, status, headers e corpo se diretti al lab.

        Args:
            flow (http.HTTPFlow): Rappresentazione della transazione HTTP catturata.
        """
        request = flow.request
        response = flow.response
        host = request.pretty_host

        # Filtra traffico rilevante per l'ambiente lab
        if any(
            h in host
            for h in ("localhost", "api-server", "127.0.0.1", "host.docker.internal", "localstack")
        ):
            auth_header = request.headers.get("Authorization", "")

            body_params = {}
            if request.content:
                with contextlib.suppress(Exception):
                    body_params = json.loads(request.text)

            req_data = {
                "method": request.method,
                "path": request.path,
                "full_url": request.url,
                "status": response.status_code,
                "headers": dict(request.headers),
                "auth_header": auth_header,
                "body_params": body_params,
            }

            self.requests.append(req_data)

            # Scrivi su file JSON
            try:
                with open(self.output_path, "w", encoding="utf-8") as f:
                    json.dump(self.requests, f, indent=2, ensure_ascii=False)
            except Exception:
                pass


addons = [TrafficLogger()]
