import json
import os
from mitmproxy import http

class TrafficLogger:
    """Mitmproxy addon to capture and log API requests/responses for dynamic security testing."""
    
    def __init__(self):
        self.output_path = "/home/mitmproxy/output/raw_traffic.json"
        self.requests = []
        os.makedirs(os.path.dirname(self.output_path), exist_ok=True)
        
        # Carica traffico esistente se presente
        if os.path.exists(self.output_path):
            try:
                with open(self.output_path, "r", encoding="utf-8") as f:
                    self.requests = json.load(f)
            except Exception:
                self.requests = []

    def response(self, flow: http.HTTPFlow) -> None:
        request = flow.request
        response = flow.response
        host = request.pretty_host
        
        # Filtra traffico rilevante per l'ambiente lab
        if any(h in host for h in ("localhost", "api-server", "127.0.0.1", "host.docker.internal", "localstack")):
            auth_header = request.headers.get("Authorization", "")
            
            body_params = {}
            if request.content:
                try:
                    body_params = json.loads(request.text)
                except Exception:
                    pass

            req_data = {
                "method": request.method,
                "path": request.path,
                "full_url": request.url,
                "status": response.status_code,
                "headers": dict(request.headers),
                "auth_header": auth_header,
                "body_params": body_params
            }
            
            self.requests.append(req_data)
            
            # Scrivi su file JSON
            try:
                with open(self.output_path, "w", encoding="utf-8") as f:
                    json.dump(self.requests, f, indent=2, ensure_ascii=False)
            except Exception:
                pass

addons = [
    TrafficLogger()
]
