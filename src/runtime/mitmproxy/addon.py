import json
import os
from datetime import datetime
from mitmproxy import http

class TrafficExtractorAddon:
    def __init__(self):
        # We can support running both inside Docker (volume mapped) and natively
        # If we are inside Docker, the mapped volume is /home/mitmproxy/output/
        # If we are native, we can save to the local src/output/ directory
        if os.path.exists("/home/mitmproxy/output"):
            self.output_file = "/home/mitmproxy/output/raw_traffic.json"
        else:
            self.output_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../output/raw_traffic.json"))
            
        os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
        # Inizializziamo come lista vuota
        with open(self.output_file, 'w') as f:
            json.dump([], f)
        print(f"⚡ Mitmproxy Addon caricato correttamente. Scrittura su: {self.output_file}")

    def request(self, flow: http.HTTPFlow):
        # Se l'host è localhost o 127.0.0.1, lo rimappiamo a host.docker.internal
        # in modo che il proxy possa contattare i servizi in esecuzione sull'host!
        if flow.request.pretty_host in ("localhost", "127.0.0.1"):
            flow.request.host = "host.docker.internal"

    def response(self, flow: http.HTTPFlow):
        # Filtriamo le richieste per catturare solo quelle dell'infrastruttura locale
        host = flow.request.pretty_host
        if not any(target in host for target in ("localhost", "127.0.0.1", "host.docker.internal", "localstack")):
            # Se stiamo usando LocalStack all'interno di compose, l'host potrebbe essere localstack o localstack-main
            if not any(target in host for target in ("localstack", "tesi-zap", "zap")):
                return

        request = flow.request
        response = flow.response

        # Estrazione Query Parameters
        query_params = dict(request.query)

        # Estrazione Body Parameters (JSON o Form urlencoded)
        body_params = {}
        if request.content:
            try:
                body_params = json.loads(request.text)
            except Exception:
                try:
                    body_params = dict(request.urlencoded_form)
                except Exception:
                    pass

        # Estrazione Auth Headers
        auth_header = request.headers.get("Authorization", "")
        
        # Normalizzazione path per rimuovere query parameters
        clean_path = request.path.split('?')[0]

        log_entry = {
            "source": "runtime",
            "method": request.method.upper(),
            "path": clean_path,
            "full_url": request.url,
            "status": response.status_code,
            "query_params": query_params,
            "body_params": body_params,
            "headers": dict(request.headers),
            "response_headers": dict(response.headers),
            "content_type": response.headers.get("Content-Type", ""),
            "auth_header": auth_header,
            "timestamp": datetime.utcnow().isoformat()
        }

        # Carica il file esistente, aggiungi il log e salva
        try:
            traffic = []
            if os.path.exists(self.output_file):
                with open(self.output_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if content:
                        traffic = json.loads(content)
            
            traffic.append(log_entry)
            
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(traffic, f, indent=2)
        except Exception as e:
            print(f"⚠️ Errore addon Mitmproxy durante la scrittura: {e}")

addons = [
    TrafficExtractorAddon()
]
