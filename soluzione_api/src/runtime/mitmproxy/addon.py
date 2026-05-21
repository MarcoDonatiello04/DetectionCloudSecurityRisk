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
        # Inizializziamo come lista vuota solo se il file non esiste ancora (append mode)
        if not os.path.exists(self.output_file):
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump([], f)
        print(f"⚡ Mitmproxy Addon caricato correttamente. Scrittura su (append-mode): {self.output_file}")

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

        # Estrazione Body Richiesta
        request_body = ""
        if request.content:
            try:
                request_body = request.text or ""
            except Exception:
                try:
                    request_body = request.content.decode('utf-8', errors='ignore')
                except Exception:
                    pass

        # Estrazione Body Risposta
        response_body = ""
        if response.content:
            try:
                response_body = response.text or ""
            except Exception:
                try:
                    response_body = response.content.decode('utf-8', errors='ignore')
                except Exception:
                    pass

        # Normalizzazione path per ottenere SOLO il path relativo (es. /users/42)
        clean_path = request.path.split('?')[0]
        if "_user_request_" in clean_path:
            relative_path = clean_path.split("_user_request_")[-1]
            if not relative_path.startswith("/"):
                relative_path = "/" + relative_path
        else:
            relative_path = clean_path

        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "method": request.method.upper(),
            "path": relative_path,
            "full_url": request.url,
            "headers": dict(request.headers),
            "request_body": request_body,
            "status_code": response.status_code,
            "response_body": response_body
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
