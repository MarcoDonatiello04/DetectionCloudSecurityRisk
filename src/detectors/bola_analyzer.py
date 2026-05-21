import json
import re
import uuid
import base64
import urllib.request
import urllib.error
import time

class BOLAAnalyzer:
    def __init__(self, traffic_file="captured_requests.json"):
        self.traffic_file = traffic_file
        self.findings = []
        
        # Regex per identificare ID numerici e UUID nell'URL
        self.numeric_id_regex = re.compile(r'/(\d+)(/|$)')
        self.uuid_regex = re.compile(r'/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(/|$)')
        self.alphanumeric_regex = re.compile(r'/([a-zA-Z0-9]{8,})(/|$)')
        
    def run_analysis(self):
        print(f"\n🕵️‍♂️ [BOLA Analyzer] Avvio analisi BOLA sul traffico catturato: {self.traffic_file}")
        try:
            with open(self.traffic_file, 'r', encoding='utf-8') as f:
                traffic = json.load(f)
        except Exception as e:
            print(f"⚠️ Errore lettura file traffico: {e}")
            return []
            
        if not traffic:
            print("⚠️ Nessun traffico da analizzare.")
            return []
            
        print(f"📦 Caricate {len(traffic)} richieste per l'analisi.")
        
        for req in traffic:
            # Evita endpoint chiaramente di login o senza percorsi utili
            if "login" in req.get("path", "").lower() or "auth" in req.get("path", "").lower():
                continue
                
            self._test_technique_1_id_tampering(req)
            self._test_technique_2_token_removal(req)
            self._test_technique_3_jwt_tampering(req)
            
        self._print_summary()
        return self.findings
        
    def _dispatch_request(self, method, url, headers, data=None):
        try:
            # encode data if present
            body = None
            if data:
                if isinstance(data, dict):
                    body = json.dumps(data).encode('utf-8')
                else:
                    body = data.encode('utf-8') if isinstance(data, str) else data
            
            # Pulisce gli header problematici se presenti
            clean_headers = {k: v for k, v in headers.items() if k.lower() not in ['host', 'content-length']}
            
            req = urllib.request.Request(url, data=body, headers=clean_headers, method=method)
            with urllib.request.urlopen(req, timeout=3) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except Exception as e:
            # Timeout o connessione rifiutata
            return 0, b""

    def _test_technique_1_id_tampering(self, req):
        url = req.get("full_url", "")
        method = req.get("method", "GET")
        headers = req.get("headers", {})
        body_params = req.get("body_params")
        
        num_matches = list(self.numeric_id_regex.finditer(url))
        uuid_matches = list(self.uuid_regex.finditer(url))
        
        tampered_urls = []
        
        if num_matches:
            for match in num_matches:
                original_id = match.group(1)
                idx = int(original_id)
                # Test ID+1, ID-1, ID+100
                for tampered_id in [idx + 1, idx - 1, idx + 100]:
                    if tampered_id < 0:
                        continue
                    new_url = url[:match.start(1)] + str(tampered_id) + url[match.end(1):]
                    tampered_urls.append((new_url, "Numeric ID Tampering"))
                    
        elif uuid_matches:
            for match in uuid_matches:
                new_uuid = str(uuid.uuid4())
                new_url = url[:match.start(1)] + new_uuid + url[match.end(1):]
                tampered_urls.append((new_url, "UUID Tampering"))
        
        for t_url, t_type in tampered_urls:
            status, resp_body = self._dispatch_request(method, t_url, headers, body_params)
            if status == 200 and len(resp_body) > 0:
                # Controlla se la risposta originale era diversa o se la risorsa appartiene ad un altro utente
                self.findings.append({
                    "technique": "ID Tampering (BOLA)",
                    "severity": "High",
                    "original_url": url,
                    "tampered_url": t_url,
                    "method": method,
                    "description": f"Possibile BOLA: Accesso riuscito con {t_type} restituendo 200 OK con corpo non vuoto."
                })
                print(f"  🔴 [BOLA DETECTED] {t_type} su {method} {t_url} -> 200 OK")

    def _test_technique_2_token_removal(self, req):
        url = req.get("full_url", "")
        method = req.get("method", "GET")
        headers = dict(req.get("headers", {}))
        body_params = req.get("body_params")
        
        if "Authorization" in headers:
            del headers["Authorization"]
        elif "authorization" in headers:
            del headers["authorization"]
        else:
            # Nessun token presente da rimuovere
            return
            
        status, resp_body = self._dispatch_request(method, url, headers, body_params)
        if status == 200:
            self.findings.append({
                "technique": "Token Removal",
                "severity": "High",
                "url": url,
                "method": method,
                "description": "Endpoint non protetto: Risponde 200 OK anche rimuovendo completamente l'header Authorization."
            })
            print(f"  🔴 [UNPROTECTED DETECTED] Missing Auth su {method} {url} -> 200 OK")

    def _add_padding(self, b64_string):
        return b64_string + "=" * (-len(b64_string) % 4)

    def _test_technique_3_jwt_tampering(self, req):
        url = req.get("full_url", "")
        method = req.get("method", "GET")
        headers = dict(req.get("headers", {}))
        body_params = req.get("body_params")
        
        auth_header = headers.get("Authorization") or headers.get("authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return
            
        token = auth_header.split(" ")[1]
        parts = token.split(".")
        if len(parts) != 3:
            return # Non è un JWT valido
            
        header_b64, payload_b64, signature_b64 = parts
        
        try:
            payload_json = base64.urlsafe_b64decode(self._add_padding(payload_b64)).decode('utf-8')
            payload = json.loads(payload_json)
        except Exception as e:
            return
            
        # Cerca il subject
        subject_keys = ["sub", "user_id", "userId", "id", "account_id"]
        tampered = False
        
        for key in subject_keys:
            if key in payload:
                # Sostituisci con un ID casuale
                original_val = payload[key]
                if isinstance(original_val, int):
                    payload[key] = 99999
                else:
                    payload[key] = str(uuid.uuid4())
                tampered = True
                break
                
        if not tampered:
            return
            
        # Ricostruisci il token manomesso
        tampered_payload_json = json.dumps(payload)
        tampered_payload_b64 = base64.urlsafe_b64encode(tampered_payload_json.encode('utf-8')).decode('utf-8').rstrip("=")
        
        tampered_token = f"{header_b64}.{tampered_payload_b64}.{signature_b64}"
        headers["Authorization"] = f"Bearer {tampered_token}"
        
        status, resp_body = self._dispatch_request(method, url, headers, body_params)
        if status == 200:
            self.findings.append({
                "technique": "JWT Tampering",
                "severity": "Critical",
                "url": url,
                "method": method,
                "description": "Vulnerabilità Critica: L'API non valida la firma del JWT. Accesso consentito modificando il payload del token."
            })
            print(f"  🔥 [CRITICAL VULN] JWT Signature Bypass su {method} {url} -> 200 OK")

    def _print_summary(self):
        print(f"\n📊 --- BOLA Analyzer Summary ---")
        if not self.findings:
            print("  🟢 Nessuna vulnerabilità BOLA/Auth rilevata.")
        else:
            print(f"  🔴 Trovate {len(self.findings)} potenziali vulnerabilità:")
            for f in self.findings:
                print(f"    - [{f['severity']}] {f['technique']}: {f['method']} {f.get('url', f.get('original_url'))}")
        print("-------------------------------\n")
