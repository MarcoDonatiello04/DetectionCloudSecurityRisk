import json
import re
import uuid
import base64
import os
import requests
import urllib3

# Suppress urllib3 SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from src.interfaces.analyzer import AnalyzerInterface

class BOLAAnalyzer(AnalyzerInterface):
    def __init__(self, traffic_file="captured_requests.json"):
        self.traffic_file = traffic_file
        self.findings = []
        
        # Regex per identificare ID numerici e UUID nell'URL (relative path)
        self.numeric_id_regex = re.compile(r'/(\d+)(/|$)')
        self.uuid_regex = re.compile(r'/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(/|$)')
        
    def run_analysis(self):
        print(f"\n🕵️‍♂️ [BOLA Analyzer] Avvio analisi BOLA sul traffico catturato: {self.traffic_file}")
        
        # 1. Controlla che raw_traffic.json esista
        if not os.path.exists(self.traffic_file):
            print(f"⚠️ File di traffico '{self.traffic_file}' non trovato.")
            return []
            
        try:
            with open(self.traffic_file, 'r', encoding='utf-8') as f:
                traffic = json.load(f)
        except Exception as e:
            print(f"⚠️ Errore lettura file traffico: {e}")
            return []
            
        # Controlla che non sia vuoto
        if not traffic:
            print("⚠️ Nessun traffico da analizzare (il file è vuoto).")
            return []
            
        # 2. Stampa quante richieste sono state caricate
        print(f"✅ Traffico reale intercettato da Mitmproxy caricato con successo: {len(traffic)} richieste.")
        
        # Filtraggio richieste di sistema
        SYSTEM_PATHS = [
            "/robots.txt",
            "/sitemap.xml", 
            "/favicon.ico",
            "/.well-known/",
            "/crossdomain.xml"
        ]
        
        filtered_traffic = []
        skipped_system_count = 0
        for req in traffic:
            path = req.get("path", "")
            if any(sp in path for sp in SYSTEM_PATHS):
                skipped_system_count += 1
            else:
                filtered_traffic.append(req)
        
        if skipped_system_count > 0:
            print(f"⏭️ Skippati {skipped_system_count} path di sistema (robots.txt, sitemap.xml...)")
            
        # Deduplicazione richieste
        unique_traffic = []
        seen_endpoints = set()
        for req in filtered_traffic:
            method = req.get("method", "GET").upper()
            path = req.get("path", "")
            key = (method, path)
            if key not in seen_endpoints:
                seen_endpoints.add(key)
                unique_traffic.append(req)
                
        print(f"📦 Caricate {len(traffic)} richieste → {len(unique_traffic)} endpoint unici da testare")
        
        # 3. Per ogni richiesta caricata stampa: method + path + status_code
        print("📋 Richieste caricate per il test:")
        for idx, req in enumerate(unique_traffic, 1):
            method = req.get("method", "GET")
            path = req.get("path", "")
            status_code = req.get("status_code", "N/D")
            print(f"   [{idx}] {method} {path} ➡️ Status Code originale: {status_code}")
            
        # Esecuzione dei test
        for req in unique_traffic:
            path = req.get("path", "")
            method = req.get("method", "GET")
            # Evita endpoint chiaramente di login o senza percorsi utili
            if "login" in path.lower() or "auth" in path.lower():
                print(f"\n  ⏭️  Skipping {method} {path} (Auth/Login endpoint)")
                continue
                
            print(f"\n🔍 Analisi BOLA in corso su: {method} {path}")
            self._test_technique_1_id_tampering(req)
            self._test_technique_2_token_removal(req)
            self._test_technique_3_jwt_tampering(req)
            
        self._print_summary()
        return self.findings
        
    def _dispatch_request(self, method, url, headers, data=None):
        try:
            # Rimappiamo host.docker.internal o localstack a localhost se eseguiamo dall'host
            if "host.docker.internal" in url:
                url = url.replace("host.docker.internal", "localhost")
            if "localstack" in url:
                url = url.replace("localstack-main", "localhost").replace("localstack", "localhost")

            clean_headers = {k: v for k, v in headers.items() 
                            if k.lower() not in ['host', 'content-length']}
            
            # Se data è un dizionario (body_params), usiamo json=data per inviarlo come JSON
            # Se è una stringa o byte (request_body), usiamo data=data
            if data and isinstance(data, dict):
                response = requests.request(
                    method=method,
                    url=url,
                    headers=clean_headers,
                    json=data,
                    verify=False,
                    timeout=3
                )
            else:
                response = requests.request(
                    method=method,
                    url=url,
                    headers=clean_headers,
                    data=data,
                    verify=False,
                    timeout=3
                )
                
            status_code = response.status_code
            body = response.content
            print(f"      [DEBUG] {method} {url} → {status_code} | body_len={len(body)}")
            return status_code, body
        except Exception as e:
            print(f"      [DEBUG] {method} {url} → ERRORE: {e}")
            return 0, b""

    def _test_technique_1_id_tampering(self, req):
        path = req.get("path", "")
        url = req.get("full_url", "")
        method = req.get("method", "GET")
        headers = req.get("headers", {})
        body_params = req.get("request_body", req.get("body_params"))
        
        num_matches = list(self.numeric_id_regex.finditer(path))
        uuid_matches = list(self.uuid_regex.finditer(path))
        
        tampered_urls = []
        
        if num_matches:
            for match in num_matches:
                original_id = match.group(1)
                idx = int(original_id)
                # Test ID+1, ID-1, ID+100
                for tampered_id in [idx + 1, idx - 1, idx + 100]:
                    if tampered_id < 0:
                        continue
                    new_path = path[:match.start(1)] + str(tampered_id) + path[match.end(1):]
                    if path in url:
                        parts = url.rsplit(path, 1)
                        new_url = new_path.join(parts)
                    else:
                        new_url = url.replace(path, new_path)
                    tampered_urls.append((new_url, "Numeric ID Tampering"))
                    
        elif uuid_matches:
            for match in uuid_matches:
                new_uuid = str(uuid.uuid4())
                new_path = path[:match.start(1)] + new_uuid + path[match.end(1):]
                if path in url:
                    parts = url.rsplit(path, 1)
                    new_url = new_path.join(parts)
                else:
                    new_url = url.replace(path, new_path)
                tampered_urls.append((new_url, "UUID Tampering"))
        
        if not tampered_urls:
            print("   [ID Tampering] ℹ️ Nessun ID numerico o UUID trovato nel path.")
            return

        print(f"   [ID Tampering] Test in corso su URL originale: {url}")
        for t_url, t_type in tampered_urls:
            print(f"      ➡️ Test con URL generata: {t_url}")
            status, resp_body = self._dispatch_request(method, t_url, headers, body_params)
            print(f"      ⬅️ Ricevuto Status Code: {status}")
            
            if status == 200 and len(resp_body) > 0:
                self.findings.append({
                    "technique": "ID Tampering (BOLA)",
                    "severity": "High",
                    "original_url": url,
                    "tampered_url": t_url,
                    "method": method,
                    "description": f"Possibile BOLA: Accesso riuscito con {t_type} restituendo 200 OK con corpo non vuoto."
                })
                print(f"      🔴 [VULNERABILITÀ RILEVATA] {t_type} su {method} {t_url} -> Stato 200 con body non vuoto.")
            else:
                reason = "Stato diverso da 200 o corpo vuoto" if status != 200 else "Corpo della risposta vuoto"
                print(f"      🟢 [NESSUNA VULNERABILITÀ] {t_type} su {method} {t_url} -> Stato {status} ({reason}).")

        def _test_technique_2_token_removal(self, req):
            url = req.get("full_url", "")
            method = req.get("method", "GET")
            headers = dict(req.get("headers", {}))
            body_params = req.get("request_body", req.get("body_params"))
            
            auth_found = False
            if "Authorization" in headers:
                del headers["Authorization"]
                auth_found = True
            elif "authorization" in headers:
                del headers["authorization"]
                auth_found = True
                
            if not auth_found:
                print("   [Token Removal] ℹ️ Nessun header Authorization presente nella richiesta originale.")
                return
                
            print(f"   [Token Removal] Test in corso su URL originale (senza token): {url}")
            print(f"      ➡️ Test con URL generata: {url} (rimosso header Authorization)")
            status, resp_body = self._dispatch_request(method, url, headers, body_params)
            print(f"      ⬅️ Ricevuto Status Code: {status}")
            
            if status == 200:
                self.findings.append({
                    "technique": "Token Removal",
                    "severity": "High",
                    "url": url,
                    "method": method,
                    "description": "Endpoint non protetto: Risponde 200 OK anche rimuovendo completamente l'header Authorization."
                })
                print(f"      🔴 [VULNERABILITÀ RILEVATA] Token Removal su {method} {url} -> Risponde 200 OK anche senza autenticazione.")
            else:
                print(f"      🟢 [NESSUNA VULNERABILITÀ] Token Removal su {method} {url} -> Risponde correttamente {status} (Richiesta bloccata).")

        def _add_padding(self, b64_string):
            return b64_string + "=" * (-len(b64_string) % 4)

        def _test_technique_3_jwt_tampering(self, req):
            url = req.get("full_url", "")
            method = req.get("method", "GET")
            headers = dict(req.get("headers", {}))
            body_params = req.get("request_body", req.get("body_params"))
            
            auth_header = headers.get("Authorization") or headers.get("authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                print("   [JWT Tampering] ℹ️ Nessun token Bearer JWT presente per questo endpoint.")
                return
                
            token = auth_header.split(" ")[1]
            parts = token.split(".")
            if len(parts) != 3:
                print("   [JWT Tampering] ℹ️ L'header Authorization contiene un token non conforme al formato JWT (3 parti).")
                return
                
            header_b64, payload_b64, signature_b64 = parts
            
            try:
                payload_json = base64.urlsafe_b64decode(self._add_padding(payload_b64)).decode('utf-8')
                payload = json.loads(payload_json)
            except Exception as e:
                print(f"   [JWT Tampering] ⚠️ Impossibile decodificare il payload JWT: {e}")
                return
                
            subject_keys = ["sub", "user_id", "userId", "id", "account_id"]
            tampered = False
            original_val = None
            tampered_val = None
            
            for key in subject_keys:
                if key in payload:
                    original_val = payload[key]
                    if isinstance(original_val, int):
                        payload[key] = 99999
                    else:
                        payload[key] = str(uuid.uuid4())
                    tampered_val = payload[key]
                    tampered = True
                    break
                    
            if not tampered:
                print(f"   [JWT Tampering] ℹ️ Nessun subject claim identificativo ({', '.join(subject_keys)}) trovato nel payload JWT.")
                return
                
            tampered_payload_json = json.dumps(payload)
            tampered_payload_b64 = base64.urlsafe_b64encode(tampered_payload_json.encode('utf-8')).decode('utf-8').rstrip("=")
            
            tampered_token = f"{header_b64}.{tampered_payload_b64}.{signature_b64}"
            headers["Authorization"] = f"Bearer {tampered_token}"
            
            print(f"   [JWT Tampering] Test in corso su URL originale: {url}")
            print(f"      ➡️ Test con JWT manomesso (sub modificato: {original_val} ➡️ {tampered_val})")
            status, resp_body = self._dispatch_request(method, url, headers, body_params)
            print(f"      ⬅️ Ricevuto Status Code: {status}")
            
            if status == 200:
                self.findings.append({
                    "technique": "JWT Tampering",
                    "severity": "Critical",
                    "url": url,
                    "method": method,
                    "description": "Vulnerabilità Critica: L'API non valida la firma del JWT. Accesso consentito modificando il payload del token."
                })
                print(f"      🔴 [VULNERABILITÀ RILEVATA] JWT Signature Bypass su {method} {url} -> Risponde 200 OK anche con firma non valida/manomessa.")
            else:
                print(f"      🟢 [NESSUNA VULNERABILITÀ] JWT Signature Bypass su {method} {url} -> Risponde correttamente {status} (Firma/Token non valido).")

    def _test_technique_2_token_removal(self, req):
        url = req.get("full_url", "")
        method = req.get("method", "GET")
        headers = dict(req.get("headers", {}))
        body_params = req.get("request_body", req.get("body_params"))
        
        auth_found = False
        if "Authorization" in headers:
            del headers["Authorization"]
            auth_found = True
        elif "authorization" in headers:
            del headers["authorization"]
            auth_found = True
            
        if not auth_found:
            print("   [Token Removal] ℹ️ Nessun header Authorization presente nella richiesta originale.")
            return
            
        print(f"   [Token Removal] Test in corso su URL originale (senza token): {url}")
        print(f"      ➡️ Test con URL generata: {url} (rimosso header Authorization)")
        status, resp_body = self._dispatch_request(method, url, headers, body_params)
        print(f"      ⬅️ Ricevuto Status Code: {status}")
        
        if status == 200:
            self.findings.append({
                "technique": "Token Removal",
                "severity": "High",
                "url": url,
                "method": method,
                "description": "Endpoint non protetto: Risponde 200 OK anche rimuovendo completamente l'header Authorization."
            })
            print(f"      🔴 [VULNERABILITÀ RILEVATA] Token Removal su {method} {url} -> Risponde 200 OK anche senza autenticazione.")
        else:
            print(f"      🟢 [NESSUNA VULNERABILITÀ] Token Removal su {method} {url} -> Risponde correttamente {status} (Richiesta bloccata).")

    def _add_padding(self, b64_string):
        return b64_string + "=" * (-len(b64_string) % 4)

    def _test_technique_3_jwt_tampering(self, req):
        url = req.get("full_url", "")
        method = req.get("method", "GET")
        headers = dict(req.get("headers", {}))
        body_params = req.get("request_body", req.get("body_params"))
        
        auth_header = headers.get("Authorization") or headers.get("authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            print("   [JWT Tampering] ℹ️ Nessun token Bearer JWT presente per questo endpoint.")
            return
            
        token = auth_header.split(" ")[1]
        parts = token.split(".")
        if len(parts) != 3:
            print("   [JWT Tampering] ℹ️ L'header Authorization contiene un token non conforme al formato JWT (3 parti).")
            return
            
        header_b64, payload_b64, signature_b64 = parts
        
        try:
            payload_json = base64.urlsafe_b64decode(self._add_padding(payload_b64)).decode('utf-8')
            payload = json.loads(payload_json)
        except Exception as e:
            print(f"   [JWT Tampering] ⚠️ Impossibile decodificare il payload JWT: {e}")
            return
            
        subject_keys = ["sub", "user_id", "userId", "id", "account_id"]
        tampered = False
        original_val = None
        tampered_val = None
        
        for key in subject_keys:
            if key in payload:
                original_val = payload[key]
                if isinstance(original_val, int):
                    payload[key] = 99999
                else:
                    payload[key] = str(uuid.uuid4())
                tampered_val = payload[key]
                tampered = True
                break
                
        if not tampered:
            print(f"   [JWT Tampering] ℹ️ Nessun subject claim identificativo ({', '.join(subject_keys)}) trovato nel payload JWT.")
            return
            
        tampered_payload_json = json.dumps(payload)
        tampered_payload_b64 = base64.urlsafe_b64encode(tampered_payload_json.encode('utf-8')).decode('utf-8').rstrip("=")
        
        tampered_token = f"{header_b64}.{tampered_payload_b64}.{signature_b64}"
        headers["Authorization"] = f"Bearer {tampered_token}"
        
        print(f"   [JWT Tampering] Test in corso su URL originale: {url}")
        print(f"      ➡️ Test con JWT manomesso (sub modificato: {original_val} ➡️ {tampered_val})")
        status, resp_body = self._dispatch_request(method, url, headers, body_params)
        print(f"      ⬅️ Ricevuto Status Code: {status}")
        
        if status == 200:
            self.findings.append({
                "technique": "JWT Tampering",
                "severity": "Critical",
                "url": url,
                "method": method,
                "description": "Vulnerabilità Critica: L'API non valida la firma del JWT. Accesso consentito modificando il payload del token."
            })
            print(f"      🔴 [VULNERABILITÀ RILEVATA] JWT Signature Bypass su {method} {url} -> Risponde 200 OK anche con firma non valida/manomessa.")
        else:
            print(f"      🟢 [NESSUNA VULNERABILITÀ] JWT Signature Bypass su {method} {url} -> Risponde correttamente {status} (Firma/Token non valido).")

    def _print_summary(self):
        print(f"\n📊 --- BOLA Analyzer Summary ---")
        if not self.findings:
            print("  🟢 Nessuna vulnerabilità BOLA/Auth rilevata.")
        else:
            # Raggruppiamo i findings per (technique, url, method, severity)
            grouped_findings = {}
            for f in self.findings:
                tech = f.get("technique", "")
                url = f.get("url") or f.get("original_url", "")
                method = f.get("method", "GET")
                severity = f.get("severity", "High")
                key = (tech, url, method, severity)
                if key not in grouped_findings:
                    grouped_findings[key] = 0
                grouped_findings[key] += 1
            
            print(f"  🔴 Trovate {len(grouped_findings)} potenziali vulnerabilità:")
            for (tech, url, method, severity), count in grouped_findings.items():
                print(f"    - [{severity}] {tech}: {method} {url} (rilevato {count} volte, mostrato 1)")
        print("-------------------------------\n")

if __name__ == "__main__":
    import sys
    
    traffic_path = "captured_requests.json"
    if len(sys.argv) > 1:
        traffic_path = sys.argv[1]
        
    analyzer = BOLAAnalyzer(traffic_path)
    analyzer.run_analysis()
