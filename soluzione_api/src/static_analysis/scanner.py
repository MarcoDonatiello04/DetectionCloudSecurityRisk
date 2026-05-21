import os
import re
import json
import subprocess
from typing import List, Dict, Any
from src.normalization.normalizer import APIEndpointNormalizer
from src.interfaces.scanner import ScannerInterface

class StaticAPIScanner(ScannerInterface):
    """
    Scanner statico polimorfico in grado di scansionare file sorgenti per estrarre
    endpoint API, metodi HTTP, middleware di autenticazione e parametri per i framework:
    FastAPI, Flask, Express.js, Spring Boot.
    Integra l'uso diretto di Semgrep con regole custom (route-detect.yaml).
    """
    def __init__(self, target_dir: str = "."):
        self.target_dir = target_dir
        self.endpoints: List[Dict[str, Any]] = []

    def scan(self, target_dir: str = None) -> List[Dict[str, Any]]:
        if target_dir is not None:
            self.target_dir = target_dir
        self.endpoints = []
        
        # 1. Esegui la Discovery Nativa tramite Regex/AST (Flask, FastAPI, Express, Spring Boot)
        for root, dirs, files in os.walk(self.target_dir):
            # Escludiamo directory di sistema o virtualenv
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('venv', '.venv', 'node_modules', 'target', 'build', 'dist')]
            for file in files:
                if file == "scanner.py":
                    continue
                filepath = os.path.join(root, file)
                rel_path = os.path.relpath(filepath, self.target_dir)
                
                if file.endswith('.py'):
                    self._parse_python_file(filepath, rel_path)
                elif file.endswith(('.js', '.ts')):
                    self._parse_javascript_file(filepath, rel_path)
                elif file.endswith('.java'):
                    self._parse_java_file(filepath, rel_path)
                    
        # 2. Integra i risultati dell'estrazione di Semgrep (route-detect)
        self._run_semgrep_discovery()
        
        # 3. Deduplica gli endpoint trovati
        return self._deduplicate_endpoints()

    def _deduplicate_endpoints(self) -> List[Dict[str, Any]]:
        registry = {}
        for ep in self.endpoints:
            key = f"{ep['method']}:{ep['path']}"
            if key not in registry:
                registry[key] = {
                    "source": "static",
                    "method": ep["method"],
                    "path": ep["path"],
                    "file": ep["file"],
                    "auth_detected": ep["auth_detected"],
                    "frameworks": [ep["framework"]],
                    "route_parameters": list(ep.get("route_parameters", []))
                }
            else:
                entry = registry[key]
                if ep["framework"] not in entry["frameworks"]:
                    entry["frameworks"].append(ep["framework"])
                if ep["auth_detected"]:
                    entry["auth_detected"] = True
                for p in ep.get("route_parameters", []):
                    if p not in entry["route_parameters"]:
                        entry["route_parameters"].append(p)
                        
        for entry in registry.values():
            entry["framework"] = ", ".join(entry["frameworks"])
            
        return list(registry.values())

    def _run_semgrep_discovery(self):
        """Esegue Semgrep con la regola route-detect.yaml per completare la discovery statica."""
        print("🔍 Esecuzione Semgrep Route Extraction (route-detect.yaml)...")
        semgrep_bin = "semgrep"
        if os.path.exists("./.venv/bin/semgrep"):
            semgrep_bin = "./.venv/bin/semgrep"

        ruleset_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../config/scanner_configs/route-detect.yaml"))
        if not os.path.exists(ruleset_path):
            ruleset_path = "config/scanner_configs/route-detect.yaml"

        if not os.path.exists(ruleset_path):
            print("⚠️ File route-detect.yaml non trovato. Salto Semgrep Route Discovery.")
            return

        output_file = "semgrep_routes_discovered.json"
        cmd = [semgrep_bin, "scan", f"--config={ruleset_path}", "--json", "-o", output_file, self.target_dir]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            if os.path.exists(output_file):
                with open(output_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for issue in data.get("results", []):
                        extra = issue.get("extra", {})
                        message = extra.get("message", "")
                        
                        # Estraiamo la rotta dal messaggio o metadati
                        route_match = re.search(r'(?:Route|Secured Route)\s+Detected:\s*[\'"]?([^\'"\s,]+)[\'"]?', message)
                        if route_match:
                            path = route_match.group(1)
                            path = APIEndpointNormalizer.normalize_path(path)
                            
                            rule_id = issue.get("check_id", "")
                            method = "GET"
                            lines = extra.get("lines", "").lower()
                            if "post" in rule_id.lower() or "post" in lines:
                                method = "POST"
                            elif "put" in rule_id.lower() or "put" in lines:
                                method = "PUT"
                            elif "delete" in rule_id.lower() or "delete" in lines:
                                method = "DELETE"
                                
                            auth_detected = "secured" in rule_id.lower()
                            
                            self.endpoints.append({
                                "source": "static",
                                "method": method,
                                "path": path,
                                "file": issue.get("path", ""),
                                "auth_detected": auth_detected,
                                "framework": "python-semgrep",
                                "route_parameters": re.findall(r'\{([^}]+)\}', path)
                            })
                # Rimuove il file temporaneo
                if os.path.exists(output_file):
                    os.remove(output_file)
        except Exception as e:
            print(f"⚠️ Semgrep Route Discovery fallita o non disponibile: {e}")

    def _parse_python_file(self, filepath: str, rel_path: str):
        """Parsa file Python cercando rotte Flask o FastAPI."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Verifica se ci sono indicazioni di FastAPI o Flask
            is_fastapi = "fastapi" in content.lower() or "apirouter" in content.lower()
            is_flask = "flask" in content.lower() or "blueprint" in content.lower()
            
            # Se non sono esplicitamente importati ma assomigliano ad essi:
            if not is_fastapi and not is_flask:
                if "@app.get" in content or "@router." in content or "Depends(" in content:
                    is_fastapi = True
                elif "route(" in content or "Blueprint(" in content:
                    is_flask = True

            # Caso FastAPI: @app.get("/path"), @router.post("/path"), etc.
            if is_fastapi:
                # Cerca decoratori tipo @app.get("/...") o @router.post("/...")
                fastapi_pattern = r'@(?:app|router|api_router)\.(get|post|put|delete|patch|options|head)\(\s*[\'"]([^\'"]+)[\'"]'
                matches = re.finditer(fastapi_pattern, content)
                for match in matches:
                    method = match.group(1).upper()
                    path = match.group(2)
                    
                    # Estrazione dei parametri del path (es: {user_id} o {id})
                    route_params = re.findall(r'\{([^}]+)\}', path)
                    
                    # Verifica Autenticazione (e.g. Depends(verify_token) o Depends(get_current_user))
                    # Cerchiamo la firma della funzione subito sotto il decoratore
                    decorator_end = match.end()
                    sub_content = content[decorator_end:decorator_end + 300]
                    auth_detected = "Depends(" in sub_content or "verify_" in sub_content or "auth" in sub_content.lower()

                    self.endpoints.append({
                        "source": "static",
                        "method": method,
                        "path": path,
                        "file": rel_path,
                        "auth_detected": auth_detected,
                        "framework": "fastapi",
                        "route_parameters": route_params
                    })

            # Caso Flask: @app.route("/path", methods=['GET', 'POST']) o @blueprint.route(...)
            if is_flask or not is_fastapi: # Fallback su Flask
                flask_pattern = r'@(?:app|blueprint|auth_blueprint)?\.route\(\s*[\'"]([^\'"]+)[\'"](?:\s*,\s*methods\s*=\s*\[([^\]]+)\])?'
                matches = re.finditer(flask_pattern, content)
                for match in matches:
                    path = match.group(1)
                    methods_str = match.group(2)
                    
                    methods = ["GET"] # Default Flask method
                    if methods_str:
                        methods = [m.strip().strip('\'"') for m in methods_str.split(',')]
                        
                    # Estrazione parametri (es: <int:user_id> o <id>)
                    route_params = re.findall(r'<[^>:]*:?([^>]+)>', path)
                    # Convertiamo il path Flask style (<int:id>) in OpenAPI style ({id})
                    openapi_path = re.sub(r'<[^>:]*:?([^>]+)>', r'{\1}', path)

                    # Verifica Autenticazione (es: @login_required, @jwt_required, @token_required)
                    decorator_end = match.end()
                    sub_content = content[decorator_end:decorator_end + 300]
                    auth_detected = any(decorator in sub_content for decorator in [
                        "@login_required", "@jwt_required", "@token_required", "@requires_auth", "@auth"
                    ]) or "current_user" in sub_content

                    for method in methods:
                        self.endpoints.append({
                            "source": "static",
                            "method": method.upper(),
                            "path": openapi_path,
                            "file": rel_path,
                            "auth_detected": auth_detected,
                            "framework": "flask",
                            "route_parameters": route_params
                        })
                        
            # Heuristic per AWS Lambda / Path conditional routing
            # Se vediamo if path.startswith() o path ==
            if "path = event.get" in content or "event.get('path'" in content:
                lambda_matches = re.finditer(r'path\.startswith\(\s*[\'"]([^\'"]+)[\'"]\s*\)', content)
                for match in lambda_matches:
                    m_path = match.group(1)
                    if m_path.endswith('/') and m_path != '/':
                        m_path = f"{m_path}{{id}}"
                    self.endpoints.append({
                        "source": "static",
                        "method": "GET", # Assumiamo GET come default heuristico
                        "path": m_path,
                        "file": rel_path,
                        "auth_detected": "auth" in content.lower(),
                        "framework": "aws-lambda",
                        "route_parameters": ["id"] if "{id}" in m_path else []
                    })
                
                # Check for equality path == '/...'
                lambda_eq_matches = re.finditer(r'path\s*==\s*[\'"]([^\'"]+)[\'"]', content)
                for match in lambda_eq_matches:
                    m_path = match.group(1)
                    self.endpoints.append({
                        "source": "static",
                        "method": "GET",
                        "path": m_path,
                        "file": rel_path,
                        "auth_detected": "auth" in content.lower(),
                        "framework": "aws-lambda",
                        "route_parameters": []
                    })

        except Exception as e:
            print(f"⚠️ Errore nel parsing del file Python {filepath}: {e}")

    def _parse_javascript_file(self, filepath: str, rel_path: str):
        """Parsa file JS/TS cercando rotte Express.js."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()

            # Express pattern: app.get('/path', middleware, function) o router.post(...)
            express_pattern = r'(?:app|router)\.(get|post|put|delete|patch|use)\(\s*[\'"]([^\'"]+)[\'"]\s*,'
            matches = re.finditer(express_pattern, content)
            for match in matches:
                method = match.group(1).upper()
                path = match.group(2)
                
                if method == "USE":
                    # Spesso app.use('/api', ...) serve come prefisso, saltiamo o lo mappiamo come jolly
                    continue
                    
                # Estrazione parametri (es: /users/:id ➡️ /users/{id})
                route_params = re.findall(r':([^/]+)', path)
                openapi_path = re.sub(r':([^/]+)', r'{\1}', path)

                # Verifica Autenticazione
                # Controlla se la riga contiene middleware tipici (es. isAuthenticated, verifyToken, protect, passport)
                match_end = match.end()
                sub_content = content[match_end:match_end + 150]
                auth_detected = any(term in sub_content for term in [
                    "auth", "verify", "passport", "protect", "login", "session", "jwt"
                ])

                self.endpoints.append({
                    "source": "static",
                    "method": method,
                    "path": openapi_path,
                    "file": rel_path,
                    "auth_detected": auth_detected,
                    "framework": "express",
                    "route_parameters": route_params
                })
        except Exception as e:
            print(f"⚠️ Errore nel parsing del file JS/TS {filepath}: {e}")

    def _parse_java_file(self, filepath: str, rel_path: str):
        """Parsa file Java cercando annotazioni Spring Boot."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()

            # Spring Mapping Annotations: @GetMapping("/path"), @PostMapping(value = "/path"), etc.
            spring_pattern = r'@(GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)\s*\(\s*(?:value\s*=\s*)?[\'"]([^\'"]+)[\'"]'
            matches = re.finditer(spring_pattern, content)
            for match in matches:
                annotation = match.group(1)
                path = match.group(2)
                
                # Mapping method
                method = "GET"
                if "Post" in annotation:
                    method = "POST"
                elif "Put" in annotation:
                    method = "PUT"
                elif "Delete" in annotation:
                    method = "DELETE"
                elif "Request" in annotation:
                    # RequestMapping senza specificare method è solitamente GET o copre tutto
                    method = "GET"

                # Spring path parameters: /users/{id}
                route_params = re.findall(r'\{([^}]+)\}', path)

                # Verifica Autenticazione (es. @PreAuthorize, SecurityContext, Principal)
                auth_detected = any(term in content for term in [
                    "@PreAuthorize", "@Secured", "Principal ", "SecurityContext", "auth", "OAuth2"
                ])

                self.endpoints.append({
                    "source": "static",
                    "method": method,
                    "path": path,
                    "file": rel_path,
                    "auth_detected": auth_detected,
                    "framework": "springboot",
                    "route_parameters": route_params
                })
        except Exception as e:
            print(f"⚠️ Errore nel parsing del file Java {filepath}: {e}")

if __name__ == "__main__":
    import json
    scanner = StaticAPIScanner(".")
    res = scanner.scan()
    print(json.dumps(res, indent=2))
