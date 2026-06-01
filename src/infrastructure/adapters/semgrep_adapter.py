import os
import re
import json
import subprocess
import logging
from typing import List, Dict, Any
from src.domain.interfaces import IScanner
from src.domain.entities import Finding, FindingSource, FindingCategory, Severity, CodeLocation, APIContext
from src.normalization.normalizer import APIEndpointNormalizer

logger = logging.getLogger("SecurityPlatform.SemgrepAdapter")


class SemgrepScannerAdapter(IScanner):
    """
    Adapter statico che scansiona i sorgenti per estrarre
    endpoint API e identificare configurazioni insicure (AST & Semgrep).
    """

    def __init__(self):
        self.endpoints: List[Dict[str, Any]] = []

    def scan(self, target_dir: str) -> List[Finding]:
        logger.info(f"🚀 Esecuzione Semgrep & Heuristic AST Scanner su: {target_dir}")
        self.endpoints = []
        
        # 1. Esecuzione euristica nativa dei sorgenti (Python, Express, Spring Boot)
        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('venv', '.venv', 'node_modules', 'target', 'build')]
            for file in files:
                filepath = os.path.join(root, file)
                rel_path = os.path.relpath(filepath, target_dir)
                
                try:
                    if file.endswith('.py'):
                        self._parse_python_file(filepath, rel_path)
                    elif file.endswith(('.js', '.ts')):
                        self._parse_javascript_file(filepath, rel_path)
                    elif file.endswith('.java'):
                        self._parse_java_file(filepath, rel_path)
                except Exception as e:
                    logger.debug(f"Errore nel parsing euristico di {filepath}: {e}")

        # 2. Integrazione con Semgrep route-detect
        self._run_semgrep_discovery(target_dir)

        # 3. Trasformazione delle definizioni degli endpoint in entità Finding del Dominio
        findings: List[Finding] = []
        deduplicated = self._deduplicate_endpoints()
        
        for ep in deduplicated:
            method = ep["method"]
            path = ep["path"]
            file = ep["file"]
            auth_detected = ep["auth_detected"]
            framework = ep["framework"]
            
            api_ctx = APIContext(
                endpoint=path,
                method=method,
                requires_authentication=auth_detected
            )
            
            # Se la rotta non richiede/rileva autenticazione staticamente, impostiamo un MEDIUM Risk
            # Altrimenti registriamo come INFO (route discovered)
            severity = Severity.INFO if auth_detected else Severity.MEDIUM
            title = "API Endpoint Rilevato" if auth_detected else "Endpoint API non protetto rilevato (Statico)"
            desc = (
                f"Identificato endpoint API [{framework}]: {method} {path} protetto da autenticazione."
                if auth_detected else
                f"L'endpoint API [{framework}]: {method} {path} non sembra richiedere controlli di autenticazione a livello statico."
            )
            
            finding = Finding.create(
                source=FindingSource.SEMGREP,
                category=FindingCategory.API_EXPOSURE if auth_detected else FindingCategory.AUTHENTICATION,
                title=title,
                description=desc,
                severity=severity,
                confidence=0.8,
                rule_id="api-route-discovery" if auth_detected else "unauthenticated-api-route",
                target_identifier=f"{method}:{path}",
                rule_name="API Route Detection",
                location=CodeLocation(file_path=file),
                api=api_ctx,
                correlation_key=f"api:{method}:{APIEndpointNormalizer.normalize_path(path)}",
                raw_data=ep
            )
            findings.append(finding)
            
        logger.info(f"Scansione sorgenti completata. Trovati {len(findings)} endpoint statici.")
        return findings

    def _deduplicate_endpoints(self) -> List[Dict[str, Any]]:
        registry = {}
        for ep in self.endpoints:
            key = f"{ep['method']}:{ep['path']}"
            if key not in registry:
                registry[key] = ep
            else:
                existing = registry[key]
                if ep["auth_detected"]:
                    existing["auth_detected"] = True
                if ep["framework"] not in existing["framework"]:
                    existing["framework"] = f"{existing['framework']}, {ep['framework']}"
        return list(registry.values())

    def _run_semgrep_discovery(self, target_dir: str):
        semgrep_bin = "semgrep"
        if os.path.exists("./.venv/bin/semgrep"):
            semgrep_bin = "./.venv/bin/semgrep"

        ruleset_path = "config/scanner_configs/route-detect.yaml"
        if not os.path.exists(ruleset_path):
            # Fallback path per testing
            ruleset_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../config/scanner_configs/route-detect.yaml"))

        if not os.path.exists(ruleset_path):
            logger.warning("File config/scanner_configs/route-detect.yaml non trovato. Semgrep saltato.")
            return

        output_file = "semgrep_routes_discovered.json"
        cmd = [semgrep_bin, "scan", f"--config={ruleset_path}", "--json", "-o", output_file, target_dir]
        
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if os.path.exists(output_file):
                with open(output_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for issue in data.get("results", []):
                        extra = issue.get("extra", {})
                        message = extra.get("message", "")
                        
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
                                "method": method,
                                "path": path,
                                "file": issue.get("path", ""),
                                "auth_detected": auth_detected,
                                "framework": "python-semgrep"
                            })
                if os.path.exists(output_file):
                    os.remove(output_file)
        except Exception as e:
            logger.debug(f"Esecuzione Semgrep fallita: {e}")

    def _parse_python_file(self, filepath: str, rel_path: str):
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            
        is_fastapi = "fastapi" in content.lower() or "apirouter" in content.lower() or "@app.get" in content or "@router." in content
        is_flask = "flask" in content.lower() or "@app.route" in content or "@blueprint.route" in content
        
        if is_fastapi:
            fastapi_pattern = r'@(?:app|router|api_router)\.(get|post|put|delete|patch)\(\s*[\'"]([^\'"]+)[\'"]'
            for match in re.finditer(fastapi_pattern, content):
                method = match.group(1).upper()
                path = match.group(2)
                
                decorator_end = match.end()
                sub_content = content[decorator_end:decorator_end + 300]
                auth_detected = "Depends(" in sub_content or "verify_" in sub_content or "auth" in sub_content.lower()
                
                self.endpoints.append({
                    "method": method,
                    "path": path,
                    "file": rel_path,
                    "auth_detected": auth_detected,
                    "framework": "fastapi"
                })
                
        if is_flask or (not is_fastapi and "route(" in content):
            flask_pattern = r'@(?:app|blueprint|auth_blueprint)?\.route\(\s*[\'"]([^\'"]+)[\'"](?:\s*,\s*methods\s*=\s*\[([^\]]+)\])?'
            for match in re.finditer(flask_pattern, content):
                path = match.group(1)
                methods_str = match.group(2)
                
                methods = ["GET"]
                if methods_str:
                    methods = [m.strip().strip('\'"') for m in methods_str.split(',')]
                    
                openapi_path = re.sub(r'<[^>:]*:?([^>]+)>', r'{\1}', path)
                
                decorator_end = match.end()
                sub_content = content[decorator_end:decorator_end + 300]
                auth_detected = any(dec in sub_content for dec in ["@login_required", "@jwt_required", "@token_required"])
                
                for method in methods:
                    self.endpoints.append({
                        "method": method.upper(),
                        "path": openapi_path,
                        "file": rel_path,
                        "auth_detected": auth_detected,
                        "framework": "flask"
                    })

    def _parse_javascript_file(self, filepath: str, rel_path: str):
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        express_pattern = r'(?:app|router)\.(get|post|put|delete|patch)\(\s*[\'"]([^\'"]+)[\'"]\s*,'
        for match in re.finditer(express_pattern, content):
            method = match.group(1).upper()
            path = match.group(2)
            openapi_path = re.sub(r':([^/]+)', r'{\1}', path)
            
            sub_content = content[match.end():match.end() + 150]
            auth_detected = any(term in sub_content for term in ["auth", "verify", "protect", "jwt"])
            
            self.endpoints.append({
                "method": method,
                "path": openapi_path,
                "file": rel_path,
                "auth_detected": auth_detected,
                "framework": "express"
            })

    def _parse_java_file(self, filepath: str, rel_path: str):
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        spring_pattern = r'@(GetMapping|PostMapping|PutMapping|DeleteMapping)\s*\(\s*(?:value\s*=\s*)?[\'"]([^\'"]+)[\'"]'
        for match in re.finditer(spring_pattern, content):
            ann = match.group(1)
            path = match.group(2)
            
            method = "GET"
            if "Post" in ann: method = "POST"
            elif "Put" in ann: method = "PUT"
            elif "Delete" in ann: method = "DELETE"
            
            auth_detected = any(term in content for term in ["@PreAuthorize", "SecurityContext", "auth"])
            
            self.endpoints.append({
                "method": method,
                "path": path,
                "file": rel_path,
                "auth_detected": auth_detected,
                "framework": "springboot"
            })
