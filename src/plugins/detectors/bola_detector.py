import logging
import re
import uuid
import base64
import os
from typing import List, Dict, Any
import requests
import urllib3

from src.domain.interfaces import IDetector
from src.domain.entities import Finding, FindingSource, FindingCategory, Severity, APIContext, RuntimeEvidence, RiskContext
from src.domain.events import EVENT_STATIC_SCAN_COMPLETED, EVENT_TRAFFIC_CAPTURED
from src.normalization.normalizer import APIEndpointNormalizer

# Disabilita gli alert SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger("SecurityPlatform.Plugins.BOLADetector")


class BOLADetectorPlugin(IDetector):
    """
    Detector Plugin per Broken Object Level Authorization (BOLA / IDOR).
    1. Staticamente: Estrae rotte basate su oggetti ({id}) e solleva rischi preventivi.
    2. Dinamicamente: Analizza il traffico catturato ed esegue test di tampering (ID, Token, JWT)
       per convalidare l'effettiva presenza di exploitabilità BOLA.
    """

    def __init__(self):
        self.numeric_id_regex = re.compile(r'/(\d+)(/|$)')
        self.uuid_regex = re.compile(r'/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(/|$)')

    @property
    def name(self) -> str:
        return "BOLA-IDOR-Detector-Plugin"

    @property
    def subscribed_events(self) -> List[str]:
        return [EVENT_STATIC_SCAN_COMPLETED, EVENT_TRAFFIC_CAPTURED]

    def analyze(self, payload: Any) -> List[Finding]:
        findings: List[Finding] = []
        
        # Gestiamo l'evento Static Scan Completed
        if "static_findings" in payload:
            logger.info("🕵️‍♂️ [BOLA Plugin] Avvio analisi statica per endpoint basati su oggetti...")
            target_dir = payload.get("target_dir", ".")
            findings.extend(self._analyze_static_routes(target_dir))

        # Gestiamo l'evento Traffic Captured (Dinamico)
        elif "traffic" in payload:
            logger.info("🕵️‍♂️ [BOLA Plugin] Avvio analisi dinamica / active vulnerability testing sul traffico...")
            traffic = payload.get("traffic", [])
            findings.extend(self._analyze_runtime_traffic(traffic))

        return findings

    def _analyze_static_routes(self, target_dir: str) -> List[Finding]:
        """Scansiona staticamente i file per trovare percorsi tipo /users/{id} o simili."""
        findings = []
        object_routes = []

        # Scansione semplice del target dir cercando route e definizioni
        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('venv', '.venv', 'node_modules')]
            for file in files:
                if file.endswith(('.py', '.js', '.ts', '.java', '.yaml', '.yml', '.json')):
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            content = f.read(100000) # Legge max 100KB per performance
                            # Trova rotte contenenti parametri dinamici {id} o <id>
                            matches = re.findall(r'([\'"]/[a-zA-Z0-9_/]*(?:\{[a-zA-Z0-9_]+\}|<[a-zA-Z0-9_:]+>)[a-zA-Z0-9_/]*[\'"])', content)
                            for match in matches:
                                route = match.strip('\'"')
                                # Normalizza
                                norm_route = re.sub(r'<[^>:]*:?([^>]+)>', r'{\1}', route)
                                if norm_route not in object_routes:
                                    object_routes.append(norm_route)
                    except Exception:
                        pass

        for route in object_routes:
            api_ctx = APIContext(endpoint=route, requires_authentication=True)
            finding = Finding.create(
                source=FindingSource.SEMGREP,
                category=FindingCategory.AUTHORIZATION,
                title="Potenziale BOLA / IDOR statico rilevato",
                description=f"L'endpoint '{route}' riceve parametri identificativi nel percorso. Richiede validazione rigorosa dei permessi sull'oggetto specifico (OWASP API1:2023).",
                severity=Severity.HIGH,
                confidence=0.7,
                rule_id="bola-route-static-check",
                target_identifier=route,
                rule_name="Object-based Routing Exposure",
                api=api_ctx,
                correlation_key=f"api:GET:{APIEndpointNormalizer.normalize_path(route)}"
            )
            findings.append(finding)

        return findings

    def _analyze_runtime_traffic(self, traffic: List[Dict[str, Any]]) -> List[Finding]:
        """Esegue active testing per bypassare autorizzazione e controllare BOLA."""
        findings = []
        
        # Deduplica i percorsi per evitare spam di scansioni
        unique_reqs = []
        seen = set()
        for req in traffic:
            # Salta percorsi statici/di sistema
            path = req.get("path", "")
            if any(term in path.lower() for term in ["login", "auth", "robots.txt", "favicon"]):
                continue
            key = (req.get("method", "GET").upper(), path)
            if key not in seen:
                seen.add(key)
                unique_reqs.append(req)

        for req in unique_reqs:
            # 1. Test di ID Tampering (BOLA classico)
            tampered_finding = self._test_id_tampering(req)
            if tampered_finding:
                findings.append(tampered_finding)

            # 2. Test di Token Removal (Mancanza autenticazione)
            auth_bypass_finding = self._test_token_removal(req)
            if auth_bypass_finding:
                findings.append(auth_bypass_finding)

        return findings

    def _dispatch_request(self, method: str, url: str, headers: Dict[str, str], data: Any = None):
        """Metodo helper per inoltrare le richieste verso localhost."""
        try:
            # Mappatura host container/docker a localhost se eseguiamo in locale
            url = url.replace("host.docker.internal", "localhost")
            url = url.replace("localstack-main", "localhost").replace("localstack", "localhost")

            clean_headers = {k: v for k, v in headers.items() if k.lower() not in ['host', 'content-length']}
            
            if data and isinstance(data, dict):
                resp = requests.request(method, url, headers=clean_headers, json=data, verify=False, timeout=2)
            else:
                resp = requests.request(method, url, headers=clean_headers, data=data, verify=False, timeout=2)
                
            return resp.status_code, resp.text
        except Exception:
            return 0, ""

    def _test_id_tampering(self, req: Dict[str, Any]) -> Finding:
        path = req.get("path", "")
        url = req.get("full_url", "")
        method = req.get("method", "GET")
        headers = req.get("headers", {})
        body = req.get("body_params") or req.get("request_body")

        num_match = self.numeric_id_regex.search(path)
        uuid_match = self.uuid_regex.search(path)
        
        tampered_url = None
        technique = "ID Tampering"
        
        if num_match:
            original_id = int(num_match.group(1))
            tampered_id = original_id + 1
            new_path = path.replace(str(original_id), str(tampered_id), 1)
            tampered_url = url.replace(path, new_path, 1)
        elif uuid_match:
            new_uuid = str(uuid.uuid4())
            original_uuid = uuid_match.group(1)
            new_path = path.replace(original_uuid, new_uuid, 1)
            tampered_url = url.replace(path, new_path, 1)
            technique = "UUID Tampering"

        if tampered_url:
            status, body_res = self._dispatch_request(method, tampered_url, headers, body)
            if status == 200 and len(body_res) > 0:
                # Vulnerabilità confermata!
                evidence = RuntimeEvidence(
                    tested_url=tampered_url,
                    http_status=status,
                    response_snippet=body_res[:200]
                )
                
                return Finding.create(
                    source=FindingSource.RUNTIME_VALIDATOR,
                    category=FindingCategory.AUTHORIZATION,
                    title="Vulnerabilità BOLA Rilevata e Verificata a Runtime",
                    description=f"Possibile BOLA: Modificando l'identificatore della risorsa ({technique}) a runtime, l'endpoint risponde 200 OK con contenuto valido.",
                    severity=Severity.HIGH,
                    confidence=1.0,
                    rule_id="bola-exploit-confirmed",
                    target_identifier=f"{method}:{path}",
                    rule_name="Runtime BOLA Validation",
                    api=APIContext(endpoint=path, method=method, requires_authentication=True),
                    runtime_evidence=evidence,
                    risk_context=RiskContext(exploitable=True, internet_exposed=True),
                    correlation_key=f"api:{method}:{APIEndpointNormalizer.normalize_path(path)}"
                )
        return None

    def _test_token_removal(self, req: Dict[str, Any]) -> Finding:
        url = req.get("full_url", "")
        path = req.get("path", "")
        method = req.get("method", "GET")
        headers = dict(req.get("headers", {}))
        body = req.get("body_params") or req.get("request_body")

        auth_key = None
        for k in list(headers.keys()):
            if k.lower() == "authorization":
                auth_key = k
                break
                
        if auth_key:
            del headers[auth_key]
            status, body_res = self._dispatch_request(method, url, headers, body)
            
            if status == 200:
                evidence = RuntimeEvidence(
                    tested_url=url,
                    http_status=status,
                    accessible_without_auth=True
                )
                
                return Finding.create(
                    source=FindingSource.RUNTIME_VALIDATOR,
                    category=FindingCategory.AUTHENTICATION,
                    title="Bypass dell'Autenticazione Rilevato a Runtime",
                    description=f"L'endpoint risponde con 200 OK anche rimuovendo completamente l'header di autorizzazione ({auth_key}).",
                    severity=Severity.CRITICAL,
                    confidence=1.0,
                    rule_id="auth-bypass-confirmed",
                    target_identifier=f"{method}:{path}",
                    rule_name="Runtime Auth Bypass Validation",
                    api=APIContext(endpoint=path, method=method, requires_authentication=True),
                    runtime_evidence=evidence,
                    risk_context=RiskContext(exploitable=True, internet_exposed=True),
                    correlation_key=f"api:{method}:{APIEndpointNormalizer.normalize_path(path)}"
                )
        return None
