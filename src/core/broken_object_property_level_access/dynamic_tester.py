import re
import json
import base64
import requests
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple, Set

from loguru import logger

# Import models
from src.core.broken_object_property_level_access.models import (
    PropertyInventory, PropertyEvidence, PropertyAuthorizationGraph,
    DynamicPropertyFinding, ObjectGraphNode, PropertyGraphNode
)
from src.core.broken_object_property_level_access.discovery import PropertyDiscoveryEngine
from src.normalization.normalizer import APIEndpointNormalizer


class BOPLADynamicTester:
    """
    BOPLADynamicTester executes targeted dynamic testing (T01 - T07) against the target base URL
    using the discovery inventory, inference evidences, and authorization graph.
    """

    def __init__(
        self,
        target_base_url: str,
        inventory: PropertyInventory,
        evidences: List[PropertyEvidence],
        graph: PropertyAuthorizationGraph,
        headers_matrix: Dict[str, Dict[str, str]],
        proxies: Optional[Dict[str, str]] = None,
        runtime_traffic: Optional[List[Dict[str, Any]]] = None,
        openapi_spec: Optional[Dict[str, Any]] = None,
        confidence_threshold: float = 0.4
    ):
        self.target_base_url = target_base_url.rstrip("/")
        self.inventory = inventory
        self.evidences = evidences
        self.graph = graph
        self.headers_matrix = headers_matrix
        self.proxies = proxies or {}
        self.runtime_traffic = runtime_traffic or []
        self.openapi_spec = openapi_spec or {}
        self.confidence_threshold = confidence_threshold

        # Extract UUIDs from the standard tokens (Bearer sub claims) or use realistic fallbacks
        self.uuid_alice = self.extract_sub_from_jwt(headers_matrix.get("userA", {}).get("Authorization")) or "f81d4fae-7dec-11d0-a765-00a0c91e6bfa"
        self.uuid_bob = self.extract_sub_from_jwt(headers_matrix.get("userB", {}).get("Authorization")) or "f81d4fae-7dec-11d0-a765-00a0c91e6bfb"
        self.uuid_charlie = self.extract_sub_from_jwt(headers_matrix.get("userC", {}).get("Authorization")) or "f81d4fae-7dec-11d0-a765-00a0c91e6bfc"

        logger.info(f"BOPLA Dynamic Tester: Identità estratte - Alice (userA): {self.uuid_alice}, Bob (userB): {self.uuid_bob}, Admin (userC): {self.uuid_charlie}")

    @staticmethod
    def extract_sub_from_jwt(auth_header: Optional[str]) -> Optional[str]:
        """
        Decodes the standard JWT without signature verification to extract the 'sub' UUID.
        """
        if not auth_header or not auth_header.startswith("Bearer "):
            return None
        token = auth_header.split(" ")[1]
        try:
            import jwt
            decoded = jwt.decode(token, options={"verify_signature": False})
            sub = decoded.get("sub")
            if sub:
                return str(sub)
        except Exception:
            pass

        # Manual base64 decode fallback
        try:
            segments = token.split(".")
            if len(segments) >= 2:
                payload_b64 = segments[1]
                payload_b64 += "=" * (-len(payload_b64) % 4)
                payload_json = base64.urlsafe_b64decode(payload_b64).decode("utf-8")
                payload = json.loads(payload_json)
                sub = payload.get("sub")
                if sub:
                    return str(sub)
        except Exception:
            pass
        return None

    def _resolve_path(self, path: str, resource_id: str) -> str:
        """
        Replaces any endpoint path parameters (like {id}, {userId}, <id>, etc.) with a specific resource ID.
        """
        resolved = re.sub(r"\{[a-zA-Z0-9_-]+\}", resource_id, path)
        resolved = re.sub(r"<[a-zA-Z0-9_-]+>", resource_id, resolved)
        return resolved

    def _send_request(
        self,
        method: str,
        path: str,
        headers: Dict[str, str],
        json_data: Any = None
    ) -> Tuple[Optional[int], str, Optional[Any]]:
        """
        Wraps HTTP requests using requests library, applying configured base URL and proxies.
        Returns a tuple: (status_code, raw_text_response, parsed_json_response)
        """
        method = method.upper()
        # Resolve target full URL
        url = f"{self.target_base_url}{path}"
        try:
            kwargs = {
                "headers": headers,
                "verify": False,
                "timeout": 5
            }
            if self.proxies:
                kwargs["proxies"] = self.proxies
            if json_data is not None:
                kwargs["json"] = json_data

            resp = requests.request(method, url, **kwargs)
            
            json_parsed = None
            try:
                json_parsed = resp.json()
            except Exception:
                pass

            return resp.status_code, resp.text, json_parsed
        except Exception as e:
            logger.error(f"Errore durante la chiamata HTTP {method} {url}: {e}")
            return None, str(e), None

    def _generate_baseline_payload(self, object_name: str, target_property: str, tampered_value: Any) -> Dict[str, Any]:
        """
        Constructs a realistic payload for write endpoints using OpenAPI schemas and runtime traffic.
        """
        payload = {}

        # 1. Try OpenAPI spec components/schemas
        if self.openapi_spec:
            schemas = self.openapi_spec.get("components", {}).get("schemas", {}) or self.openapi_spec.get("definitions", {})
            schema = None
            for name in (object_name, f"{object_name}DTO", f"{object_name}Request", f"{object_name}Model"):
                if name in schemas:
                    schema = schemas[name]
                    break
            if schema and schema.get("type") == "object":
                props = schema.get("properties", {})
                for k, v in props.items():
                    t = v.get("type")
                    if t == "integer" or t == "number":
                        payload[k] = 0
                    elif t == "boolean":
                        payload[k] = False
                    elif t == "array":
                        payload[k] = []
                    elif t == "object":
                        payload[k] = {}
                    else:
                        payload[k] = "test"

        # 2. Enrich with observed runtime traffic body keys
        if self.runtime_traffic:
            for entry in self.runtime_traffic:
                path = entry.get("path")
                if path and PropertyDiscoveryEngine.get_object_name_from_path(path) == object_name:
                    body = entry.get("body_params") or entry.get("response_body") or entry.get("response")
                    if body:
                        if isinstance(body, str):
                            try:
                                body = json.loads(body)
                            except Exception:
                                pass
                        if isinstance(body, dict):
                            for k, v in body.items():
                                payload[k] = v
                            break

        # 3. Explicitly insert the target property to test
        payload[target_property] = tampered_value
        return payload

    def _parse_endpoint_string(self, ep_str: str) -> Tuple[str, str]:
        """
        Parses an operation string like 'GET /api/orders/{id}' into ('GET', '/api/orders/{id}').
        """
        parts = ep_str.split(" ", 1)
        if len(parts) == 2:
            return parts[0].upper(), parts[1]
        return "GET", ep_str

    def _extract_keys_recursive(self, data: Any) -> Set[str]:
        """Recursively extracts keys from dictionary or list structure."""
        keys = set()
        if isinstance(data, dict):
            for k, v in data.items():
                keys.add(k)
                keys.update(self._extract_keys_recursive(v))
        elif isinstance(data, list):
            for item in data:
                keys.update(self._extract_keys_recursive(item))
        return keys

    def run_all_tests(self) -> List[DynamicPropertyFinding]:
        """Runs the entire BOPLA dynamic testing suite (T01 - T07)."""
        findings = []
        findings.extend(self.run_t01())
        findings.extend(self.run_t02())
        findings.extend(self.run_t03())
        findings.extend(self.run_t04())
        findings.extend(self.run_t05())
        findings.extend(self.run_t06())
        findings.extend(self.run_t07())
        return findings

    def run_t01(self) -> List[DynamicPropertyFinding]:
        """
        T01 - Sensitive Property Exposure.
        Checks if standard users can retrieve sensitive properties.
        """
        logger.info("Avvio BOPLA Test T01 - Sensitive Property Exposure...")
        findings = []

        for ev in self.evidences:
            # We target properties inferred to be authorized (high confidence or auth context)
            if ev.confidence >= self.confidence_threshold or ev.authorization_contexts:
                for rd in ev.read_endpoints:
                    method, path = self._parse_endpoint_string(rd)
                    if method != "GET":
                        continue

                    # Substitute resource ID of Alice
                    test_path = self._resolve_path(path, self.uuid_alice)
                    headers = self.headers_matrix.get("userA", {})

                    status, text, json_data = self._send_request("GET", test_path, headers)
                    
                    if status and 200 <= status < 300 and json_data:
                        extracted_keys = self._extract_keys_recursive(json_data)
                        if ev.property in extracted_keys:
                            evidence_msg = [
                                "Proprietà identificata come protetta nell'AST o Inference Engine.",
                                f"Proprietà '{ev.property}' restituita nella risposta GET per l'utente standard userA.",
                                f"Contesti autorizzativi noti: {ev.authorization_contexts}"
                            ]
                            findings.append(
                                DynamicPropertyFinding(
                                    test_id="T01",
                                    endpoint=test_path,
                                    method="GET",
                                    property_name=ev.property,
                                    evidence=evidence_msg,
                                    request=f"GET {test_path} \nHeaders: {headers}",
                                    response=text,
                                    response_code=status,
                                    verified=True,
                                    confidence=ev.confidence
                                )
                            )

        return findings

    def run_t02(self) -> List[DynamicPropertyFinding]:
        """
        T02 - Unauthorized Property Modification.
        Tries to modify sensitive properties using a standard user role.
        """
        logger.info("Avvio BOPLA Test T02 - Unauthorized Property Modification...")
        findings = []

        for ev in self.evidences:
            if ev.confidence >= self.confidence_threshold or ev.authorization_contexts:
                for wr in ev.write_endpoints:
                    method, path = self._parse_endpoint_string(wr)
                    if method not in ("PUT", "PATCH", "POST"):
                        continue

                    # Attempt modification
                    test_value = 999999 if "salary" in ev.property.lower() or "price" in ev.property.lower() else "modified_via_t02"
                    payload = self._generate_baseline_payload(ev.object_name, ev.property, test_value)

                    test_path = self._resolve_path(path, self.uuid_alice)
                    headers = self.headers_matrix.get("userA", {})

                    status, text, json_data = self._send_request(method, test_path, headers, payload)

                    if status and 200 <= status < 300:
                        # Success response: now check if the change persisted or is reflected in response
                        is_modified = False
                        evidence_msg = [
                            f"Richiesta di scrittura {method} accettata con stato {status}.",
                            "Proprietà inviata nel payload modificata con successo."
                        ]

                        # Case A: reflected in body
                        if json_data:
                            extracted_keys = self._extract_keys_recursive(json_data)
                            if ev.property in extracted_keys:
                                is_modified = True
                                evidence_msg.append(f"Valore modificato riflesso nella risposta di scrittura.")

                        # Case B: check subsequent GET
                        for rd in ev.read_endpoints:
                            rmethod, rpath = self._parse_endpoint_string(rd)
                            if rmethod == "GET":
                                gpath = self._resolve_path(rpath, self.uuid_alice)
                                gstatus, gtext, gjson = self._send_request("GET", gpath, headers)
                                if gstatus == 200 and gjson:
                                    # check if value is equal or key exists
                                    if gjson.get(ev.property) == test_value or str(gjson.get(ev.property)) == str(test_value):
                                        is_modified = True
                                        evidence_msg.append(f"Valore persistito verificato tramite successiva GET su {gpath}.")
                                        break

                        if is_modified:
                            findings.append(
                                DynamicPropertyFinding(
                                    test_id="T02",
                                    endpoint=test_path,
                                    method=method,
                                    property_name=ev.property,
                                    evidence=evidence_msg,
                                    request=f"{method} {test_path} \nPayload: {payload}",
                                    response=text,
                                    response_code=status,
                                    verified=True,
                                    confidence=ev.confidence
                                )
                            )

        return findings

    def run_t03(self) -> List[DynamicPropertyFinding]:
        """
        T03 - Mass Assignment.
        Tries injecting fields that standard clients normally do not send.
        """
        logger.info("Avvio BOPLA Test T03 - Mass Assignment...")
        findings = []

        # Identify AST-only or server-only properties for each object
        for ev in self.evidences:
            # Criteria: present in AST/Runtime but not documented in OpenAPI schemas under request body,
            # or properties with high authorization context.
            is_mass_assignment_target = False
            if ev.found_in_ast and not ev.found_in_openapi:
                is_mass_assignment_target = True
            elif ev.confidence >= self.confidence_threshold:
                is_mass_assignment_target = True

            if is_mass_assignment_target:
                for wr in ev.write_endpoints:
                    method, path = self._parse_endpoint_string(wr)
                    if method not in ("PUT", "PATCH", "POST"):
                        continue

                    # Try to write/inject property
                    test_value = 99999 if "salary" in ev.property.lower() else "mass_assigned_value"
                    payload = self._generate_baseline_payload(ev.object_name, ev.property, test_value)

                    test_path = self._resolve_path(path, self.uuid_alice)
                    headers = self.headers_matrix.get("userA", {})

                    status, text, json_data = self._send_request(method, test_path, headers, payload)

                    if status and 200 <= status < 300:
                        evidence_msg = [
                            f"Mass assignment tentata su proprietà '{ev.property}' tramite {method}.",
                            f"Server ha accettato la richiesta con status {status}."
                        ]
                        
                        # Verify reflection or persistence
                        is_success = False
                        if json_data:
                            extracted_keys = self._extract_keys_recursive(json_data)
                            if ev.property in extracted_keys:
                                is_success = True
                                evidence_msg.append("Proprietà riflessa nel corpo di risposta di scrittura.")

                        for rd in ev.read_endpoints:
                            rmethod, rpath = self._parse_endpoint_string(rd)
                            if rmethod == "GET":
                                gpath = self._resolve_path(rpath, self.uuid_alice)
                                gstatus, gtext, gjson = self._send_request("GET", gpath, headers)
                                if gstatus == 200 and gjson:
                                    if gjson.get(ev.property) == test_value or str(gjson.get(ev.property)) == str(test_value):
                                        is_success = True
                                        evidence_msg.append(f"Valore persistito verificato via GET su {gpath}.")
                                        break

                        if is_success:
                            findings.append(
                                DynamicPropertyFinding(
                                    test_id="T03",
                                    endpoint=test_path,
                                    method=method,
                                    property_name=ev.property,
                                    evidence=evidence_msg,
                                    request=f"{method} {test_path} \nPayload: {payload}",
                                    response=text,
                                    response_code=status,
                                    verified=True,
                                    confidence=ev.confidence
                                )
                            )

        return findings

    def run_t04(self) -> List[DynamicPropertyFinding]:
        """
        T04 - Hidden Property Injection.
        Tries to inject undocumented properties (present in AST/Runtime but not OpenAPI).
        """
        logger.info("Avvio BOPLA Test T04 - Hidden Property Injection...")
        findings = []

        for ev in self.evidences:
            # Strictly undocumented properties
            if (ev.found_in_ast or ev.found_runtime) and not ev.found_in_openapi:
                for wr in ev.write_endpoints:
                    method, path = self._parse_endpoint_string(wr)
                    if method not in ("PUT", "PATCH", "POST"):
                        continue

                    test_value = 88888 if "salary" in ev.property.lower() else "hidden_injected"
                    payload = self._generate_baseline_payload(ev.object_name, ev.property, test_value)

                    test_path = self._resolve_path(path, self.uuid_alice)
                    headers = self.headers_matrix.get("userA", {})

                    status, text, json_data = self._send_request(method, test_path, headers, payload)

                    if status and 200 <= status < 300:
                        evidence_msg = [
                            f"Iniezione di proprietà nascosta '{ev.property}' tentata via {method}.",
                            "Proprietà assente nella documentazione OpenAPI ma presente nel codice sorgente/AST.",
                            f"Server ha accettato la richiesta (status {status})."
                        ]

                        is_success = False
                        if json_data and ev.property in self._extract_keys_recursive(json_data):
                            is_success = True
                            evidence_msg.append("Proprietà riflessa nella risposta.")

                        for rd in ev.read_endpoints:
                            rmethod, rpath = self._parse_endpoint_string(rd)
                            if rmethod == "GET":
                                gpath = self._resolve_path(rpath, self.uuid_alice)
                                gstatus, gtext, gjson = self._send_request("GET", gpath, headers)
                                if gstatus == 200 and gjson and ev.property in gjson:
                                    is_success = True
                                    evidence_msg.append("Proprietà osservata persistita nella risposta GET.")
                                    break

                        if is_success:
                            findings.append(
                                DynamicPropertyFinding(
                                    test_id="T04",
                                    endpoint=test_path,
                                    method=method,
                                    property_name=ev.property,
                                    evidence=evidence_msg,
                                    request=f"{method} {test_path} \nPayload: {payload}",
                                    response=text,
                                    response_code=status,
                                    verified=True,
                                    confidence=ev.confidence
                                )
                            )

        return findings

    def run_t05(self) -> List[DynamicPropertyFinding]:
        """
        T05 - Read / Write Authorization Mismatch.
        Checks if properties hidden from GET responses can still be modified by clients.
        """
        logger.info("Avvio BOPLA Test T05 - Read / Write Authorization Mismatch...")
        findings = []

        for ev in self.evidences:
            # Property is writeable but NOT readable (not in read endpoints or GET responses)
            if ev.write_endpoints and not ev.read_endpoints:
                for wr in ev.write_endpoints:
                    method, path = self._parse_endpoint_string(wr)
                    if method not in ("PUT", "PATCH", "POST"):
                        continue

                    test_value = "mismatch_write_test"
                    payload = self._generate_baseline_payload(ev.object_name, ev.property, test_value)

                    test_path = self._resolve_path(path, self.uuid_alice)
                    headers = self.headers_matrix.get("userA", {})

                    status, text, json_data = self._send_request(method, test_path, headers, payload)

                    if status and 200 <= status < 300:
                        evidence_msg = [
                            f"Rilevata proprietà '{ev.property}' scrivibile ({method}) ma non associata ad operazioni di lettura.",
                            f"Server ha accettato la modifica con status {status}.",
                            "Questa discrepanza indica un potenziale bypass autorizzativo/mismatch di visibilità."
                        ]
                        findings.append(
                            DynamicPropertyFinding(
                                test_id="T05",
                                endpoint=test_path,
                                method=method,
                                property_name=ev.property,
                                evidence=evidence_msg,
                                request=f"{method} {test_path} \nPayload: {payload}",
                                response=text,
                                response_code=status,
                                verified=True,
                                confidence=ev.confidence
                            )
                        )

        return findings

    def run_t06(self) -> List[DynamicPropertyFinding]:
        """
        T06 - Differential Response Analysis.
        Compares GET responses between a standard user (userA) and admin user (userC).
        """
        logger.info("Avvio BOPLA Test T06 - Differential Response Analysis...")
        findings = []

        # Gather all unique GET endpoints from evidences
        get_endpoints = set()
        for ev in self.evidences:
            for rd in ev.read_endpoints:
                method, path = self._parse_endpoint_string(rd)
                if method == "GET":
                    get_endpoints.add(path)

        for path in get_endpoints:
            # We need both standard and admin tokens
            headers_user = self.headers_matrix.get("userA")
            headers_admin = self.headers_matrix.get("userC")

            if not headers_user or not headers_admin:
                logger.warning("BOPLA T06: Credenziali userA o userC mancanti. Salto analisi differenziale.")
                break

            # Test using Alice's resource
            path_user = self._resolve_path(path, self.uuid_alice)
            # Admin accesses Alice's resource
            path_admin = self._resolve_path(path, self.uuid_alice)

            status_u, text_u, json_u = self._send_request("GET", path_user, headers_user)
            status_a, text_a, json_a = self._send_request("GET", path_admin, headers_admin)

            if status_u == 200 and status_a == 200 and json_u and json_a:
                keys_u = self._extract_keys_recursive(json_u)
                keys_a = self._extract_keys_recursive(json_a)

                diff_keys = keys_a - keys_u
                if diff_keys:
                    # Mismatch found: admin gets more properties
                    for diff_prop in diff_keys:
                        evidence_msg = [
                            f"Analisi differenziale completata per endpoint GET {path_user}.",
                            f"L'amministratore (userC) riceve le seguenti proprietà aggiuntive: {list(diff_keys)}.",
                            f"Proprietà '{diff_prop}' non è visibile per l'utente standard userA."
                        ]
                        # Verify if this property has high confidence of being protected
                        # Finding is valid as structural information mapping
                        findings.append(
                            DynamicPropertyFinding(
                                test_id="T06",
                                endpoint=path_user,
                                method="GET",
                                property_name=diff_prop,
                                evidence=evidence_msg,
                                request=f"GET {path_user} (User vs Admin)",
                                response=f"User Keys: {list(keys_u)}\nAdmin Keys: {list(keys_a)}",
                                response_code=200,
                                verified=True,
                                confidence=0.5
                            )
                        )

        return findings

    def run_t07(self) -> List[DynamicPropertyFinding]:
        """
        T07 - Differential Update Analysis.
        Compares update authorization levels between standard and admin users.
        """
        logger.info("Avvio BOPLA Test T07 - Differential Update Analysis...")
        findings = []

        for ev in self.evidences:
            if ev.confidence >= self.confidence_threshold or ev.authorization_contexts:
                for wr in ev.write_endpoints:
                    method, path = self._parse_endpoint_string(wr)
                    if method not in ("PUT", "PATCH", "POST"):
                        continue

                    headers_user = self.headers_matrix.get("userA")
                    headers_admin = self.headers_matrix.get("userC")

                    if not headers_user or not headers_admin:
                        logger.warning("BOPLA T07: Credenziali userA o userC mancanti. Analisi differenziale di scrittura saltata.")
                        break

                    test_value_admin = "admin_update_t07"
                    test_value_user = "user_update_t07"

                    payload_admin = self._generate_baseline_payload(ev.object_name, ev.property, test_value_admin)
                    payload_user = self._generate_baseline_payload(ev.object_name, ev.property, test_value_user)

                    test_path = self._resolve_path(path, self.uuid_alice)

                    # 1. Test Admin modification
                    status_a, text_a, json_a = self._send_request(method, test_path, headers_admin, payload_admin)
                    # 2. Test User modification
                    status_u, text_u, json_u = self._send_request(method, test_path, headers_user, payload_user)

                    # Analyze outcome
                    # If standard user succeeds (2xx) and admin succeeds (2xx):
                    if status_u and 200 <= status_u < 300:
                        # Standard user modified it successfully
                        evidence_msg = [
                            f"Analisi differenziale di scrittura completata per {method} {test_path} su proprietà '{ev.property}'.",
                            f"L'amministratore risponde con codice {status_a}.",
                            f"L'utente standard userA risponde con codice {status_u} (modifica accettata).",
                            "Mancanza di controlli autorizzativi differenziali sul livello di scrittura della proprietà."
                        ]
                        findings.append(
                            DynamicPropertyFinding(
                                test_id="T07",
                                endpoint=test_path,
                                method=method,
                                property_name=ev.property,
                                evidence=evidence_msg,
                                request=f"Payload Admin: {payload_admin}\nPayload User: {payload_user}",
                                response=f"Admin Status: {status_a}, User Status: {status_u}",
                                response_code=status_u,
                                verified=True,
                                confidence=ev.confidence
                            )
                        )
                    else:
                        # User was blocked (e.g. 403 or 401), and admin succeeded. This is secure!
                        evidence_msg = [
                            f"Analisi differenziale di scrittura completata per {method} {test_path} su proprietà '{ev.property}'.",
                            f"L'utente standard userA è stato correttamente respinto con codice {status_u}.",
                            f"L'amministratore (userC) ha modificato con successo con codice {status_a}."
                        ]
                        findings.append(
                            DynamicPropertyFinding(
                                test_id="T07",
                                endpoint=test_path,
                                method=method,
                                property_name=ev.property,
                                evidence=evidence_msg,
                                request=f"Payload Admin: {payload_admin}\nPayload User: {payload_user}",
                                response=f"Admin Status: {status_a}, User Status: {status_u}",
                                response_code=status_u,
                                verified=False,
                                confidence=ev.confidence
                            )
                        )

        return findings
