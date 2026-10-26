import base64
import contextlib
import json
import re
from typing import Any

import requests
from loguru import logger

from src.core.api3_bopla.discovery import PropertyDiscoveryEngine

# Import models
from src.core.api3_bopla.models import (
    DynamicPropertyFinding,
    PropertyAuthorizationGraph,
    PropertyEvidence,
    PropertyInventory,
)
from src.core.api3_bopla.property_inference import PropertyAuthorizationInferenceEngine

WRITE_METHODS = ("PUT", "PATCH", "POST")


class BOPLADynamicTester:
    """
    BOPLADynamicTester executes targeted dynamic testing (T01 - T07) against the target base URL
    using the discovery inventory, inference evidences, and authorization graph.
    """

    def __init__(
        self,
        target_base_url: str,
        inventory: PropertyInventory,
        evidences: list[PropertyEvidence],
        graph: PropertyAuthorizationGraph,
        headers_matrix: dict[str, dict[str, str]],
        proxies: dict[str, str] | None = None,
        runtime_traffic: list[dict[str, Any]] | None = None,
        openapi_spec: dict[str, Any] | None = None,
        confidence_threshold: float = 0.4,
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
        self.uuid_alice = (
            self.extract_sub_from_jwt(headers_matrix.get("userA", {}).get("Authorization"))
            or "f81d4fae-7dec-11d0-a765-00a0c91e6bfa"
        )
        self.uuid_bob = (
            self.extract_sub_from_jwt(headers_matrix.get("userB", {}).get("Authorization"))
            or "f81d4fae-7dec-11d0-a765-00a0c91e6bfb"
        )
        self.uuid_charlie = (
            self.extract_sub_from_jwt(headers_matrix.get("userC", {}).get("Authorization"))
            or "f81d4fae-7dec-11d0-a765-00a0c91e6bfc"
        )

        logger.info(
            f"BOPLA Dynamic Tester: Identità estratte - Alice (userA): {self.uuid_alice}, Bob (userB): {self.uuid_bob}, Admin (userC): {self.uuid_charlie}"
        )

    @staticmethod
    def extract_sub_from_jwt(auth_header: str | None) -> str | None:
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
        self, method: str, path: str, headers: dict[str, str], json_data: Any = None
    ) -> tuple[int | None, str, Any | None]:
        """
        Wraps HTTP requests using requests library, applying configured base URL and proxies.
        Returns a tuple: (status_code, raw_text_response, parsed_json_response)
        """
        method = method.upper()
        # Resolve target full URL
        url = f"{self.target_base_url}{path}"
        try:
            kwargs = {"headers": headers, "verify": False, "timeout": 5}
            if self.proxies:
                kwargs["proxies"] = self.proxies
            if json_data is not None:
                kwargs["json"] = json_data

            resp = requests.request(method, url, **kwargs)

            json_parsed = None
            with contextlib.suppress(Exception):
                json_parsed = resp.json()

            return resp.status_code, resp.text, json_parsed
        except Exception as e:
            logger.error(f"Errore durante la chiamata HTTP {method} {url}: {e}")
            return None, str(e), None

    def _generate_baseline_payload(
        self, object_name: str, target_property: str, tampered_value: Any
    ) -> dict[str, Any]:
        """
        Constructs a realistic payload for write endpoints using OpenAPI schemas and runtime traffic.
        """
        payload = {}

        # 1. Try OpenAPI spec components/schemas
        if self.openapi_spec:
            schemas = self.openapi_spec.get("components", {}).get(
                "schemas", {}
            ) or self.openapi_spec.get("definitions", {})
            schema = None
            for name in (
                object_name,
                f"{object_name}DTO",
                f"{object_name}Request",
                f"{object_name}Model",
            ):
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
                    body = (
                        entry.get("body_params")
                        or entry.get("response_body")
                        or entry.get("response")
                    )
                    if body:
                        if isinstance(body, str):
                            with contextlib.suppress(Exception):
                                body = json.loads(body)
                        if isinstance(body, dict):
                            for k, v in body.items():
                                payload[k] = v
                            break

        # 3. Explicitly insert the target property to test
        payload[target_property] = tampered_value
        return payload

    def _parse_endpoint_string(self, ep_str: str) -> tuple[str, str]:
        """
        Parses an operation string like 'GET /api/orders/{id}' into ('GET', '/api/orders/{id}').
        """
        parts = ep_str.split(" ", 1)
        if len(parts) == 2:
            return parts[0].upper(), parts[1]
        return "GET", ep_str

    def _extract_keys_recursive(self, data: Any) -> set[str]:
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

    # ------------------------------------------------------------------
    # Target selection and verification helpers
    # ------------------------------------------------------------------

    def _is_protected(self, ev: PropertyEvidence, direction: str | None = None) -> bool:
        """
        A property is treated as protected only when the code shows an authorization context
        around it. Confidence alone is not enough: it measures how documented and used a
        property is, so an ordinary field present in code and contract would pass the threshold.
        `direction` ("read"/"write") ignores the contract contexts of the other direction: a
        readOnly property is legitimately returned, a writeOnly one legitimately sent.
        """
        return PropertyAuthorizationInferenceEngine.is_protected_property(
            ev, self.confidence_threshold, direction
        )

    @staticmethod
    def _testable(ev: PropertyEvidence) -> bool:
        """
        Nested properties are recorded with a dotted path (`manager.salary`, B.11). A dotted
        name is not a JSON key: sending it in a payload would inject a meaningless top-level
        field, and it never matches the keys of a response. They stay in the inventory and in
        the static phases but are excluded from the dynamic tests.
        """
        return "." not in ev.property

    def _object_endpoints(self, object_name: str, methods: tuple[str, ...]) -> list[str]:
        """
        Returns the paths of all operations touching an object with one of the given methods.
        Mass assignment and protected-field tampering target the object's write operations,
        not only the ones where the property was already observed.
        """
        paths = set()
        for ev in self.evidences:
            if ev.object_name != object_name:
                continue
            for ep in ev.read_endpoints + ev.write_endpoints:
                method, path = self._parse_endpoint_string(ep)
                if method in methods:
                    paths.add((method, path))
        return [f"{m} {p}" for m, p in sorted(paths)]

    def _reader_headers(self) -> dict[str, str]:
        """Most privileged identity available: a protected property may be hidden from userA."""
        return self.headers_matrix.get("userC") or self.headers_matrix.get("userA", {})

    def _find_value(self, data: Any, prop: str, expected: Any) -> bool:
        """True if `prop` holds `expected` anywhere in a JSON structure."""
        if isinstance(data, dict):
            for k, v in data.items():
                if k == prop and str(v) == str(expected):
                    return True
                if self._find_value(v, prop, expected):
                    return True
        elif isinstance(data, list):
            return any(self._find_value(item, prop, expected) for item in data)
        return False

    def _read_back(self, object_name: str, prop: str, expected: Any) -> str | None:
        """
        Re-reads the resource and returns the path where the marker value was found persisted,
        or None. An accepted write is not proof of a vulnerability: the server may silently
        ignore the field.
        """
        headers = self._reader_headers()
        for ep in self._object_endpoints(object_name, ("GET",)):
            _method, path = self._parse_endpoint_string(ep)
            gpath = self._resolve_path(path, self.uuid_alice)
            status, _text, data = self._send_request("GET", gpath, headers)
            if status == 200 and self._find_value(data, prop, expected):
                return gpath
        return None

    @staticmethod
    def _marker(prop: str, test_id: str, numeric: int) -> Any:
        numeric_hint = any(k in prop.lower() for k in ("salary", "price", "amount", "balance"))
        return numeric if numeric_hint else f"bopla_{test_id.lower()}_{prop}"

    def _attempt_write(
        self,
        test_id: str,
        ev: PropertyEvidence,
        write_endpoint: str,
        value: Any,
        evidence_intro: list[str],
    ) -> DynamicPropertyFinding | None:
        """
        Sends a write as userA carrying `value` for the property and confirms the defect only
        if the value is read back as persisted.
        """
        method, path = self._parse_endpoint_string(write_endpoint)
        payload = self._generate_baseline_payload(ev.object_name, ev.property, value)
        test_path = self._resolve_path(path, self.uuid_alice)
        headers = self.headers_matrix.get("userA", {})

        status, text, _json_data = self._send_request(method, test_path, headers, payload)
        if not (status and 200 <= status < 300):
            return None

        persisted_at = self._read_back(ev.object_name, ev.property, value)
        if not persisted_at:
            logger.debug(
                f"BOPLA {test_id}: {method} {test_path} accettata ma '{ev.property}' non persistita."
            )
            return None

        return DynamicPropertyFinding(
            test_id=test_id,
            endpoint=test_path,
            method=method,
            property_name=ev.property,
            evidence=[
                *evidence_intro,
                f"Richiesta {method} dell'utente standard userA accettata con stato {status}.",
                f"Valore '{value}' persistito, verificato rileggendo {persisted_at}.",
            ],
            request=f"{method} {test_path} \nPayload: {payload}",
            response=text,
            response_code=status,
            verified=True,
            confidence=ev.confidence,
        )

    # ------------------------------------------------------------------
    # Test suite
    # ------------------------------------------------------------------

    def run_all_tests(self) -> list[DynamicPropertyFinding]:
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

    def run_t01(self) -> list[DynamicPropertyFinding]:
        """
        T01 - Sensitive Property Exposure.
        A standard user reading their own resource receives a protected property.
        """
        logger.info("Avvio BOPLA Test T01 - Sensitive Property Exposure...")
        findings = []
        headers = self.headers_matrix.get("userA", {})

        for ev in self.evidences:
            if not (self._testable(ev) and self._is_protected(ev, "read")):
                continue
            for rd in self._object_endpoints(ev.object_name, ("GET",)):
                _method, path = self._parse_endpoint_string(rd)
                test_path = self._resolve_path(path, self.uuid_alice)
                status, text, json_data = self._send_request("GET", test_path, headers)

                if status and 200 <= status < 300 and json_data:
                    if ev.property in self._extract_keys_recursive(json_data):
                        findings.append(
                            DynamicPropertyFinding(
                                test_id="T01",
                                endpoint=test_path,
                                method="GET",
                                property_name=ev.property,
                                evidence=[
                                    "Proprietà inferita come protetta (contesto autorizzativo nel codice).",
                                    f"Proprietà '{ev.property}' restituita nella risposta GET per l'utente standard userA.",
                                    f"Contesti autorizzativi noti: {ev.authorization_contexts}",
                                ],
                                request=f"GET {test_path} \nHeaders: {headers}",
                                response=text,
                                response_code=status,
                                verified=True,
                                confidence=ev.confidence,
                            )
                        )
        return findings

    def run_t02(self) -> list[DynamicPropertyFinding]:
        """
        T02 - Unauthorized Property Modification.
        A standard user changes a protected property and the change is persisted.
        """
        logger.info("Avvio BOPLA Test T02 - Unauthorized Property Modification...")
        findings = []
        for ev in self.evidences:
            if not (self._testable(ev) and self._is_protected(ev, "write")):
                continue
            for wr in self._object_endpoints(ev.object_name, WRITE_METHODS):
                finding = self._attempt_write(
                    "T02",
                    ev,
                    wr,
                    self._marker(ev.property, "T02", 999999),
                    [
                        f"Modifica della proprietà protetta '{ev.property}' tentata dall'utente standard."
                    ],
                )
                if finding:
                    findings.append(finding)
        return findings

    def run_t03(self) -> list[DynamicPropertyFinding]:
        """
        T03 - Mass Assignment.
        Injects fields that clients do not normally send (present in code, absent from the
        contract) or protected fields into the object's write operations.
        """
        logger.info("Avvio BOPLA Test T03 - Mass Assignment...")
        findings = []
        for ev in self.evidences:
            undocumented = ev.found_in_ast and not ev.found_in_openapi
            if not self._testable(ev) or not (undocumented or self._is_protected(ev, "write")):
                continue
            for wr in self._object_endpoints(ev.object_name, WRITE_METHODS):
                finding = self._attempt_write(
                    "T03",
                    ev,
                    wr,
                    self._marker(ev.property, "T03", 99999),
                    [f"Mass assignment tentata sulla proprietà '{ev.property}'."],
                )
                if finding:
                    findings.append(finding)
        return findings

    def run_t04(self) -> list[DynamicPropertyFinding]:
        """
        T04 - Hidden Property Injection.
        Injects properties seen in code or traffic but absent from the contract.
        """
        logger.info("Avvio BOPLA Test T04 - Hidden Property Injection...")
        findings = []
        for ev in self.evidences:
            if not self._testable(ev):
                continue
            if not ((ev.found_in_ast or ev.found_runtime) and not ev.found_in_openapi):
                continue
            for wr in self._object_endpoints(ev.object_name, WRITE_METHODS):
                finding = self._attempt_write(
                    "T04",
                    ev,
                    wr,
                    self._marker(ev.property, "T04", 88888),
                    [
                        f"Iniezione della proprietà non documentata '{ev.property}'.",
                        "Proprietà assente dal contratto OpenAPI ma presente nel codice o nel traffico.",
                    ],
                )
                if finding:
                    findings.append(finding)
        return findings

    def run_t05(self) -> list[DynamicPropertyFinding]:
        """
        T05 - Read / Write Authorization Mismatch.
        A property never returned to clients can still be modified by a standard user.
        """
        logger.info("Avvio BOPLA Test T05 - Read / Write Authorization Mismatch...")
        findings = []
        for ev in self.evidences:
            if not self._testable(ev) or not (ev.write_endpoints and not ev.read_endpoints):
                continue
            for wr in ev.write_endpoints:
                method, _path = self._parse_endpoint_string(wr)
                if method not in WRITE_METHODS:
                    continue
                finding = self._attempt_write(
                    "T05",
                    ev,
                    wr,
                    self._marker(ev.property, "T05", 77777),
                    [
                        f"Proprietà '{ev.property}' scrivibile ({method}) ma mai restituita nelle letture osservate.",
                    ],
                )
                if finding:
                    findings.append(finding)
        return findings

    def run_t06(self) -> list[DynamicPropertyFinding]:
        """
        T06 - Differential Response Analysis.
        Compares the same GET for a standard user (userA) and an admin (userC). A protected
        property returned to both is a vulnerability; a property only the admin receives is the
        expected outcome of a working control and is recorded as protected (verified=False).
        """
        logger.info("Avvio BOPLA Test T06 - Differential Response Analysis...")
        findings = []

        headers_user = self.headers_matrix.get("userA")
        headers_admin = self.headers_matrix.get("userC")
        if not headers_user or not headers_admin:
            logger.warning(
                "BOPLA T06: Credenziali userA o userC mancanti. Salto analisi differenziale."
            )
            return findings

        objects = sorted({ev.object_name for ev in self.evidences})
        for obj in objects:
            protected = {
                ev.property: ev
                for ev in self.evidences
                if ev.object_name == obj and self._testable(ev) and self._is_protected(ev, "read")
            }
            for rd in self._object_endpoints(obj, ("GET",)):
                _method, path = self._parse_endpoint_string(rd)
                test_path = self._resolve_path(path, self.uuid_alice)
                status_u, _tu, json_u = self._send_request("GET", test_path, headers_user)
                status_a, _ta, json_a = self._send_request("GET", test_path, headers_admin)
                if not (status_u == 200 and status_a == 200 and json_u and json_a):
                    continue

                keys_u = self._extract_keys_recursive(json_u)
                keys_a = self._extract_keys_recursive(json_a)
                response = f"User Keys: {sorted(keys_u)}\nAdmin Keys: {sorted(keys_a)}"

                for prop, ev in protected.items():
                    if prop in keys_u and prop in keys_a:
                        findings.append(
                            DynamicPropertyFinding(
                                test_id="T06",
                                endpoint=test_path,
                                method="GET",
                                property_name=prop,
                                evidence=[
                                    f"Analisi differenziale su GET {test_path}.",
                                    f"La proprietà protetta '{prop}' è restituita sia all'amministratore sia all'utente standard.",
                                ],
                                request=f"GET {test_path} (User vs Admin)",
                                response=response,
                                response_code=200,
                                verified=True,
                                confidence=ev.confidence,
                            )
                        )

                for prop in sorted(keys_a - keys_u):
                    findings.append(
                        DynamicPropertyFinding(
                            test_id="T06",
                            endpoint=test_path,
                            method="GET",
                            property_name=prop,
                            evidence=[
                                f"Analisi differenziale su GET {test_path}.",
                                f"La proprietà '{prop}' è restituita solo all'amministratore: visibilità differenziata come atteso.",
                            ],
                            request=f"GET {test_path} (User vs Admin)",
                            response=response,
                            response_code=200,
                            verified=False,
                            confidence=protected[prop].confidence if prop in protected else 0.0,
                        )
                    )
        return findings

    def run_t07(self) -> list[DynamicPropertyFinding]:
        """
        T07 - Differential Update Analysis.
        The admin and the standard user write the same protected property with different
        markers; the defect is confirmed only if the user's value is the one persisted.
        """
        logger.info("Avvio BOPLA Test T07 - Differential Update Analysis...")
        findings = []

        headers_user = self.headers_matrix.get("userA")
        headers_admin = self.headers_matrix.get("userC")
        if not headers_user or not headers_admin:
            logger.warning(
                "BOPLA T07: Credenziali userA o userC mancanti. Analisi differenziale di scrittura saltata."
            )
            return findings

        for ev in self.evidences:
            if not (self._testable(ev) and self._is_protected(ev, "write")):
                continue
            for wr in self._object_endpoints(ev.object_name, WRITE_METHODS):
                method, path = self._parse_endpoint_string(wr)
                test_path = self._resolve_path(path, self.uuid_alice)
                value_admin = self._marker(ev.property, "T07A", 70001)
                value_user = self._marker(ev.property, "T07U", 70002)
                payload_admin = self._generate_baseline_payload(
                    ev.object_name, ev.property, value_admin
                )
                payload_user = self._generate_baseline_payload(
                    ev.object_name, ev.property, value_user
                )

                status_a, _ta, _ja = self._send_request(
                    method, test_path, headers_admin, payload_admin
                )
                admin_persisted = self._read_back(ev.object_name, ev.property, value_admin)
                status_u, _tu, _ju = self._send_request(
                    method, test_path, headers_user, payload_user
                )
                user_persisted = (
                    self._read_back(ev.object_name, ev.property, value_user)
                    if status_u and 200 <= status_u < 300
                    else None
                )

                if status_a is None and status_u is None:
                    continue  # no response at all: nothing was tested, nothing to record
                evidence = [
                    f"Analisi differenziale di scrittura su {method} {test_path}, proprietà '{ev.property}'.",
                    f"Amministratore: stato {status_a}, valore {'persistito' if admin_persisted else 'non persistito'}.",
                    f"Utente standard: stato {status_u}, valore {'persistito' if user_persisted else 'non persistito'}.",
                ]
                findings.append(
                    DynamicPropertyFinding(
                        test_id="T07",
                        endpoint=test_path,
                        method=method,
                        property_name=ev.property,
                        evidence=evidence,
                        request=f"Payload Admin: {payload_admin}\nPayload User: {payload_user}",
                        response=f"Admin Status: {status_a}, User Status: {status_u}",
                        response_code=status_u,
                        verified=bool(user_persisted),
                        confidence=ev.confidence,
                    )
                )
        return findings
