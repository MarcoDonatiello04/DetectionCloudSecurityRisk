"""
Broken Authentication - Dynamic Tester Module (Fase 4).
Runs dynamic security tests against the running application to identify broken authentication vulnerabilities.
"""

import re
import json
import base64
import httpx
import asyncio
from typing import List, Dict, Any, Optional, Tuple
from pydantic import BaseModel
from loguru import logger

from src.core.broken_authentication.discovery import StackInfo, Config, VulnerabilityCategory
from src.core.broken_authentication.authentication_intelligence import AuthenticationKnowledgeGraph

# --- Custom Exceptions ---
class EndpointNotFoundException(Exception):
    """Raised when the authentication endpoint cannot be found."""
    pass

class HealthCheckException(Exception):
    """Raised when the target application is unreachable or returns server errors during health checks."""
    pass

# --- Pydantic Models ---
class Vulnerabilita(BaseModel):
    id: str
    tipo: str
    descrizione: str
    file: str
    linea: int
    route_auth: List[str] = []
    category: Optional[VulnerabilityCategory] = None
    dettagli: Optional[Dict[str, Any]] = None

class RisultatoTest(BaseModel):
    test_id: str
    nome: str
    stato: str  # "PASS" | "FAIL"
    severita: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    dettagli: str
    category: Optional[VulnerabilityCategory] = None
    dettagli_quantitativi: Optional[Dict[str, Any]] = None

# --- JWT Base64 Helpers ---
def base64url_decode(payload: str) -> dict:
    rem = len(payload) % 4
    if rem > 0:
        payload += "=" * (4 - rem)
    decoded = base64.urlsafe_b64decode(payload.encode('utf-8'))
    return json.loads(decoded.decode('utf-8'))

def base64url_encode(data: dict) -> str:
    serialized = json.dumps(data, separators=(',', ':'))
    encoded = base64.urlsafe_b64encode(serialized.encode('utf-8'))
    return encoded.decode('utf-8').rstrip('=')

# --- Helper to extract path from a route string (e.g. from tree-sitter output) ---
def _extract_path_from_route_string(route_str: str) -> Optional[str]:
    matches = re.findall(r'["\']([^"\']+)["\']', route_str)
    if matches:
        for m in matches:
            if m.startswith("/") or "/" in m:
                return m
    return None

# --- DynamicTester Class ---
class DynamicTester:
    def __init__(
        self, 
        config: Config, 
        client: Optional[httpx.AsyncClient] = None, 
        auth_intel: Optional[AuthenticationKnowledgeGraph] = None,
        target_environment: str = "staging",
        allow_destructive_tests: bool = False,
        rate_limit_delay: float = 0.0,
        confidence_threshold: float = 0.4,
        openapi_spec: Optional[Dict[str, Any]] = None
    ):
        self.config = config
        self._client = client
        self.auth_intel = auth_intel
        self.target_environment = target_environment
        self.allow_destructive_tests = allow_destructive_tests
        self.rate_limit_delay = rate_limit_delay
        self.confidence_threshold = confidence_threshold
        self.openapi_spec = openapi_spec
        
        self.endpoint_auth: Optional[str] = None
        self.endpoint_logout: Optional[str] = None
        self.endpoint_refresh: Optional[str] = None
        self.endpoint_reset: Optional[str] = None
        self.endpoint_mfa: Optional[str] = None
        self.tipo_token: str = "jwt"
        self.header_token: str = "Authorization"
        self.request_audit_log: List[Dict[str, Any]] = []
        self.auth_strategy: Optional[str] = None

    def _wrap_client_methods(self, client: httpx.AsyncClient):
        if hasattr(client, "_wrapped_for_audit"):
            return
        client._wrapped_for_audit = True
        
        original_get = client.get
        original_post = client.post
        
        async def wrapped_get(url, *args, **kwargs):
            if self.rate_limit_delay > 0:
                await asyncio.sleep(self.rate_limit_delay)
            self.request_audit_log.append({
                "method": "GET",
                "url": str(url),
                "headers": {k: str(v) for k, v in kwargs.get("headers", {}).items()} if kwargs.get("headers") else {}
            })
            return await original_get(url, *args, **kwargs)
            
        async def wrapped_post(url, *args, **kwargs):
            if self.rate_limit_delay > 0:
                await asyncio.sleep(self.rate_limit_delay)
            self.request_audit_log.append({
                "method": "POST",
                "url": str(url),
                "headers": {k: str(v) for k, v in kwargs.get("headers", {}).items()} if kwargs.get("headers") else {},
                "json": kwargs.get("json")
            })
            return await original_post(url, *args, **kwargs)
            
        client.get = wrapped_get
        client.post = wrapped_post

    def _get_client(self) -> httpx.AsyncClient:
        """Returns the injected client or initializes a new one with config settings."""
        if self._client:
            self._wrap_client_methods(self._client)
            return self._client
        c = httpx.AsyncClient(
            base_url=self.config.target.base_url,
            timeout=self.config.scanner.timeout_http
        )
        self._wrap_client_methods(c)
        return c

    async def health_check(self) -> None:
        """
        Verifies if the application responds on / or /health with status < 500.
        Retries every 2 seconds up to config.docker.timeout_startup seconds.
        """
        base_url = self.config.target.base_url
        timeout = self.config.docker.timeout_startup
        logger.info(f"Avvio Health Check su {base_url} (timeout: {timeout}s)...")

        # Injected client might have its own base_url, use it if present
        url_paths = ["/", "/health"]
        
        start_time = asyncio.get_event_loop().time()
        client = self._get_client()

        while True:
            for path in url_paths:
                try:
                    # If client has a base_url, path is relative, otherwise absolute
                    url = path if client.base_url and str(client.base_url) != "http://localhost" else f"{base_url.rstrip('/')}{path}"
                    logger.debug(f"Tentativo di connessione a {url}...")
                    response = await client.get(url)
                    if response.status_code < 500:
                        logger.info(f"Health check superato con successo su {url} (status: {response.status_code})")
                        return
                except Exception as e:
                    logger.debug(f"Tentativo fallito su {path}: {e}")

            if asyncio.get_event_loop().time() - start_time >= timeout:
                break

            await asyncio.sleep(2)

        raise HealthCheckException(f"L'applicazione su {base_url} non è raggiungibile o restituisce errori 500 dopo {timeout}s.")

    async def discover_endpoints(self, stack: StackInfo, vulnerabilities: List[Vulnerabilita]) -> None:
        """
        Discovers authentication-related endpoints using Swagger/OpenAPI docs or fallbacks.
        """
        client = self._get_client()
        
        # Populate from Authentication Intelligence first if available
        if self.auth_intel:
            logger.info("Utilizzo informazioni da Authentication Intelligence Engine per endpoints...")
            if self.auth_intel.login_endpoint:
                self.endpoint_auth = self.auth_intel.login_endpoint
            if self.auth_intel.logout_endpoint:
                self.endpoint_logout = self.auth_intel.logout_endpoint
            if self.auth_intel.refresh_endpoint:
                self.endpoint_refresh = self.auth_intel.refresh_endpoint
            if self.auth_intel.authentication_type:
                auth_type_lower = self.auth_intel.authentication_type.lower()
                if "jwt" in auth_type_lower or "oauth" in auth_type_lower:
                    self.tipo_token = "jwt"
                    self.header_token = "Authorization"
                elif "session" in auth_type_lower or "cookie" in auth_type_lower:
                    self.tipo_token = "session_cookie"
                    self.header_token = "Cookie"
                else:
                    self.tipo_token = "opaque"
                    self.header_token = "X-Auth-Token"

        # Search OpenAPI and extract endpoints always if specs are available or fetched (A.3)
        openapi_paths_data = None
        
        # If openapi_spec is already set/injected, use it
        if self.openapi_spec:
            logger.info("Utilizzo specifiche OpenAPI iniettate in DynamicTester...")
            openapi_paths_data = self.openapi_spec.get("paths", {})
        else:
            doc_paths = ["/openapi.json", "/docs/openapi.json", "/swagger.json", "/api-docs"]
            logger.info("Avvio recupero endpoint reali tramite documentazione API...")
            discovered = False
            for path in doc_paths:
                try:
                    url = path if client.base_url and str(client.base_url) != "http://localhost" else f"{self.config.target.base_url.rstrip('/')}{path}"
                    response = await client.get(url)
                    if response.status_code == 200:
                        data = response.json()
                        self.openapi_spec = data
                        openapi_paths_data = data.get("paths", {})
                        if openapi_paths_data:
                            logger.info(f"Documentazione API trovata su {url}. Estrazione endpoint...")
                            discovered = True
                            break
                except Exception as e:
                    logger.debug(f"Impossibile leggere documentazione da {path}: {e}")

        if openapi_paths_data:
            self._parse_openapi_paths(openapi_paths_data)

        # Fallback Strategy: use route_auth from Fase 2 if login is still missing
        if not self.endpoint_auth:
            logger.info("Endpoint di login assente. Utilizzo dei fallback di Fase 2...")
            self._apply_fallback_routes(vulnerabilities)

        if not self.endpoint_auth:
            raise EndpointNotFoundException("Endpoint di autenticazione principale non trovato.")

        # Determine token type & header if not already set by auth_intel
        if not self.auth_intel or not self.auth_intel.authentication_type:
            auth_libs_lower = [lib.lower() for lib in stack.librerie_auth]
            if any(kw in "".join(auth_libs_lower) for kw in ["jwt", "jose", "oauth"]):
                self.tipo_token = "jwt"
                self.header_token = "Authorization"
            elif any(kw in "".join(auth_libs_lower) for kw in ["cookie", "session"]):
                self.tipo_token = "session_cookie"
                self.header_token = "Cookie"
            else:
                self.tipo_token = "opaque"
                self.header_token = "X-Auth-Token"

        logger.info(f"Endpoint Auth Rilevato: {self.endpoint_auth}")
        logger.info(f"Endpoint Logout Rilevato: {self.endpoint_logout}")
        logger.info(f"Endpoint Refresh Rilevato: {self.endpoint_refresh}")
        logger.info(f"Endpoint Reset Rilevato: {self.endpoint_reset}")
        logger.info(f"Endpoint MFA Rilevato: {self.endpoint_mfa}")
        logger.info(f"Configurazione Client: Tipo Token={self.tipo_token}, Header={self.header_token}")

    def _parse_openapi_paths(self, paths: Dict[str, Any]) -> None:
        for path in paths.keys():
            path_lower = path.lower()
            if any(kw in path_lower for kw in ["login", "token", "signin"]):
                if not self.endpoint_auth:
                    self.endpoint_auth = path
                elif "login" in path_lower and "with-token" not in path_lower:
                    if "with-token" in self.endpoint_auth.lower() or len(path) < len(self.endpoint_auth):
                        self.endpoint_auth = path
            if any(kw in path_lower for kw in ["logout", "signout"]):
                if not self.endpoint_logout:
                    self.endpoint_logout = path
            if "refresh" in path_lower:
                if not self.endpoint_refresh:
                    self.endpoint_refresh = path
            if any(kw in path_lower for kw in ["reset", "password"]):
                if not self.endpoint_reset:
                    self.endpoint_reset = path
            if any(kw in path_lower for kw in ["mfa", "2fa", "otp", "totp", "verify-mfa"]):
                if not self.endpoint_mfa:
                    self.endpoint_mfa = path

    def _apply_fallback_routes(self, vulnerabilities: List[Vulnerabilita]) -> None:
        for vuln in vulnerabilities:
            for route in vuln.route_auth:
                path = _extract_path_from_route_string(route)
                if path:
                    path_lower = path.lower()
                    if any(kw in path_lower for kw in ["login", "token", "signin"]):
                        if not self.endpoint_auth or "login" in path_lower:
                            self.endpoint_auth = path
                    if any(kw in path_lower for kw in ["logout", "signout"]):
                        self.endpoint_logout = path
                    if "refresh" in path_lower:
                        self.endpoint_refresh = path
                    if any(kw in path_lower for kw in ["reset", "password"]):
                        self.endpoint_reset = path
                    if any(kw in path_lower for kw in ["mfa", "2fa", "otp", "totp", "verify-mfa"]):
                        self.endpoint_mfa = path

    def _resolve_schema(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(schema, dict):
            return {}
        if "$ref" in schema:
            ref = schema["$ref"]
            parts = ref.split("/")
            ref_name = parts[-1]
            if self.openapi_spec:
                ref_schema = self.openapi_spec.get("components", {}).get("schemas", {}).get(ref_name)
                if ref_schema:
                    return self._resolve_schema(ref_schema)
        return schema

    def _extract_token_from_response(self, res: httpx.Response) -> Optional[str]:
        try:
            data = res.json()
            for key in ["access_token", "token", "jwt", "accessToken"]:
                if key in data:
                    return data[key]
        except Exception:
            pass
        auth_header = res.headers.get("Authorization") or res.headers.get("X-Auth-Token")
        if auth_header:
            return auth_header.replace("Bearer ", "").strip()
        cookie = res.headers.get("Set-Cookie")
        if cookie:
            return cookie.split(";")[0].strip()
        return None

    def _extract_refresh_token_from_response(self, res: httpx.Response) -> Optional[str]:
        try:
            data = res.json()
            for key in ["refresh_token", "refreshToken"]:
                if key in data:
                    return data[key]
        except Exception:
            pass
        cookie = res.headers.get("Set-Cookie")
        if cookie and "refresh" in cookie.lower():
            return cookie.split(";")[0].strip()
        return None

    async def _login_and_get_tokens(self, client: httpx.AsyncClient) -> Tuple[Optional[str], Optional[str]]:
        """Helper to login and retrieve both access and refresh tokens."""
        if not self.endpoint_auth:
            return None, None

        # Try schema-driven first
        username_key = None
        password_key = None
        schema_found = False

        if self.openapi_spec:
            try:
                paths = self.openapi_spec.get("paths", {})
                path_info = paths.get(self.endpoint_auth)
                if not path_info:
                    for p, info in paths.items():
                        if p.lower().rstrip('/') == self.endpoint_auth.lower().rstrip('/'):
                            path_info = info
                            break
                if path_info:
                    post_op = path_info.get("post") or path_info.get("POST")
                    if post_op:
                        request_body = post_op.get("requestBody", {})
                        content = request_body.get("content", {})
                        json_content = content.get("application/json", {})
                        schema = json_content.get("schema", {})
                        resolved = self._resolve_schema(schema)
                        properties = resolved.get("properties", {})
                        if properties:
                            schema_found = True
                            for key in properties.keys():
                                k_low = key.lower()
                                if any(alias in k_low for alias in ["email", "username", "user", "login"]):
                                    if not username_key or "email" in k_low or "username" in k_low:
                                        username_key = key
                                if "password" in k_low or "passwd" in k_low:
                                    password_key = key
            except Exception as e:
                logger.debug(f"Errore durante l'analisi dello schema OpenAPI per il login: {e}")

        # If schema-derived fields found, use them
        if schema_found and username_key and password_key:
            payload = {
                username_key: self.config.target.username,
                password_key: self.config.target.password
            }
            try:
                res = await client.post(self.endpoint_auth, json=payload)
                if res.status_code in (200, 201):
                    self.auth_strategy = "schema-derived"
                    return self._extract_token_from_response(res), self._extract_refresh_token_from_response(res)
            except Exception as e:
                logger.debug(f"Errore login schema-derived: {e}")

        # Fallback sequence of aliases
        username_aliases = ["username", "email", "user", "login"]
        password_aliases = ["password", "passwd"]

        attempt = 0
        for u_alias in username_aliases:
            for p_alias in password_aliases:
                attempt += 1
                payload = {
                    u_alias: self.config.target.username,
                    p_alias: self.config.target.password
                }
                try:
                    res = await client.post(self.endpoint_auth, json=payload)
                    if res.status_code in (200, 201):
                        self.auth_strategy = f"alias-fallback-{attempt}"
                        return self._extract_token_from_response(res), self._extract_refresh_token_from_response(res)
                except Exception as e:
                    logger.debug(f"Errore login alias-fallback: {e}")

        return None, None

    async def _login_and_get_token(self, client: httpx.AsyncClient) -> Optional[str]:
        """Helper to login and retrieve token using adaptive credentials resolution (A.2)."""
        if not self.endpoint_auth:
            return None

        # Try schema-driven first
        username_key = None
        password_key = None
        schema_found = False

        if self.openapi_spec:
            try:
                paths = self.openapi_spec.get("paths", {})
                path_info = paths.get(self.endpoint_auth)
                if not path_info:
                    for p, info in paths.items():
                        if p.lower().rstrip('/') == self.endpoint_auth.lower().rstrip('/'):
                            path_info = info
                            break
                if path_info:
                    post_op = path_info.get("post") or path_info.get("POST")
                    if post_op:
                        request_body = post_op.get("requestBody", {})
                        content = request_body.get("content", {})
                        json_content = content.get("application/json", {})
                        schema = json_content.get("schema", {})
                        resolved = self._resolve_schema(schema)
                        properties = resolved.get("properties", {})
                        if properties:
                            schema_found = True
                            for key in properties.keys():
                                k_low = key.lower()
                                if any(alias in k_low for alias in ["email", "username", "user", "login"]):
                                    if not username_key or "email" in k_low or "username" in k_low:
                                        username_key = key
                                if "password" in k_low or "passwd" in k_low:
                                    password_key = key
            except Exception as e:
                logger.debug(f"Errore durante l'analisi dello schema OpenAPI per il login: {e}")

        # If schema-derived fields found, use them
        if schema_found and username_key and password_key:
            payload = {
                username_key: self.config.target.username,
                password_key: self.config.target.password
            }
            try:
                res = await client.post(self.endpoint_auth, json=payload)
                if res.status_code in (200, 201, 401, 403):
                    self.auth_strategy = "schema-derived"
                    logger.info(f"Strategia di autenticazione riuscita: schema-derived usando chiavi ({username_key}, {password_key})")
                    if res.status_code in (200, 201):
                        return self._extract_token_from_response(res)
                    else:
                        # Structurally accepted but credentials rejected (e.g. 401/403)
                        return None
            except Exception as e:
                logger.debug(f"Errore login schema-derived: {e}")

        # Fallback sequence of aliases
        username_aliases = ["username", "email", "user", "login"]
        password_aliases = ["password", "passwd"]

        attempt = 0
        for u_alias in username_aliases:
            for p_alias in password_aliases:
                attempt += 1
                payload = {
                    u_alias: self.config.target.username,
                    p_alias: self.config.target.password
                }
                try:
                    res = await client.post(self.endpoint_auth, json=payload)
                    if res.status_code in (200, 201, 401, 403):
                        self.auth_strategy = f"alias-fallback-{attempt}"
                        logger.info(f"Strategia di autenticazione riuscita: alias-fallback-{attempt} usando chiavi ({u_alias}, {p_alias})")
                        if res.status_code in (200, 201):
                            return self._extract_token_from_response(res)
                        else:
                            return None
                except Exception as e:
                    logger.debug(f"Errore login alias-fallback: {e}")

        return None

    # --- T01 - JWT Manipulation ---
    async def _test_t01_jwt_manipulation(self) -> RisultatoTest:
        client = self._get_client()
        token = await self._login_and_get_token(client)
        if not token or self.tipo_token != "jwt":
            return RisultatoTest(
                test_id="T01",
                nome="Manipolazione JWT",
                stato="INCONCLUSIVE",
                severita="INFO",
                dettagli="Token non presente o non JWT, test ignorato."
            )

        parts = token.split(".")
        if len(parts) != 3:
            return RisultatoTest(
                test_id="T01",
                nome="Manipolazione JWT",
                stato="INCONCLUSIVE",
                severita="INFO",
                dettagli="Il token non ha una struttura JWT valida."
            )

        try:
            header = base64url_decode(parts[0])
            payload = base64url_decode(parts[1])

            # Leverage discovered issuer and claims
            if self.auth_intel:
                if self.auth_intel.idp_metadata and "issuer" in self.auth_intel.idp_metadata:
                    payload["iss"] = self.auth_intel.idp_metadata["issuer"]
                for claim in self.auth_intel.jwt_claims:
                    if claim not in payload:
                        payload[claim] = "test-value"

            # Manipolation 1: alg = "none"
            header_none = header.copy()
            header_none["alg"] = "none"
            manipulated_token_none = base64url_encode(header_none) + "." + base64url_encode(payload) + "."

            # Send request
            headers = {self.header_token: f"Bearer {manipulated_token_none}"}
            # Test request to auth endpoint or generic protected path
            test_path = "/api/profile" if not client.base_url else "api/profile"
            res = await client.get(test_path, headers=headers)
            if res.status_code == 200:
                return RisultatoTest(
                    test_id="T01",
                    nome="Manipolazione JWT",
                    stato="FAIL",
                    severita="CRITICAL",
                    dettagli="L'applicazione accetta token con algoritmo 'none'."
                )

            # Manipolation 2: Signature tamper
            tampered_token = token + "modified"
            headers_tamper = {self.header_token: f"Bearer {tampered_token}"}
            res_tamper = await client.get(test_path, headers=headers_tamper)
            if res_tamper.status_code == 200:
                return RisultatoTest(
                    test_id="T01",
                    nome="Manipolazione JWT",
                    stato="FAIL",
                    severita="CRITICAL",
                    dettagli="L'applicazione accetta token con firma alterata."
                )

            return RisultatoTest(
                test_id="T01",
                nome="Manipolazione JWT",
                stato="PASS",
                severita="INFO",
                dettagli="I token modificati o con algoritmo 'none' sono correttamente rifiutati."
            )
        except Exception as e:
            return RisultatoTest(
                test_id="T01",
                nome="Manipolazione JWT",
                stato="FAIL",
                severita="HIGH",
                dettagli=f"Eccezione inattesa durante il test: {e}"
            )

    # --- T02 - Token scaduto ---
    async def _test_t02_expired_token(self) -> RisultatoTest:
        """
        Tests whether the application accepts tokens with a past expiry date.

        Strategy
        --------
        1. Attempt a real login to obtain a valid token whose header/payload
           structure we can inspect.
        2. Re-sign a copy of that payload with exp=1 using the known JWT secret
           (extracted from auth_intel if available) so the signature is
           cryptographically valid — only the exp claim is modified.
        3. If no secret is known and we could not log in, fall back to
           INCONCLUSIVE with an explicit explanation: the test cannot reach
           the expiry-verification logic without a valid signature.

        Rationale
        ---------
        Using a deliberately invalid signature ('invalidsignature') fails before
        the server ever checks exp, so PASS would never mean 'exp is verified'
        but merely 'signature is verified' — which is a different test entirely.
        """
        import hmac
        import hashlib

        client = self._get_client()

        # --- Step 1: obtain a real token via login (if possible) ---
        real_token = None
        jwt_secret = None

        # Try to get the JWT secret from auth_intel metadata
        if self.auth_intel and hasattr(self.auth_intel, "jwt_secret"):
            jwt_secret = getattr(self.auth_intel, "jwt_secret", None)

        try:
            real_token = await self._login_and_get_token(client)
        except Exception:
            pass

        if not real_token and not jwt_secret:
            return RisultatoTest(
                test_id="T02",
                nome="Token scaduto",
                stato="INCONCLUSIVE",
                severita="INFO",
                dettagli=(
                    "Impossibile costruire un token scaduto con firma valida: "
                    "login fallito e segreto JWT non disponibile. "
                    "Il test non è attendibile con una firma invalida — il server "
                    "rifiuterebbe per firma errata prima di controllare exp."
                )
            )

        try:
            # --- Step 2: build an expired payload ---
            if real_token:
                parts = real_token.split(".")
                if len(parts) != 3:
                    raise ValueError(f"Token malformato: {len(parts)} parti")
                orig_payload = base64url_decode(parts[1])
            else:
                # Construct a minimal payload if we only have the secret
                orig_payload = {
                    "sub": self.config.target.username or "testuser",
                    "role": "user",
                }

            # Override exp to Unix epoch 1 (effectively expired since 1970)
            orig_payload["exp"] = 1
            orig_payload["iat"] = 1

            encoded_header  = base64url_encode({"alg": "HS256", "typ": "JWT"})
            encoded_payload = base64url_encode(orig_payload)
            signing_input   = f"{encoded_header}.{encoded_payload}".encode("ascii")

            # Re-sign with the known secret (HMAC-SHA256)
            if jwt_secret:
                secret_bytes = jwt_secret.encode("utf-8") if isinstance(jwt_secret, str) else jwt_secret
            else:
                # No secret available — we cannot produce a valid signature.
                return RisultatoTest(
                    test_id="T02",
                    nome="Token scaduto",
                    stato="INCONCLUSIVE",
                    severita="INFO",
                    dettagli=(
                        "Impossibile costruire un token scaduto con firma valida: "
                        "segreto JWT non disponibile in auth_intel. "
                        "Il test non è attendibile con una firma invalida."
                    )
                )

            raw_signature = hmac.new(secret_bytes, signing_input, hashlib.sha256).digest()
            import base64
            b64_sig = base64.urlsafe_b64encode(raw_signature).decode("ascii").rstrip("=")
            expired_token = f"{encoded_header}.{encoded_payload}.{b64_sig}"

            # --- Step 3: send the expired but validly-signed token ---
            headers = {self.header_token: f"Bearer {expired_token}"}
            test_path = "/api/profile" if not client.base_url else "api/profile"
            res = await client.get(test_path, headers=headers)

            if res.status_code == 200:
                return RisultatoTest(
                    test_id="T02",
                    nome="Token scaduto",
                    stato="FAIL",
                    severita="HIGH",
                    dettagli="L'applicazione accetta token scaduti (firma valida, exp=1)."
                )
            return RisultatoTest(
                test_id="T02",
                nome="Token scaduto",
                stato="PASS",
                severita="INFO",
                dettagli="Il token scaduto è stato correttamente rifiutato."
            )
        except Exception as e:
            return RisultatoTest(
                test_id="T02",
                nome="Token scaduto",
                stato="INCONCLUSIVE",
                severita="INFO",
                dettagli=f"Errore durante la costruzione del token scaduto: {e}"
            )

    # --- T03 - Brute Force e Rate Limiting ---
    async def _test_t03_brute_force_rate_limiting(self) -> RisultatoTest:
        if self.target_environment == "production" and not self.allow_destructive_tests:
            logger.warning("Test T03 (brute-force) saltato per target in ambiente di produzione.")
            return RisultatoTest(
                test_id="T03",
                nome="Brute Force e Rate Limiting",
                stato="SKIPPED",
                severita="INFO",
                dettagli="Test bruteforce disabilitato in ambiente di produzione per sicurezza.",
                category=VulnerabilityCategory.AUTHENTICATION
            )
        client = self._get_client()
        if not self.endpoint_auth:
            return RisultatoTest(
                test_id="T03",
                nome="Brute Force e Rate Limiting",
                stato="INCONCLUSIVE",
                severita="INFO",
                dettagli="Endpoint auth non disponibile.",
                category=VulnerabilityCategory.AUTHENTICATION
            )
        try:
            payload = {"username": "wronguser", "password": "wrongpassword"}
            attempts_before_block = 0
            block_duration_seconds = 0
            ip_spoof_bypass = False
            triggered_429 = False

            # Invia richieste iterative fino a un massimo di 50 per misurare la soglia
            for i in range(1, 51):
                res = await client.post(self.endpoint_auth, json=payload)
                if res.status_code == 429:
                    triggered_429 = True
                    attempts_before_block = i - 1
                    
                    # Cerca l'header Retry-After
                    retry_after = res.headers.get("Retry-After")
                    if retry_after:
                        try:
                            block_duration_seconds = int(retry_after)
                        except ValueError:
                            # Se non è intero (es. data), impostiamo a 60 secondi
                            block_duration_seconds = 60
                    else:
                        block_duration_seconds = 60 # Valore stimato di default
                    
                    # Test bypass via IP Spoofing
                    spoofed_headers = {"X-Forwarded-For": f"198.51.100.{i + 10}"}
                    res_spoof = await client.post(self.endpoint_auth, json=payload, headers=spoofed_headers)
                    if res_spoof.status_code != 429:
                        ip_spoof_bypass = True
                    break
            
            # Se è stato rilevato il blocco 429
            if triggered_429:
                if self.auth_intel:
                    self.auth_intel.rate_limiting_detected = True
                    self.auth_intel.rate_limit_threshold = attempts_before_block
                
                details_quant = {
                    "attempts_before_block": attempts_before_block,
                    "block_duration_seconds": block_duration_seconds,
                    "ip_spoof_bypass": ip_spoof_bypass
                }
                
                dettagli_msg = (
                    f"Rilevato blocco di sicurezza (status 429) dopo {attempts_before_block} tentativi falliti. "
                    f"Durata blocco: {block_duration_seconds}s. Bypass via IP spoofing: {ip_spoof_bypass}."
                )
                
                if ip_spoof_bypass:
                    return RisultatoTest(
                        test_id="T03",
                        nome="Brute Force e Rate Limiting",
                        stato="FAIL",
                        severita="HIGH",
                        dettagli=dettagli_msg + " Rischio di bypass del rate limit.",
                        category=VulnerabilityCategory.AUTHENTICATION,
                        dettagli_quantitativi=details_quant
                    )
                else:
                    return RisultatoTest(
                        test_id="T03",
                        nome="Brute Force e Rate Limiting",
                        stato="PASS",
                        severita="INFO",
                        dettagli=dettagli_msg,
                        category=VulnerabilityCategory.AUTHENTICATION,
                        dettagli_quantitativi=details_quant
                    )
            
            # Se non c'è stato alcun blocco dopo 50 richieste
            if self.auth_intel:
                self.auth_intel.rate_limiting_detected = False
                
            details_quant = {
                "attempts_before_block": 50,
                "block_duration_seconds": None,
                "ip_spoof_bypass": False
            }
            return RisultatoTest(
                test_id="T03",
                nome="Brute Force e Rate Limiting",
                stato="FAIL",
                severita="MEDIUM",
                dettagli="Nessun meccanismo di rate limiting rilevato dopo 50 tentativi falliti.",
                category=VulnerabilityCategory.AUTHENTICATION,
                dettagli_quantitativi=details_quant
            )
        except Exception as e:
            return RisultatoTest(
                test_id="T03",
                nome="Brute Force e Rate Limiting",
                stato="FAIL",
                severita="HIGH",
                dettagli=f"Eccezione inattesa durante il test: {e}",
                category=VulnerabilityCategory.AUTHENTICATION
            )

    # --- T04 - Token Replay su endpoint diversi ---
    async def _test_t04_token_replay(self) -> RisultatoTest:
        if self.auth_intel and self.auth_intel.confidence_score < self.confidence_threshold:
            logger.warning(f"Test T04 saltato per basso confidence score: {self.auth_intel.confidence_score} < {self.confidence_threshold}")
            return RisultatoTest(
                test_id="T04",
                nome="Token Replay su endpoint diversi",
                stato="SKIPPED",
                severita="INFO",
                dettagli=f"Test skippato a causa del basso confidence score ({self.auth_intel.confidence_score} < {self.confidence_threshold})."
            )
        client = self._get_client()
        token = await self._login_and_get_token(client)
        if not token or self.tipo_token != "jwt":
            return RisultatoTest(
                test_id="T04",
                nome="Token Replay su endpoint diversi",
                stato="INCONCLUSIVE",
                severita="INFO",
                dettagli="Token non presente o non JWT, test ignorato."
            )
        try:
            parts = token.split(".")
            if len(parts) == 3:
                header = base64url_decode(parts[0])
                payload = base64url_decode(parts[1])
                
                payload_tampered = payload.copy()
                payload_tampered["aud"] = "different_audience"
                payload_tampered["client_id"] = "different_client"
                
                tampered_token = base64url_encode(header) + "." + base64url_encode(payload_tampered) + "."
                headers = {self.header_token: f"Bearer {tampered_token}"}
                
                test_path = "/api/profile" if not client.base_url else "api/profile"
                res = await client.get(test_path, headers=headers)
                if res.status_code == 200:
                    return RisultatoTest(
                        test_id="T04",
                        nome="Token Replay su endpoint diversi",
                        stato="FAIL",
                        severita="HIGH",
                        dettagli="L'endpoint accetta token emessi per audience/client differente."
                    )
            return RisultatoTest(
                test_id="T04",
                nome="Token Replay su endpoint diversi",
                stato="PASS",
                severita="INFO",
                dettagli="Token con audience differente correttamente rifiutati."
            )
        except Exception as e:
            return RisultatoTest(
                test_id="T04",
                nome="Token Replay su endpoint diversi",
                stato="FAIL",
                severita="HIGH",
                dettagli=f"Eccezione inattesa: {e}"
            )

    # --- T05 - Riuso Token Post-Logout ---
    async def _test_t05_token_reuse_post_logout(self) -> RisultatoTest:
        client = self._get_client()
        if not self.endpoint_logout:
            return RisultatoTest(
                test_id="T05",
                nome="Riuso Token Post-Logout",
                stato="INCONCLUSIVE",
                severita="INFO",
                dettagli="Endpoint logout non rilevato, impossibile eseguire il test."
            )
        try:
            token = await self._login_and_get_token(client)
            if not token:
                return RisultatoTest(
                    test_id="T05",
                    nome="Riuso Token Post-Logout",
                    stato="INCONCLUSIVE",
                    severita="INFO",
                    dettagli="Impossibile ottenere un token valido per il test."
                )

            headers = {self.header_token: f"Bearer {token}"}
            # Perform logout
            await client.post(self.endpoint_logout, headers=headers)

            # Try to reuse the token
            test_path = "/api/profile" if not client.base_url else "api/profile"
            res = await client.get(test_path, headers=headers)
            if res.status_code == 200:
                return RisultatoTest(
                    test_id="T05",
                    nome="Riuso Token Post-Logout",
                    stato="FAIL",
                    severita="HIGH",
                    dettagli="Il token è riutilizzabile anche dopo la chiamata di logout."
                )

            return RisultatoTest(
                test_id="T05",
                nome="Riuso Token Post-Logout",
                stato="PASS",
                severita="INFO",
                dettagli="Il token è correttamente invalidato post logout."
            )
        except Exception as e:
            return RisultatoTest(
                test_id="T05",
                nome="Riuso Token Post-Logout",
                stato="FAIL",
                severita="HIGH",
                dettagli=f"Eccezione inattesa: {e}"
            )

    # --- T06 - Session Fixation ---
    async def _test_t06_session_fixation(self) -> RisultatoTest:
        client = self._get_client()
        if not self.endpoint_auth:
            return RisultatoTest(
                test_id="T06",
                nome="Session Fixation",
                stato="INCONCLUSIVE",
                severita="INFO",
                dettagli="Endpoint auth non disponibile."
            )
        try:
            # --- Step 1: obtain a pre-login session cookie ---
            # Try multiple paths that are likely to initialise a server-side
            # session before the user authenticates.
            session1 = None
            pre_login_paths = ["/", "/api/admin", "/api/profile"]
            for probe_path in pre_login_paths:
                try:
                    res_probe = await client.get(probe_path)
                    cookie_probe = res_probe.headers.get("Set-Cookie")
                    if cookie_probe:
                        session1 = cookie_probe.split(";")[0].split("=", 1)[-1]
                        logger.debug(f"[T06] Pre-login session cookie trovato su {probe_path}: {session1[:20]}...")
                        break
                except Exception as probe_err:
                    logger.debug(f"[T06] Probe {probe_path} fallita: {probe_err}")

            # GUARD: if no pre-login cookie exists the comparison is meaningless.
            # session1=None vs session2=<value> would incorrectly look like
            # 'regenerated' when in reality there was nothing to compare.
            if session1 is None:
                return RisultatoTest(
                    test_id="T06",
                    nome="Session Fixation",
                    stato="INCONCLUSIVE",
                    severita="INFO",
                    dettagli=(
                        "Impossibile ottenere un cookie di sessione prima del login. "
                        "L'applicazione potrebbe usare sessioni client-side (cookie firmati) "
                        "che non vengono emessi finché la sessione non viene scritta — "
                        "il test di session fixation non è eseguibile in questa configurazione."
                    )
                )

            # --- Step 2: login and collect post-login session cookie ---
            payload = {
                "username": self.config.target.username,
                "password": self.config.target.password
            }
            res2 = await client.post(self.endpoint_auth, json=payload)
            session2 = None
            cookie2 = res2.headers.get("Set-Cookie")
            if cookie2:
                session2 = cookie2.split(";")[0].split("=", 1)[-1]

            # GUARD: if the login response sets no cookie either, INCONCLUSIVE.
            if session2 is None:
                return RisultatoTest(
                    test_id="T06",
                    nome="Session Fixation",
                    stato="INCONCLUSIVE",
                    severita="INFO",
                    dettagli=(
                        "Il login non ha impostato alcun cookie di sessione nella risposta. "
                        "Impossibile confrontare gli identificatori pre/post login."
                    )
                )

            # --- Step 3: compare ---
            if session1 == session2:
                return RisultatoTest(
                    test_id="T06",
                    nome="Session Fixation",
                    stato="FAIL",
                    severita="HIGH",
                    dettagli="La sessione non viene rigenerata dopo il login."
                )
            return RisultatoTest(
                test_id="T06",
                nome="Session Fixation",
                stato="PASS",
                severita="INFO",
                dettagli="L'identificativo di sessione viene correttamente rigenerato al login."
            )
        except Exception as e:
            return RisultatoTest(
                test_id="T06",
                nome="Session Fixation",
                stato="FAIL",
                severita="HIGH",
                dettagli=f"Eccezione inattesa: {e}"
            )

    # --- T07 - Key Confusion (RS256 -> HS256) ---
    async def _test_t07_key_confusion(self) -> RisultatoTest:
        if self.auth_intel and self.auth_intel.confidence_score < self.confidence_threshold:
            logger.warning(f"Test T07 saltato per basso confidence score: {self.auth_intel.confidence_score} < {self.confidence_threshold}")
            return RisultatoTest(
                test_id="T07",
                nome="Key Confusion (RS256 -> HS256)",
                stato="SKIPPED",
                severita="INFO",
                dettagli=f"Test skippato a causa del basso confidence score ({self.auth_intel.confidence_score} < {self.confidence_threshold})."
            )
        client = self._get_client()
        token = await self._login_and_get_token(client)
        if not token or self.tipo_token != "jwt":
            return RisultatoTest(
                test_id="T07",
                nome="Key Confusion (RS256 -> HS256)",
                stato="INCONCLUSIVE",
                severita="INFO",
                dettagli="Token non presente o non JWT, test ignorato."
            )
        try:
            parts = token.split(".")
            if len(parts) == 3:
                header = base64url_decode(parts[0])
                payload = base64url_decode(parts[1])
                
                header_confused = header.copy()
                header_confused["alg"] = "HS256"
                
                dummy_public_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0...\n-----END PUBLIC KEY-----"
                
                import hmac
                import hashlib
                message = base64url_encode(header_confused) + "." + base64url_encode(payload)
                sig = hmac.new(dummy_public_key.encode('utf-8'), message.encode('utf-8'), digestmod=hashlib.sha256).digest()
                sig_encoded = base64.urlsafe_b64encode(sig).decode('utf-8').rstrip('=')
                
                confused_token = message + "." + sig_encoded
                headers = {self.header_token: f"Bearer {confused_token}"}
                
                test_path = "/api/profile" if not client.base_url else "api/profile"
                res = await client.get(test_path, headers=headers)
                if res.status_code == 200:
                    return RisultatoTest(
                        test_id="T07",
                        nome="Key Confusion (RS256 -> HS256)",
                        stato="FAIL",
                        severita="CRITICAL",
                        dettagli="L'applicazione accetta token HS256 firmati con la chiave pubblica RSA."
                    )
            return RisultatoTest(
                test_id="T07",
                nome="Key Confusion (RS256 -> HS256)",
                stato="PASS",
                severita="INFO",
                dettagli="I token con algoritmo alterato HS256/RS256 sono correttamente respinti."
            )
        except Exception as e:
            return RisultatoTest(
                test_id="T07",
                nome="Key Confusion (RS256 -> HS256)",
                stato="FAIL",
                severita="HIGH",
                dettagli=f"Eccezione inattesa: {e}"
            )

    # --- T08 - Privilege Escalation via Token ---
    async def _test_t08_privilege_escalation(self) -> RisultatoTest:
        if self.auth_intel and self.auth_intel.confidence_score < self.confidence_threshold:
            logger.warning(f"Test T08 saltato per basso confidence score: {self.auth_intel.confidence_score} < {self.confidence_threshold}")
            return RisultatoTest(
                test_id="T08",
                nome="Privilege Escalation via Token",
                stato="SKIPPED",
                severita="INFO",
                dettagli=f"Test skippato a causa del basso confidence score ({self.auth_intel.confidence_score} < {self.confidence_threshold})."
            )
        client = self._get_client()
        token = await self._login_and_get_token(client)
        if not token or self.tipo_token != "jwt":
            return RisultatoTest(
                test_id="T08",
                nome="Privilege Escalation via Token",
                stato="INCONCLUSIVE",
                severita="INFO",
                dettagli="Token non presente o non JWT."
            )
        try:
            parts = token.split(".")
            if len(parts) == 3:
                header = base64url_decode(parts[0])
                payload = base64url_decode(parts[1])
                
                # Dynamic claim modifications based on discovered claims
                payload_escalated = payload.copy()
                escalated = False
                if self.auth_intel and self.auth_intel.jwt_claims:
                    for claim in self.auth_intel.jwt_claims:
                        if claim in ("role", "roles", "groups", "permissions", "scope"):
                            if claim == "scope":
                                payload_escalated["scope"] = "admin read write"
                            elif claim in ("groups", "roles"):
                                payload_escalated[claim] = ["admin"]
                            else:
                                payload_escalated[claim] = "admin"
                            escalated = True
                        elif "admin" in claim.lower():
                            payload_escalated[claim] = True
                            escalated = True
                            
                if not escalated:
                    payload_escalated["role"] = "admin"
                    payload_escalated["isAdmin"] = True
                    payload_escalated["groups"] = ["admin"]

                escaped_token = base64url_encode(header) + "." + base64url_encode(payload_escalated) + "."
                
                headers = {self.header_token: f"Bearer {escaped_token}"}
                # Request an admin resource
                admin_path = "/api/admin" if not client.base_url else "api/admin"
                res = await client.get(admin_path, headers=headers)
                if res.status_code == 200:
                    return RisultatoTest(
                        test_id="T08",
                        nome="Privilege Escalation via Token",
                        stato="FAIL",
                        severita="CRITICAL",
                        dettagli="L'applicazione accetta token modificati con permessi di amministratore."
                    )
            return RisultatoTest(
                test_id="T08",
                nome="Privilege Escalation via Token",
                stato="PASS",
                severita="INFO",
                dettagli="Modifiche di ruolo all'interno del token non hanno prodotto privilege escalation."
            )
        except Exception as e:
            return RisultatoTest(
                test_id="T08",
                nome="Privilege Escalation via Token",
                stato="FAIL",
                severita="HIGH",
                dettagli=f"Eccezione inattesa: {e}"
            )

    # --- T09 - Cookie Flag di Sicurezza ---
    async def _test_t09_cookie_security_flags(self) -> RisultatoTest:
        client = self._get_client()
        if not self.endpoint_auth:
            return RisultatoTest(
                test_id="T09",
                nome="Cookie Flag di Sicurezza",
                stato="INCONCLUSIVE",
                severita="INFO",
                dettagli="Endpoint auth non disponibile."
            )
        try:
            payload = {"username": self.config.target.username, "password": self.config.target.password}
            res = await client.post(self.endpoint_auth, json=payload)
            cookies_header = res.headers.get_list("Set-Cookie")
            if not cookies_header:
                return RisultatoTest(
                    test_id="T09",
                    nome="Cookie Flag di Sicurezza",
                    stato="PASS",
                    severita="INFO",
                    dettagli="Nessun cookie impostato nella risposta di login."
                )

            for cookie in cookies_header:
                cookie_lower = cookie.lower()
                missing_flags = []
                if "httponly" not in cookie_lower:
                    missing_flags.append("HttpOnly")
                if "secure" not in cookie_lower:
                    missing_flags.append("Secure")
                
                if missing_flags:
                    return RisultatoTest(
                        test_id="T09",
                        nome="Cookie Flag di Sicurezza",
                        stato="FAIL",
                        severita="MEDIUM",
                        dettagli=f"Rilevati cookie senza flag di sicurezza ({', '.join(missing_flags)}): {cookie}"
                    )
            return RisultatoTest(
                test_id="T09",
                nome="Cookie Flag di Sicurezza",
                stato="PASS",
                severita="INFO",
                dettagli="Tutti i cookie impostati contengono i flag HttpOnly e Secure."
            )
        except Exception as e:
            return RisultatoTest(
                test_id="T09",
                nome="Cookie Flag di Sicurezza",
                stato="FAIL",
                severita="HIGH",
                dettagli=f"Eccezione inattesa: {e}"
            )

    # --- T10 - Informazioni Sensibili nelle Risposte ---
    async def _test_t10_sensitive_info_disclosure(self) -> RisultatoTest:
        client = self._get_client()
        try:
            # Triggering an error page
            invalid_path = "/api/invalid_path_error_trigger_987" if not client.base_url else "api/invalid_path_error_trigger_987"
            res = await client.get(invalid_path)
            
            text = res.text
            vulnerable_indicators = {
                "Traceback (most recent call last):": "Stack trace Python rilevata nella risposta",
                "Exception in thread": "Stack trace Java rilevata nella risposta",
                "stacktrace": "Stacktrace generica rilevata nella risposta",
                "invalid password": "Dettaglio di autenticazione troppo specifico",
                "db_password": "Password di database esposta",
                "private_key": "Chiave privata esposta"
            }

            for indicator, desc in vulnerable_indicators.items():
                if indicator in text:
                    return RisultatoTest(
                        test_id="T10",
                        nome="Informazioni Sensibili nelle Risposte",
                        stato="FAIL",
                        severita="HIGH",
                        dettagli=f"Rilevato leak di informazioni sensibili nell'errore: {desc}"
                    )

            return RisultatoTest(
                test_id="T10",
                nome="Informazioni Sensibili nelle Risposte",
                stato="PASS",
                severita="INFO",
                dettagli="Nessun dettaglio sensibile o stack trace esposto nei messaggi di errore."
            )
        except Exception as e:
            return RisultatoTest(
                test_id="T10",
                nome="Informazioni Sensibili nelle Risposte",
                stato="FAIL",
                severita="HIGH",
                dettagli=f"Eccezione inattesa: {e}"
            )

    # --- T11 - Enumerazione Utenti ---
    async def _test_t11_user_enumeration(self) -> RisultatoTest:
        client = self._get_client()
        if not self.endpoint_auth:
            return RisultatoTest(
                test_id="T11",
                nome="Enumerazione Utenti",
                stato="INCONCLUSIVE",
                severita="INFO",
                dettagli="Endpoint auth non disponibile."
            )
        try:
            res_non_existent = await client.post(
                self.endpoint_auth,
                json={"username": "not_existent_user_9876", "password": "wrongpassword"}
            )
            res_wrong_pwd = await client.post(
                self.endpoint_auth,
                json={"username": self.config.target.username, "password": "wrongpassword"}
            )

            sc_ne = res_non_existent.status_code
            sc_wp = res_wrong_pwd.status_code

            # --- Classification of status codes ---
            # Auth-recognizable codes: standard rejection codes that an auth
            # endpoint is expected to return on failed login.
            AUTH_CODES = {401, 403, 404, 422}

            ne_is_auth = sc_ne in AUTH_CODES
            wp_is_auth = sc_wp in AUTH_CODES

            # Case 1: BOTH responses are structural/server errors (not auth-recognizable).
            # This means the request format was wrong, not that auth was tested.
            if not ne_is_auth and not wp_is_auth:
                return RisultatoTest(
                    test_id="T11",
                    nome="Enumerazione Utenti",
                    stato="INCONCLUSIVE",
                    severita="INFO",
                    dettagli=(
                        f"Richieste rifiutate con codici non riconducibili all'autenticazione "
                        f"(status {sc_ne} / {sc_wp}): possibile formato non supportato."
                    )
                )

            # Case 2: Status codes DIFFER.
            # This is the primary enumeration signal — the server responds
            # differently depending on whether the username exists.
            # 404 vs 401 is the classic user-enumeration pattern.
            if sc_ne != sc_wp:
                return RisultatoTest(
                    test_id="T11",
                    nome="Enumerazione Utenti",
                    stato="FAIL",
                    severita="MEDIUM",
                    dettagli=(
                        f"Status code diversi rilevati: utente inesistente ({sc_ne}) vs "
                        f"password errata ({sc_wp}). Segnale diretto di enumerazione utenti."
                    )
                )

            # Case 3: Same status code — compare response body for discriminating text.
            text1 = res_non_existent.text.lower()
            text2 = res_wrong_pwd.text.lower()
            if text1 != text2:
                # Look for strong user-existence leakage keywords
                enum_keywords = ["exist", "trovato", "not found", "unknown user",
                                 "no user", "utente non trovato", "user not found"]
                if any(kw in text1 for kw in enum_keywords):
                    return RisultatoTest(
                        test_id="T11",
                        nome="Enumerazione Utenti",
                        stato="FAIL",
                        severita="MEDIUM",
                        dettagli=(
                            "I messaggi di errore differiscono e consentono l'enumerazione degli utenti."
                        )
                    )

            return RisultatoTest(
                test_id="T11",
                nome="Enumerazione Utenti",
                stato="PASS",
                severita="INFO",
                dettagli="Nessuna differenza strutturale o di messaggio rilevata tra utente inesistente ed esistente."
            )
        except Exception as e:
            return RisultatoTest(
                test_id="T11",
                nome="Enumerazione Utenti",
                stato="FAIL",
                severita="HIGH",
                dettagli=f"Eccezione inattesa: {str(e)}"
            )

    # --- T12 - Refresh Token Reuse ---
    async def _test_t12_refresh_token_reuse(self) -> RisultatoTest:
        client = self._get_client()
        if not self.endpoint_refresh:
            return RisultatoTest(
                test_id="T12",
                nome="Refresh Token Reuse",
                stato="INCONCLUSIVE",
                severita="INFO",
                dettagli="Endpoint refresh non disponibile.",
                category=VulnerabilityCategory.AUTHENTICATION
            )
        try:
            access_token, refresh_token = await self._login_and_get_tokens(client)
            if not refresh_token:
                return RisultatoTest(
                    test_id="T12",
                    nome="Refresh Token Reuse",
                    stato="INCONCLUSIVE",
                    severita="INFO",
                    dettagli="Nessun refresh token ottenuto dopo il login. Test ignorato.",
                    category=VulnerabilityCategory.AUTHENTICATION
                )
                
            payload = {"refresh_token": refresh_token}
            res1 = await client.post(self.endpoint_refresh, json=payload)
            
            if res1.status_code not in (200, 201):
                return RisultatoTest(
                    test_id="T12",
                    nome="Refresh Token Reuse",
                    stato="INCONCLUSIVE",
                    severita="INFO",
                    dettagli=f"Il primo tentativo di refresh ha fallito con status {res1.status_code}.",
                    category=VulnerabilityCategory.AUTHENTICATION
                )
                
            res2 = await client.post(self.endpoint_refresh, json=payload)
            if res2.status_code in (200, 201):
                return RisultatoTest(
                    test_id="T12",
                    nome="Refresh Token Reuse",
                    stato="FAIL",
                    severita="HIGH",
                    dettagli="Vulnerabilità rilevata: il server consente il riutilizzo dello stesso refresh token più volte.",
                    category=VulnerabilityCategory.AUTHENTICATION,
                    raccomandazione="Implementare la revoca del refresh token a seguito del primo utilizzo o l'invalidazione dell'intera famiglia di token in caso di tentato riuso."
                )
            
            return RisultatoTest(
                test_id="T12",
                nome="Refresh Token Reuse",
                stato="PASS",
                severita="INFO",
                dettagli="Il riutilizzo del refresh token è stato correttamente bloccato dal server.",
                category=VulnerabilityCategory.AUTHENTICATION
            )
        except Exception as e:
            return RisultatoTest(
                test_id="T12",
                nome="Refresh Token Reuse",
                stato="FAIL",
                severita="HIGH",
                dettagli=f"Errore durante il test di reuse del refresh token: {e}",
                category=VulnerabilityCategory.AUTHENTICATION
            )

    # --- T13 - Refresh Token Rotation Validation ---
    async def _test_t13_refresh_token_rotation(self) -> RisultatoTest:
        client = self._get_client()
        if not self.endpoint_refresh:
            return RisultatoTest(
                test_id="T13",
                nome="Refresh Token Rotation Validation",
                stato="INCONCLUSIVE",
                severita="INFO",
                dettagli="Endpoint refresh non disponibile.",
                category=VulnerabilityCategory.AUTHENTICATION
            )
        try:
            access_token, refresh_token = await self._login_and_get_tokens(client)
            if not refresh_token:
                return RisultatoTest(
                    test_id="T13",
                    nome="Refresh Token Rotation Validation",
                    stato="INCONCLUSIVE",
                    severita="INFO",
                    dettagli="Nessun refresh token ottenuto dopo il login.",
                    category=VulnerabilityCategory.AUTHENTICATION
                )
                
            payload = {"refresh_token": refresh_token}
            res = await client.post(self.endpoint_refresh, json=payload)
            
            if res.status_code not in (200, 201):
                return RisultatoTest(
                    test_id="T13",
                    nome="Refresh Token Rotation Validation",
                    stato="INCONCLUSIVE",
                    severita="INFO",
                    dettagli=f"Il refresh ha fallito con status {res.status_code}.",
                    category=VulnerabilityCategory.AUTHENTICATION
                )
            
            new_refresh_token = self._extract_refresh_token_from_response(res)
            if not new_refresh_token or new_refresh_token == refresh_token:
                return RisultatoTest(
                    test_id="T13",
                    nome="Refresh Token Rotation Validation",
                    stato="FAIL",
                    severita="HIGH",
                    dettagli="Rotazione assente: il server non ha emesso un nuovo refresh token o ha restituito lo stesso.",
                    category=VulnerabilityCategory.AUTHENTICATION,
                    raccomandazione="Implementare la Refresh Token Rotation (RTR) in cui ogni richiesta di refresh emette un nuovo refresh token invalidando il precedente."
                )
                
            res_reuse = await client.post(self.endpoint_refresh, json={"refresh_token": refresh_token})
            if res_reuse.status_code in (200, 201):
                return RisultatoTest(
                    test_id="T13",
                    nome="Refresh Token Rotation Validation",
                    stato="FAIL",
                    severita="HIGH",
                    dettagli="Rotazione parziale: un nuovo refresh token è stato emesso, ma quello precedente è ancora valido.",
                    category=VulnerabilityCategory.AUTHENTICATION,
                    raccomandazione="Garantire che, all'emissione di un nuovo refresh token, il vecchio refresh token sia marcato come invalidato."
                )
                
            return RisultatoTest(
                test_id="T13",
                nome="Refresh Token Rotation Validation",
                stato="PASS",
                severita="INFO",
                dettagli="Refresh Token Rotation attiva: viene emesso un nuovo refresh token e il precedente viene invalidato.",
                category=VulnerabilityCategory.AUTHENTICATION
            )
        except Exception as e:
            return RisultatoTest(
                test_id="T13",
                nome="Refresh Token Rotation Validation",
                stato="FAIL",
                severita="HIGH",
                dettagli=f"Errore durante la convalida della rotazione del refresh token: {e}",
                category=VulnerabilityCategory.AUTHENTICATION
            )

    # --- T14 - Infinite Lifetime Refresh Token ---
    async def _test_t14_infinite_lifetime_refresh_token(self) -> RisultatoTest:
        client = self._get_client()
        try:
            access_token, refresh_token = await self._login_and_get_tokens(client)
            if not refresh_token:
                return RisultatoTest(
                    test_id="T14",
                    nome="Infinite Lifetime Refresh Token",
                    stato="INCONCLUSIVE",
                    severita="INFO",
                    dettagli="Nessun refresh token ottenuto dopo il login.",
                    category=VulnerabilityCategory.AUTHENTICATION
                )
            
            parts = refresh_token.split(".")
            if len(parts) == 3:
                payload = base64url_decode(parts[1])
                exp = payload.get("exp")
                iat = payload.get("iat")
                if not exp:
                    return RisultatoTest(
                        test_id="T14",
                        nome="Infinite Lifetime Refresh Token",
                        stato="FAIL",
                        severita="HIGH",
                        dettagli="Vulnerabilità rilevata: il refresh token JWT non ha un claim di scadenza ('exp').",
                        category=VulnerabilityCategory.AUTHENTICATION,
                        raccomandazione="Configurare sempre una scadenza ('exp') per tutti i token emessi."
                    )
                if iat:
                    ttl_days = (exp - iat) / 86400
                    if ttl_days > 30:
                        return RisultatoTest(
                            test_id="T14",
                            nome="Infinite Lifetime Refresh Token",
                            stato="FAIL",
                            severita="MEDIUM",
                            dettagli=f"Refresh token con durata eccessiva: {ttl_days:.1f} giorni (maggiore di 30 giorni).",
                            category=VulnerabilityCategory.AUTHENTICATION,
                            raccomandazione="Ridurre la durata massima dei refresh token a valori ragionevoli (es. max 7-30 giorni)."
                        )
                return RisultatoTest(
                    test_id="T14",
                    nome="Infinite Lifetime Refresh Token",
                    stato="PASS",
                    severita="INFO",
                    dettagli="Il refresh token ha una scadenza definita e una durata entro i limiti di sicurezza.",
                    category=VulnerabilityCategory.AUTHENTICATION
                )
            else:
                return RisultatoTest(
                    test_id="T14",
                    nome="Infinite Lifetime Refresh Token",
                    stato="INCONCLUSIVE",
                    severita="INFO",
                    dettagli="Il refresh token non è un JWT. Impossibile analizzare i claims di scadenza staticamente.",
                    category=VulnerabilityCategory.AUTHENTICATION
                )
        except Exception as e:
            return RisultatoTest(
                test_id="T14",
                nome="Infinite Lifetime Refresh Token",
                stato="FAIL",
                severita="HIGH",
                dettagli=f"Errore durante l'analisi della durata del refresh token: {e}",
                category=VulnerabilityCategory.AUTHENTICATION
            )

    # --- T15 - Parallel Refresh Abuse ---
    async def _test_t15_parallel_refresh_abuse(self) -> RisultatoTest:
        client = self._get_client()
        if not self.endpoint_refresh:
            return RisultatoTest(
                test_id="T15",
                nome="Parallel Refresh Abuse",
                stato="INCONCLUSIVE",
                severita="INFO",
                dettagli="Endpoint refresh non disponibile.",
                category=VulnerabilityCategory.AUTHENTICATION
            )
        try:
            access_token, refresh_token = await self._login_and_get_tokens(client)
            if not refresh_token:
                return RisultatoTest(
                    test_id="T15",
                    nome="Parallel Refresh Abuse",
                    stato="INCONCLUSIVE",
                    severita="INFO",
                    dettagli="Nessun refresh token ottenuto dopo il login.",
                    category=VulnerabilityCategory.AUTHENTICATION
                )
            
            payload = {"refresh_token": refresh_token}
            
            tasks = [
                client.post(self.endpoint_refresh, json=payload),
                client.post(self.endpoint_refresh, json=payload),
                client.post(self.endpoint_refresh, json=payload)
            ]
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            success_count = 0
            for r in responses:
                if not isinstance(r, Exception) and r.status_code in (200, 201):
                    success_count += 1
                      
            if success_count > 1:
                return RisultatoTest(
                    test_id="T15",
                    nome="Parallel Refresh Abuse",
                    stato="FAIL",
                    severita="HIGH",
                    dettagli=f"Race condition rilevata: inviate 3 richieste concorrenti, {success_count} hanno avuto successo emettendo nuovi token.",
                    category=VulnerabilityCategory.AUTHENTICATION,
                    raccomandazione="Implementare il locking distribuito o il controllo transazionale per impedire che più richieste parallele con lo stesso refresh token vadano a buon fine contemporaneamente."
                )
                  
            return RisultatoTest(
                test_id="T15",
                nome="Parallel Refresh Abuse",
                stato="PASS",
                severita="INFO",
                dettagli="Solo una richiesta concorrente di refresh ha avuto successo. Nessun abuso parallelo rilevato.",
                category=VulnerabilityCategory.AUTHENTICATION
            )
        except Exception as e:
            return RisultatoTest(
                test_id="T15",
                nome="Parallel Refresh Abuse",
                stato="FAIL",
                severita="HIGH",
                dettagli=f"Errore durante il test di parallel refresh abuse: {e}",
                category=VulnerabilityCategory.AUTHENTICATION
            )

    # --- T16 - Password Reset Debole ---
    async def _test_t16_weak_password_reset(self) -> RisultatoTest:
        client = self._get_client()
        if not self.endpoint_reset:
            return RisultatoTest(
                test_id="T16",
                nome="Password Reset Debole",
                stato="INCONCLUSIVE",
                severita="INFO",
                dettagli="Endpoint reset non rilevato.",
                category=VulnerabilityCategory.AUTHENTICATION
            )
        try:
            payload = {"email": ""}
            res = await client.post(self.endpoint_reset, json=payload)
            if res.status_code == 200:
                text_lower = res.text.lower()
                for key in ["token", "password", "secret"]:
                    if key in text_lower and len(text_lower) < 200:
                        return RisultatoTest(
                            test_id="T16",
                            nome="Password Reset Debole",
                            stato="FAIL",
                            severita="HIGH",
                            dettagli=f"L'endpoint risponde con successo e leaks informazioni sensibili: {res.text}",
                            category=VulnerabilityCategory.AUTHENTICATION
                        )
            return RisultatoTest(
                test_id="T16",
                nome="Password Reset Debole",
                stato="PASS",
                severita="INFO",
                dettagli="Nessuna debolezza immediata rilevata sull'endpoint di password reset.",
                category=VulnerabilityCategory.AUTHENTICATION
            )
        except Exception as e:
            return RisultatoTest(
                test_id="T16",
                nome="Password Reset Debole",
                stato="FAIL",
                severita="HIGH",
                dettagli=f"Eccezione inattesa: {e}",
                category=VulnerabilityCategory.AUTHENTICATION
            )

    # --- T17 - Validazione JWKS Header Injection ---
    async def _test_t17_jwks_validation(self) -> RisultatoTest:
        client = self._get_client()
        token = await self._login_and_get_token(client)
        if not token or self.tipo_token != "jwt":
            return RisultatoTest(
                test_id="T17",
                nome="Validazione JWKS (Header Injection)",
                stato="INCONCLUSIVE",
                severita="INFO",
                dettagli="Token non presente o non JWT, test ignorato.",
                category=VulnerabilityCategory.AUTHENTICATION
            )
        try:
            parts = token.split(".")
            if len(parts) == 3:
                header = base64url_decode(parts[0])
                payload = base64url_decode(parts[1])
                
                header_jwk = header.copy()
                header_jwk["jwk"] = {
                    "kty": "RSA",
                    "e": "AQAB",
                    "n": "v9_dummy_n_field"
                }
                
                tampered_token = base64url_encode(header_jwk) + "." + base64url_encode(payload) + ".dummysig"
                headers = {self.header_token: f"Bearer {tampered_token}"}
                
                test_path = "/api/profile" if not client.base_url else "api/profile"
                res = await client.get(test_path, headers=headers)
                if res.status_code == 200:
                    return RisultatoTest(
                        test_id="T17",
                        nome="Validazione JWKS (Header Injection)",
                        stato="FAIL",
                        severita="CRITICAL",
                        dettagli="L'applicazione accetta token firmati con una chiave jwk auto-dichiarata nell'header.",
                        category=VulnerabilityCategory.AUTHENTICATION
                    )
            return RisultatoTest(
                test_id="T17",
                nome="Validazione JWKS (Header Injection)",
                stato="PASS",
                severita="INFO",
                dettagli="JWK/x5u header injection rifiutata correttamente.",
                category=VulnerabilityCategory.AUTHENTICATION
            )
        except Exception as e:
            return RisultatoTest(
                test_id="T17",
                nome="Validazione JWKS (Header Injection)",
                stato="FAIL",
                severita="HIGH",
                dettagli=f"Eccezione: {e}",
                category=VulnerabilityCategory.AUTHENTICATION
            )

    # --- T18 - Sicurezza Flussi OAuth2/OIDC ---
    async def _test_t18_oauth2_oidc_security(self) -> RisultatoTest:
        client = self._get_client()
        if not self.auth_intel or not self.auth_intel.identity_provider:
            return RisultatoTest(
                test_id="T18",
                nome="Sicurezza Flussi OAuth2/OIDC",
                stato="INCONCLUSIVE",
                severita="INFO",
                dettagli="Nessun Identity Provider OIDC configurato.",
                category=VulnerabilityCategory.AUTHENTICATION
            )
        try:
            metadata = self.auth_intel.oauth_flows_metadata
            if metadata:
                issues = []
                if not metadata.get("state_checked", False):
                    issues.append("Mancanza parametro 'state' per prevenzione CSRF")
                if not metadata.get("pkce_checked", False):
                    issues.append("Mancanza PKCE (code_challenge) per client pubblici")
                
                if issues:
                    return RisultatoTest(
                        test_id="T18",
                        nome="Sicurezza Flussi OAuth2/OIDC",
                        stato="FAIL",
                        severita="HIGH",
                        dettagli=f"Rilevati problemi di sicurezza OIDC: {', '.join(issues)}",
                        category=VulnerabilityCategory.AUTHENTICATION
                    )
            
            if self.endpoint_auth:
                res = await client.get(f"{self.endpoint_auth}?redirect_uri=http://attacker-url.com")
                if res.status_code in (301, 302) and "attacker-url.com" in res.headers.get("Location", ""):
                    return RisultatoTest(
                        test_id="T18",
                        nome="Sicurezza Flussi OAuth2/OIDC",
                        stato="FAIL",
                        severita="HIGH",
                        dettagli="L'endpoint di login/auth soffre di Open Redirect (accetta redirect_uri non validato).",
                        category=VulnerabilityCategory.AUTHENTICATION
                    )
            
            return RisultatoTest(
                test_id="T18",
                nome="Sicurezza Flussi OAuth2/OIDC",
                stato="PASS",
                severita="INFO",
                dettagli="Nessun problema rilevato sui parametri OAuth2/OIDC (redirect_uri, state, PKCE).",
                category=VulnerabilityCategory.AUTHENTICATION
            )
        except Exception as e:
            return RisultatoTest(
                test_id="T18",
                nome="Sicurezza Flussi OAuth2/OIDC",
                stato="FAIL",
                severita="HIGH",
                dettagli=f"Eccezione: {e}",
                category=VulnerabilityCategory.AUTHENTICATION
            )

    # --- T19 - Sicurezza Credenziali Non-JWT ---
    async def _test_t19_non_jwt_credentials(self) -> RisultatoTest:
        client = self._get_client()
        if not self.auth_intel or not self.auth_intel.non_jwt_mechanisms:
            return RisultatoTest(
                test_id="T19",
                nome="Sicurezza Credenziali Non-JWT",
                stato="INCONCLUSIVE",
                severita="INFO",
                dettagli="Nessun meccanismo di autenticazione non-JWT rilevato.",
                category=VulnerabilityCategory.AUTHENTICATION
            )
        try:
            issues = []
            if "API Key" in self.auth_intel.non_jwt_mechanisms:
                test_path = "/api/data?api_key=testkey123" if not client.base_url else "api/data?api_key=testkey123"
                res = await client.get(test_path)
                if res.status_code == 200:
                    issues.append("API Key accettata nella querystring (rischio di logging)")
            
            if "Basic Auth" in self.auth_intel.non_jwt_mechanisms:
                if str(client.base_url).startswith("http://"):
                    issues.append("Basic Auth trasmesso in chiaro su HTTP (mancanza TLS)")
                    
            if issues:
                return RisultatoTest(
                    test_id="T19",
                    nome="Sicurezza Credenziali Non-JWT",
                    stato="FAIL",
                    severita="MEDIUM",
                    dettagli=f"Identificate vulnerabilità non-JWT: {', '.join(issues)}",
                    category=VulnerabilityCategory.AUTHENTICATION
                )
                
            return RisultatoTest(
                test_id="T19",
                nome="Sicurezza Credenziali Non-JWT",
                stato="PASS",
                severita="INFO",
                dettagli="Credenziali non-JWT (Basic Auth / API Key) configurate in modo sicuro.",
                category=VulnerabilityCategory.AUTHENTICATION
            )
        except Exception as e:
            return RisultatoTest(
                test_id="T19",
                nome="Sicurezza Credenziali Non-JWT",
                stato="FAIL",
                severita="HIGH",
                dettagli=f"Eccezione: {e}",
                category=VulnerabilityCategory.AUTHENTICATION
            )

    # --- T20 - Bypass Rate Limiting via Spoofing Header IP ---
    async def _test_t20_rate_limiting_bypass(self) -> RisultatoTest:
        if self.target_environment == "production" and not self.allow_destructive_tests:
            logger.warning("Test T20 (rate-limiting-bypass) saltato per target in ambiente di produzione.")
            return RisultatoTest(
                test_id="T20",
                nome="Bypass Rate Limiting via Spoofing Header IP",
                stato="SKIPPED",
                severita="INFO",
                dettagli="Test di evasione disabilitato in ambiente di produzione per sicurezza.",
                category=VulnerabilityCategory.AUTHENTICATION
            )
        client = self._get_client()
        target_path = self.endpoint_auth or "/"
        
        headers_to_test = ["X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"]
        successful_bypass_headers = []
        
        try:
            payload = {"username": "wronguser", "password": "wrongpassword"}
            triggered_429 = False
            
            method_to_use = "GET" if target_path == "/" else "POST"
            
            async def send_req(headers=None):
                if method_to_use == "GET":
                    return await client.get(target_path, headers=headers)
                else:
                    return await client.post(target_path, json=payload, headers=headers)
                    
            for _ in range(8):
                res = await send_req()
                if res.status_code == 429:
                    triggered_429 = True
                    break
            
            if not triggered_429:
                return RisultatoTest(
                    test_id="T20",
                    nome="Bypass Rate Limiting via Spoofing Header IP",
                    stato="INCONCLUSIVE",
                    severita="INFO",
                    dettagli="Rate limit non attivato durante il test preliminare (nessun 429 ricevuto dopo 8 tentativi). Impossibile verificare il bypass.",
                    category=VulnerabilityCategory.AUTHENTICATION
                )
            
            for header in headers_to_test:
                spoofed_headers = {header: "198.51.100.12"}
                res = await send_req(headers=spoofed_headers)
                if res.status_code != 429:
                    successful_bypass_headers.append(header)
            
            if successful_bypass_headers:
                return RisultatoTest(
                    test_id="T20",
                    nome="Bypass Rate Limiting via Spoofing Header IP",
                    stato="FAIL",
                    severita="HIGH",
                    dettagli=f"Rate limiting bypassato con successo tramite spoofing degli IP client nei seguenti header: {', '.join(successful_bypass_headers)}.",
                    category=VulnerabilityCategory.AUTHENTICATION
                )
            
            return RisultatoTest(
                test_id="T20",
                nome="Bypass Rate Limiting via Spoofing Header IP",
                stato="PASS",
                severita="INFO",
                dettagli="Il rate limiting è attivo e non è stato possibile bypassarlo tramite header spoofing (X-Forwarded-For, X-Real-IP, CF-Connecting-IP).",
                category=VulnerabilityCategory.AUTHENTICATION
            )
            
        except Exception as e:
            return RisultatoTest(
                test_id="T20",
                nome="Bypass Rate Limiting via Spoofing Header IP",
                stato="FAIL",
                severita="HIGH",
                dettagli=f"Eccezione durante il test: {e}",
                category=VulnerabilityCategory.AUTHENTICATION
            )

    # --- T21 - MFA Testing (Bypass e OTP Debole) ---
    async def _test_t21_mfa_testing(self) -> RisultatoTest:
        is_prod = (self.target_environment == "production")
        client = self._get_client()
        target_mfa = self.endpoint_mfa or "/api/v1/auth/mfa"
        
        has_mfa_indicator = False
        if self.auth_intel:
            for func in self.auth_intel.auth_functions:
                if any(kw in func.lower() for kw in ["mfa", "totp", "otp", "2fa"]):
                    has_mfa_indicator = True
                    break
        
        if not self.endpoint_mfa and not has_mfa_indicator:
            return RisultatoTest(
                test_id="T21",
                nome="MFA Testing (Bypass e OTP Debole)",
                stato="INCONCLUSIVE",
                dettagli="Nessun endpoint o meccanismo MFA (Multi-Factor Authentication) rilevato nell'applicazione.",
                severita="INFO",
                category=VulnerabilityCategory.AUTHENTICATION
            )
            
        try:
            payload_empty = {"code": ""}
            res_empty = await client.post(target_mfa, json=payload_empty)
            
            if res_empty.status_code in (200, 201):
                return RisultatoTest(
                    test_id="T21",
                    nome="MFA Testing (Bypass e OTP Debole)",
                    stato="FAIL",
                    severita="CRITICAL",
                    dettagli="Bypass logico MFA rilevato: l'applicazione accetta richieste di verifica MFA con codice vuoto o mancante.",
                    category=VulnerabilityCategory.AUTHENTICATION
                )
                
            if is_prod and not self.allow_destructive_tests:
                return RisultatoTest(
                    test_id="T21",
                    nome="MFA Testing (Bypass e OTP Debole)",
                    stato="PASS",
                    severita="INFO",
                    dettagli="Meccanismo MFA rilevato. Eseguito solo test logico (passato). Il brute-force di OTP è stato saltato in produzione come da guardrail.",
                    category=VulnerabilityCategory.AUTHENTICATION
                )
            
            triggered_limit = False
            for i in range(10):
                res_wrong = await client.post(target_mfa, json={"code": f"99999{i}"})
                if res_wrong.status_code == 429:
                    triggered_limit = True
                    break
                    
            if triggered_limit:
                return RisultatoTest(
                    test_id="T21",
                    nome="MFA Testing (Bypass e OTP Debole)",
                    stato="PASS",
                    severita="INFO",
                    dettagli="Il brute-force di OTP è stato correttamente bloccato o limitato dal server (status 429).",
                    category=VulnerabilityCategory.AUTHENTICATION
                )
            else:
                return RisultatoTest(
                    test_id="T21",
                    nome="MFA Testing (Bypass e OTP Debole)",
                    stato="FAIL",
                    severita="HIGH",
                    dettagli="Nessun rate limiting rilevato sull'endpoint MFA: inviati 10 codici OTP errati consecutivi senza ricevere blocchi o limitazioni (status 429).",
                    category=VulnerabilityCategory.AUTHENTICATION
                )
                
        except Exception as e:
            return RisultatoTest(
                test_id="T21",
                nome="MFA Testing (Bypass e OTP Debole)",
                stato="FAIL",
                severita="HIGH",
                dettagli=f"Eccezione durante il test MFA: {e}",
                category=VulnerabilityCategory.AUTHENTICATION
            )

    # --- T22 - SAML/SSO Security Checks ---
    async def _test_t22_saml_security(self) -> RisultatoTest:
        client = self._get_client()
        is_saml_detected = False
        if self.auth_intel and getattr(self.auth_intel, "saml_detected", False):
            is_saml_detected = True
        
        target_acs = "/saml/acs"
        if self.auth_intel and self.auth_intel.idp_metadata:
            target_acs = self.auth_intel.idp_metadata.get("acs_url", target_acs)
            
        if not is_saml_detected:
            return RisultatoTest(
                test_id="T22",
                nome="SAML/SSO Security Checks",
                stato="INCONCLUSIVE",
                dettagli="L'uso di SAML non è rilevato per questa applicazione. Test saltato.",
                severita="INFO",
                category=VulnerabilityCategory.AUTHENTICATION
            )
            
        try:
            issues = []
            import base64
            import xml.etree.ElementTree as ET
            
            def parse_xml_safely(xml_str: bytes) -> ET.Element:
                return ET.fromstring(xml_str)
            
            xsw_xml = (
                b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
                b'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response_id">\n'
                b'  <saml:Issuer>http://issuer.example.com</saml:Issuer>\n'
                b'  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">\n'
                b'    <ds:SignedInfo>\n'
                b'      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>\n'
                b'      <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>\n'
                b'      <ds:Reference URI="#_assertion_id_signed">\n'
                b'        <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>\n'
                b'        <ds:DigestValue>dummy_digest</ds:DigestValue>\n'
                b'      </ds:Reference>\n'
                b'    </ds:SignedInfo>\n'
                b'    <ds:SignatureValue>dummy_signature</ds:SignatureValue>\n'
                b'  </ds:Signature>\n'
                b'  <!-- Signed assertion -->\n'
                b'  <saml:Assertion ID="_assertion_id_signed">\n'
                b'    <saml:Issuer>http://issuer.example.com</saml:Issuer>\n'
                b'    <saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>\n'
                b'  </saml:Assertion>\n'
                b'  <!-- Wrapped unsigned assertion (manipulated) -->\n'
                b'  <saml:Assertion ID="_assertion_id_unsigned">\n'
                b'    <saml:Issuer>http://issuer.example.com</saml:Issuer>\n'
                b'    <saml:Subject><saml:NameID>admin@example.com</saml:NameID></saml:Subject>\n'
                b'  </saml:Assertion>\n'
                b'</samlp:Response>'
            )
            
            _ = parse_xml_safely(xsw_xml)
            
            b64_xsw = base64.b64encode(xsw_xml).decode("utf-8")
            res_xsw = await client.post(target_acs, data={"SAMLResponse": b64_xsw})
            
            if res_xsw.status_code in (200, 302):
                issues.append("XML Signature Wrapping accettato (status 200/302)")
                
            xxe_xml = (
                b'<?xml version="1.0" encoding="UTF-8"?>\n'
                b'<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://invalid-dns-test-url.local/xxe.xml"> ]>\n'
                b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
                b'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_xxe_response">\n'
                b'  <saml:Issuer>&xxe;</saml:Issuer>\n'
                b'</samlp:Response>'
            )
            
            b64_xxe = base64.b64encode(xxe_xml).decode("utf-8")
            res_xxe = await client.post(target_acs, data={"SAMLResponse": b64_xxe})
            
            if "invalid-dns-test-url" in res_xxe.text:
                issues.append("XXE: Risoluzione entità esterne rilevata nel corpo della risposta")
                
            if issues:
                return RisultatoTest(
                    test_id="T22",
                    nome="SAML/SSO Security Checks",
                    stato="FAIL",
                    severita="HIGH",
                    dettagli=f"Rilevate vulnerabilità SAML: {', '.join(issues)}",
                    category=VulnerabilityCategory.AUTHENTICATION
                )
                
            return RisultatoTest(
                test_id="T22",
                nome="SAML/SSO Security Checks",
                stato="PASS",
                severita="INFO",
                dettagli="L'applicazione valida correttamente le asserzioni SAML, bloccando attacchi XSW e XXE.",
                category=VulnerabilityCategory.AUTHENTICATION
            )
            
        except Exception as e:
            return RisultatoTest(
                test_id="T22",
                nome="SAML/SSO Security Checks",
                stato="FAIL",
                severita="HIGH",
                dettagli=f"Eccezione durante i controlli SAML: {e}",
                category=VulnerabilityCategory.AUTHENTICATION
            )

    def _calculate_resilience_score(self, results: List[RisultatoTest]) -> Dict[str, Any]:
        score = 100
        
        deductions = {
            "T01": 15,  # JWT manipulation
            "T02": 10,  # Expired token
            "T03": 10,  # Brute force / Rate limiting
            "T05": 10,  # Logout token reuse
            "T06": 10,  # Session fixation
            "T07": 10,  # Key confusion
            "T08": 10,  # Privilege escalation
            "T09": 10,  # Cookie flags
            "T12": 10,  # Refresh Token Reuse
            "T13": 10,  # Refresh Token Rotation Validation
            "T14": 5,   # Infinite Lifetime Refresh Token
            "T15": 5,   # Parallel Refresh Abuse
            "T17": 10,  # JWKS Validation
            "T20": 5,   # Bypass Rate Limiting
            "T21": 10   # MFA Testing
        }
        
        for res in results:
            if res.stato == "FAIL" and res.test_id in deductions:
                score -= deductions[res.test_id]
                
        if self.auth_intel and not self.auth_intel.mfa_detected:
            score -= 10
            
        score = max(0, min(100, score))
        
        if score >= 90:
            grade = "A"
            risk = "Low"
        elif score >= 80:
            grade = "B"
            risk = "Medium"
        elif score >= 70:
            grade = "C"
            risk = "Medium"
        elif score >= 60:
            grade = "D"
            risk = "High"
        else:
            grade = "F"
            risk = "Critical"
            
        return {
            "score": score,
            "grade": grade,
            "risk": risk
        }

    async def run_all(self, stack: StackInfo, vulnerabilities: List[Vulnerabilita]) -> List[RisultatoTest]:
        """Runs all checks in sequence."""
        # 1. Health check
        await self.health_check()

        # 2. Endpoint Discovery
        await self.discover_endpoints(stack, vulnerabilities)

        # 3. Test execution sequence
        results: List[RisultatoTest] = []
        
        test_methods = [
            self._test_t01_jwt_manipulation,
            self._test_t02_expired_token,
            self._test_t03_brute_force_rate_limiting,
            self._test_t04_token_replay,
            self._test_t05_token_reuse_post_logout,
            self._test_t06_session_fixation,
            self._test_t07_key_confusion,
            self._test_t08_privilege_escalation,
            self._test_t09_cookie_security_flags,
            self._test_t10_sensitive_info_disclosure,
            self._test_t11_user_enumeration,
            self._test_t12_refresh_token_reuse,
            self._test_t13_refresh_token_rotation,
            self._test_t14_infinite_lifetime_refresh_token,
            self._test_t15_parallel_refresh_abuse,
            self._test_t16_weak_password_reset,
            self._test_t17_jwks_validation,
            self._test_t18_oauth2_oidc_security,
            self._test_t19_non_jwt_credentials,
            self._test_t20_rate_limiting_bypass,
            self._test_t21_mfa_testing,
            self._test_t22_saml_security
        ]

        TEST_CATEGORY_MAP = {
            "T01": VulnerabilityCategory.AUTHENTICATION,
            "T02": VulnerabilityCategory.AUTHENTICATION,
            "T03": VulnerabilityCategory.AUTHENTICATION,
            "T04": VulnerabilityCategory.AUTHORIZATION,
            "T05": VulnerabilityCategory.AUTHENTICATION,
            "T06": VulnerabilityCategory.AUTHENTICATION,
            "T07": VulnerabilityCategory.AUTHENTICATION,
            "T08": VulnerabilityCategory.AUTHORIZATION,
            "T09": VulnerabilityCategory.SECURITY_MISCONFIGURATION,
            "T10": VulnerabilityCategory.INFORMATION_DISCLOSURE,
            "T11": VulnerabilityCategory.AUTHENTICATION,
            "T12": VulnerabilityCategory.AUTHENTICATION,
            "T13": VulnerabilityCategory.AUTHENTICATION,
            "T14": VulnerabilityCategory.AUTHENTICATION,
            "T15": VulnerabilityCategory.AUTHENTICATION,
            "T16": VulnerabilityCategory.AUTHENTICATION,
            "T17": VulnerabilityCategory.AUTHENTICATION,
            "T18": VulnerabilityCategory.AUTHENTICATION,
            "T19": VulnerabilityCategory.AUTHENTICATION,
            "T20": VulnerabilityCategory.AUTHENTICATION,
            "T21": VulnerabilityCategory.AUTHENTICATION,
            "T22": VulnerabilityCategory.AUTHENTICATION
        }

        for method in test_methods:
            try:
                test_res = await method()
                test_res.category = TEST_CATEGORY_MAP.get(test_res.test_id, VulnerabilityCategory.AUTHENTICATION)
                results.append(test_res)
            except Exception as e:
                test_id = method.__name__.split("_test_")[-1].split("_")[0].upper()
                test_name = " ".join(method.__name__.split("_test_")[-1].split("_")[1:]).title()
                results.append(RisultatoTest(
                    test_id=test_id,
                    nome=test_name,
                    stato="FAIL",
                    severita="HIGH",
                    dettagli=f"Eccezione imprevista durante l'esecuzione: {e}",
                    category=TEST_CATEGORY_MAP.get(test_id, VulnerabilityCategory.AUTHENTICATION)
                ))

        resilience_score = self._calculate_resilience_score(results)
        if self.auth_intel:
            self.auth_intel.authentication_score = resilience_score

        return results

# --- Main Entry Point ---
async def run(
    stack: StackInfo,
    vulnerabilita: List[Vulnerabilita],
    config: Config,
    auth_intel: Optional[AuthenticationKnowledgeGraph] = None,
    target_environment: str = "staging",
    allow_destructive_tests: bool = False,
    rate_limit_delay: float = 0.0,
    confidence_threshold: float = 0.4
) -> List[RisultatoTest]:
    """
    Main entry point for Fase 4: Test Dinamico.
    Instantiates DynamicTester, runs the health check, discovers endpoints, and executes security tests.
    """
    logger.info("Avvio Fase 4 - Test Dinamico per Broken Authentication")
    tester = DynamicTester(
        config, 
        auth_intel=auth_intel,
        target_environment=target_environment,
        allow_destructive_tests=allow_destructive_tests,
        rate_limit_delay=rate_limit_delay,
        confidence_threshold=confidence_threshold
    )
    results = await tester.run_all(stack, vulnerabilita)
    logger.info(f"Fase 4 completata. Eseguiti {len(results)} test dinamici.")
    return results
