"""
Broken Authentication - Dynamic Tester Module (Fase 4).
Runs dynamic security tests against the running application to identify broken authentication vulnerabilities.
"""

import re
import json
import base64
import httpx
import asyncio
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from loguru import logger

from src.core.broken_authentication.discovery import StackInfo, Config

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
    dettagli: Optional[Dict[str, Any]] = None

class RisultatoTest(BaseModel):
    test_id: str
    nome: str
    stato: str  # "PASS" | "FAIL"
    severita: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    dettagli: str

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
    def __init__(self, config: Config, client: Optional[httpx.AsyncClient] = None):
        self.config = config
        self._client = client
        self.endpoint_auth: Optional[str] = None
        self.endpoint_logout: Optional[str] = None
        self.endpoint_refresh: Optional[str] = None
        self.endpoint_reset: Optional[str] = None
        self.tipo_token: str = "jwt"
        self.header_token: str = "Authorization"

    def _get_client(self) -> httpx.AsyncClient:
        """Returns the injected client or initializes a new one with config settings."""
        if self._client:
            return self._client
        return httpx.AsyncClient(
            base_url=self.config.target.base_url,
            timeout=self.config.scanner.timeout_http
        )

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
        doc_paths = ["/openapi.json", "/docs/openapi.json", "/swagger.json", "/api-docs"]
        
        logger.info("Avvio recupero endpoint reali tramite documentazione API...")
        discovered = False

        for path in doc_paths:
            try:
                url = path if client.base_url and str(client.base_url) != "http://localhost" else f"{self.config.target.base_url.rstrip('/')}{path}"
                response = await client.get(url)
                if response.status_code == 200:
                    data = response.json()
                    paths = data.get("paths", {})
                    if paths:
                        logger.info(f"Documentazione API trovata su {url}. Estrazione endpoint...")
                        self._parse_openapi_paths(paths)
                        discovered = True
                        break
            except Exception as e:
                logger.debug(f"Impossibile leggere documentazione da {path}: {e}")

        # Fallback Strategy: use route_auth from Fase 2
        if not discovered or not self.endpoint_auth:
            logger.info("Documentazione API non trovata o endpoint di login assente. Utilizzo dei fallback di Fase 2...")
            self._apply_fallback_routes(vulnerabilities)

        if not self.endpoint_auth:
            raise EndpointNotFoundException("Endpoint di autenticazione principale non trovato.")

        # Determine token type & header
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
        logger.info(f"Configurazione Client: Tipo Token={self.tipo_token}, Header={self.header_token}")

    def _parse_openapi_paths(self, paths: Dict[str, Any]) -> None:
        for path in paths.keys():
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

    async def _login_and_get_token(self, client: httpx.AsyncClient) -> Optional[str]:
        """Helper to login and retrieve token."""
        if not self.endpoint_auth:
            return None
        try:
            payload = {
                "username": self.config.target.username,
                "password": self.config.target.password
            }
            res = await client.post(self.endpoint_auth, json=payload)
            if res.status_code in (200, 201):
                try:
                    data = res.json()
                    for key in ["access_token", "token", "jwt", "accessToken"]:
                        if key in data:
                            return data[key]
                except Exception:
                    pass
                # Check headers for cookie or custom header
                auth_header = res.headers.get("Authorization") or res.headers.get("X-Auth-Token")
                if auth_header:
                    return auth_header.replace("Bearer ", "").strip()
                cookie = res.headers.get("Set-Cookie")
                if cookie:
                    return cookie.split(";")[0].strip()
        except Exception as e:
            logger.debug(f"Errore durante il login per i test: {e}")
        return None

    # --- T01 - JWT Manipulation ---
    async def _test_t01_jwt_manipulation(self) -> RisultatoTest:
        client = self._get_client()
        token = await self._login_and_get_token(client)
        if not token or self.tipo_token != "jwt":
            return RisultatoTest(
                test_id="T01",
                nome="Manipolazione JWT",
                stato="PASS",
                severita="INFO",
                dettagli="Token non presente o non JWT, test ignorato."
            )

        parts = token.split(".")
        if len(parts) != 3:
            return RisultatoTest(
                test_id="T01",
                nome="Manipolazione JWT",
                stato="PASS",
                severita="INFO",
                dettagli="Il token non ha una struttura JWT valida."
            )

        try:
            header = base64url_decode(parts[0])
            payload = base64url_decode(parts[1])

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
        client = self._get_client()
        # Generates a dummy expired JWT
        try:
            header = {"alg": "HS256", "typ": "JWT"}
            # expired claim (1000s ago)
            payload = {"sub": "test", "exp": 0}
            expired_token = base64url_encode(header) + "." + base64url_encode(payload) + ".invalidsignature"
            
            headers = {self.header_token: f"Bearer {expired_token}"}
            test_path = "/api/profile" if not client.base_url else "api/profile"
            res = await client.get(test_path, headers=headers)
            if res.status_code == 200:
                return RisultatoTest(
                    test_id="T02",
                    nome="Token scaduto",
                    stato="FAIL",
                    severita="HIGH",
                    dettagli="L'applicazione accetta token scaduti."
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
                stato="FAIL",
                severita="HIGH",
                dettagli=f"Eccezione inattesa durante il test: {e}"
            )

    # --- T03 - Brute Force e Rate Limiting ---
    async def _test_t03_brute_force_rate_limiting(self) -> RisultatoTest:
        client = self._get_client()
        if not self.endpoint_auth:
            return RisultatoTest(
                test_id="T03",
                nome="Brute Force e Rate Limiting",
                stato="PASS",
                severita="INFO",
                dettagli="Endpoint auth non disponibile."
            )
        try:
            payload = {"username": "wronguser", "password": "wrongpassword"}
            responses = []
            for _ in range(10):
                res = await client.post(self.endpoint_auth, json=payload)
                responses.append(res.status_code)
            
            if 429 in responses:
                return RisultatoTest(
                    test_id="T03",
                    nome="Brute Force e Rate Limiting",
                    stato="PASS",
                    severita="INFO",
                    dettagli="Rilevato blocco di sicurezza (status 429) dopo tentativi multipli falliti."
                )
            
            # If all were 401/400 without rate limit block
            return RisultatoTest(
                test_id="T03",
                nome="Brute Force e Rate Limiting",
                stato="FAIL",
                severita="MEDIUM",
                dettagli="Nessun meccanismo di rate limiting rilevato (10 tentativi falliti con status 401)."
            )
        except Exception as e:
            return RisultatoTest(
                test_id="T03",
                nome="Brute Force e Rate Limiting",
                stato="FAIL",
                severita="HIGH",
                dettagli=f"Eccezione inattesa durante il test: {e}"
            )

    # --- T04 - Enumerazione Utenti ---
    async def _test_t04_user_enumeration(self) -> RisultatoTest:
        client = self._get_client()
        if not self.endpoint_auth:
            return RisultatoTest(
                test_id="T04",
                nome="Enumerazione Utenti",
                stato="PASS",
                severita="INFO",
                dettagli="Endpoint auth non disponibile."
            )
        try:
            # 1. Non existent user
            res_non_existent = await client.post(
                self.endpoint_auth, 
                json={"username": "not_existent_user_9876", "password": "wrongpassword"}
            )
            # 2. Existent user, wrong password
            res_wrong_pwd = await client.post(
                self.endpoint_auth, 
                json={"username": self.config.target.username, "password": "wrongpassword"}
            )

            # Check for structural differences
            if res_non_existent.status_code != res_wrong_pwd.status_code:
                return RisultatoTest(
                    test_id="T04",
                    nome="Enumerazione Utenti",
                    stato="FAIL",
                    severita="MEDIUM",
                    dettagli=f"Status code diversi: utente inesistente ({res_non_existent.status_code}) vs pwd errata ({res_wrong_pwd.status_code})."
                )

            text1 = res_non_existent.text.lower()
            text2 = res_wrong_pwd.text.lower()
            if text1 != text2:
                # check if details differ specifically on user presence
                if "exist" in text1 or "trovato" in text1 or "not found" in text1:
                    return RisultatoTest(
                        test_id="T04",
                        nome="Enumerazione Utenti",
                        stato="FAIL",
                        severita="MEDIUM",
                        dettagli="I messaggi di errore differiscono e consentono l'enumerazione degli utenti."
                    )

            return RisultatoTest(
                test_id="T04",
                nome="Enumerazione Utenti",
                stato="PASS",
                severita="INFO",
                dettagli="Nessuna differenza strutturale o di messaggio rilevata tra utente inesistente ed esistente."
            )
        except Exception as e:
            return RisultatoTest(
                test_id="T04",
                nome="Enumerazione Utenti",
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
                stato="PASS",
                severita="INFO",
                dettagli="Endpoint logout non rilevato, impossibile eseguire il test."
            )
        try:
            token = await self._login_and_get_token(client)
            if not token:
                return RisultatoTest(
                    test_id="T05",
                    nome="Riuso Token Post-Logout",
                    stato="PASS",
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

    # --- T06 - Token Refresh ---
    async def _test_t06_token_refresh(self) -> RisultatoTest:
        client = self._get_client()
        if not self.endpoint_refresh:
            return RisultatoTest(
                test_id="T06",
                nome="Token Refresh",
                stato="PASS",
                severita="INFO",
                dettagli="Endpoint refresh non rilevato."
            )
        try:
            # Send invalid refresh token
            payload = {"refresh_token": "invalid_refresh_token_xyz"}
            res = await client.post(self.endpoint_refresh, json=payload)
            if res.status_code == 200:
                return RisultatoTest(
                    test_id="T06",
                    nome="Token Refresh",
                    stato="FAIL",
                    severita="HIGH",
                    dettagli="L'endpoint di refresh accetta refresh token non validi."
                )
            return RisultatoTest(
                test_id="T06",
                nome="Token Refresh",
                stato="PASS",
                severita="INFO",
                dettagli="Refresh token non validi vengono correttamente respinti."
            )
        except Exception as e:
            return RisultatoTest(
                test_id="T06",
                nome="Token Refresh",
                stato="FAIL",
                severita="HIGH",
                dettagli=f"Eccezione inattesa: {e}"
            )

    # --- T07 - Password Reset Debole ---
    async def _test_t07_weak_password_reset(self) -> RisultatoTest:
        client = self._get_client()
        if not self.endpoint_reset:
            return RisultatoTest(
                test_id="T07",
                nome="Password Reset Debole",
                stato="PASS",
                severita="INFO",
                dettagli="Endpoint reset non rilevato."
            )
        try:
            # Send weak or missing params reset request
            payload = {"email": ""}
            res = await client.post(self.endpoint_reset, json=payload)
            # Check if response exposes password or reset token in JSON
            if res.status_code == 200:
                text_lower = res.text.lower()
                for key in ["token", "password", "secret"]:
                    if key in text_lower and len(text_lower) < 200:
                        return RisultatoTest(
                            test_id="T07",
                            nome="Password Reset Debole",
                            stato="FAIL",
                            severita="HIGH",
                            dettagli=f"L'endpoint risponde con successo e leaks informazioni sensibili: {res.text}"
                        )
            return RisultatoTest(
                test_id="T07",
                nome="Password Reset Debole",
                stato="PASS",
                severita="INFO",
                dettagli="Nessuna debolezza immediata rilevata sull'endpoint di password reset."
            )
        except Exception as e:
            return RisultatoTest(
                test_id="T07",
                nome="Password Reset Debole",
                stato="FAIL",
                severita="HIGH",
                dettagli=f"Eccezione inattesa: {e}"
            )

    # --- T08 - Privilege Escalation via Token ---
    async def _test_t08_privilege_escalation(self) -> RisultatoTest:
        client = self._get_client()
        token = await self._login_and_get_token(client)
        if not token or self.tipo_token != "jwt":
            return RisultatoTest(
                test_id="T08",
                nome="Privilege Escalation via Token",
                stato="PASS",
                severita="INFO",
                dettagli="Token non presente o non JWT."
            )
        try:
            parts = token.split(".")
            if len(parts) == 3:
                header = base64url_decode(parts[0])
                payload = base64url_decode(parts[1])
                
                # Escalation claim modifications
                payload_escalated = payload.copy()
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
                stato="PASS",
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
            self._test_t04_user_enumeration,
            self._test_t05_token_reuse_post_logout,
            self._test_t06_token_refresh,
            self._test_t07_weak_password_reset,
            self._test_t08_privilege_escalation,
            self._test_t09_cookie_security_flags,
            self._test_t10_sensitive_info_disclosure
        ]

        for method in test_methods:
            try:
                test_res = await method()
                results.append(test_res)
            except Exception as e:
                # Under "Regole di esecuzione": Se un test solleva eccezione inattesa marcalo FAIL con severità HIGH
                # We name the test appropriately using its method name or a mapping
                test_id = method.__name__.split("_test_")[-1].split("_")[0].upper()
                test_name = " ".join(method.__name__.split("_test_")[-1].split("_")[1:]).title()
                results.append(RisultatoTest(
                    test_id=test_id,
                    nome=test_name,
                    stato="FAIL",
                    severita="HIGH",
                    dettagli=f"Eccezione imprevista durante l'esecuzione: {e}"
                ))

        return results

# --- Main Entry Point ---
async def run(
    stack: StackInfo,
    vulnerabilita: List[Vulnerabilita],
    config: Config
) -> List[RisultatoTest]:
    """
    Main entry point for Fase 4: Test Dinamico.
    Instantiates DynamicTester, runs the health check, discovers endpoints, and executes security tests.
    """
    logger.info("Avvio Fase 4 - Test Dinamico per Broken Authentication")
    tester = DynamicTester(config)
    results = await tester.run_all(stack, vulnerabilita)
    logger.info(f"Fase 4 completata. Eseguiti {len(results)} test dinamici.")
    return results
