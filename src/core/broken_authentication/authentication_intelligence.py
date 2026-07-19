"""
Broken Authentication - Authentication Intelligence Engine (Fase 3).
Correlates findings from Discovery, AST Analysis, OpenAPI specs, and Runtime Traffic
to build a structured model (AuthenticationKnowledgeGraph) of application authentication.
"""

import base64
import json
import re
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import BaseModel

from src.core.broken_authentication.ast_parser import FileScore
from src.core.broken_authentication.discovery import StackInfo


class AuthenticationKnowledgeGraph(BaseModel):
    authentication_type: str | None = None
    identity_provider: str | None = None
    login_endpoint: str | None = None
    refresh_endpoint: str | None = None
    logout_endpoint: str | None = None
    jwt_claims: list[str] = []
    roles: list[str] = []
    permissions: list[str] = []
    auth_middlewares: list[str] = []
    protected_endpoints: dict[str, Any] = {}
    auth_functions: list[str] = []
    confidence_score: float = 0.0
    idp_metadata: dict[str, Any] = {}
    jwks_validation_enabled: bool = False
    oauth_flows_metadata: dict[str, Any] = {}
    non_jwt_mechanisms: list[str] = []
    refresh_token_rotation: bool = False
    saml_detected: bool = False
    # Optional: JWT secret extracted by the AST parser from the source code.
    # When present, T02 uses it to produce a validly-signed expired token.
    jwt_secret: str | None = None

    # Extended fields
    refresh_token_supported: bool = False
    mfa_detected: bool | None = None
    mfa_type: str | None = None
    mfa_confidence: float = 0.0
    rate_limiting_detected: bool = False
    rate_limit_threshold: int | None = None
    authentication_score: dict[str, Any] | None = None


def base64url_decode(payload: str) -> dict:
    """Helper to decode base64url encoded strings safely (e.g. JWT parts)."""
    try:
        rem = len(payload) % 4
        if rem > 0:
            payload += "=" * (4 - rem)
        decoded = base64.urlsafe_b64decode(payload.encode("utf-8"))
        return json.loads(decoded.decode("utf-8"))
    except Exception as e:
        logger.debug(f"Error decoding base64url payload: {e}")
        return {}


def _extract_path_from_route(route_str: str) -> str | None:
    """Extracts a path from a route string, supporting quotes or raw paths."""
    # 1. Try quotes first
    matches = re.findall(r'["\']([^"\']+)["\']', route_str)
    if matches:
        for m in matches:
            if m.startswith("/") or "/" in m:
                return m.split("?")[0]
    # 2. Check if the whole string is a path
    if route_str.startswith("/") or "/" in route_str:
        cleaned = route_str.strip().split("?")[0]
        if not any(
            kw in cleaned for kw in ["def ", "function ", "func ", "class ", "@", "app.", "router."]
        ):
            return cleaned
    return None


class AuthenticationIntelligenceEngine:
    @staticmethod
    def decode_token_claims(token: str) -> dict:
        """Attempts to parse a token as a JWT and retrieve claims."""
        if not token:
            return {}
        parts = token.split(".")
        if len(parts) == 3:
            return base64url_decode(parts[1])
        return {}

    @staticmethod
    def correlate(
        discovery_output: StackInfo,
        ast_output: list[FileScore],
        openapi_spec: dict[str, Any] | None = None,
        runtime_traffic: list[dict[str, Any]] | None = None,
    ) -> AuthenticationKnowledgeGraph:
        """
        Correlates inputs from multiple stages to build a structured AuthenticationKnowledgeGraph.
        """
        logger.info("Avvio correlazione Authentication Intelligence Engine...")

        # Initialize collections
        auth_type = None
        identity_provider = discovery_output.identity_provider
        login_endpoint = None
        refresh_endpoint = None
        logout_endpoint = None

        jwt_claims_set: set[str] = set()
        roles_set: set[str] = set()
        permissions_set: set[str] = set()
        auth_middlewares_set: set[str] = set()
        protected_endpoints: dict[str, Any] = {}
        auth_functions_set: set[str] = set()
        idp_metadata: dict[str, Any] = {}

        # 1. Correlate Discovery Output
        auth_libs = [lib.lower() for lib in discovery_output.librerie_auth]
        if any(
            kw in "".join(auth_libs)
            for kw in ["jwt", "jose", "oauth", "auth0", "keycloak", "cognito", "okta"]
        ):
            auth_type = "JWT"
        elif any(kw in "".join(auth_libs) for kw in ["cookie", "session"]):
            auth_type = "Session"
        else:
            auth_type = "Opaque"

        # 2. Correlate AST Output
        for file_score in ast_output:
            auth_functions_set.update(file_score.auth_functions)
            jwt_claims_set.update(file_score.jwt_claims)
            auth_middlewares_set.update(file_score.auth_middlewares)

            # Map decorators/routes
            # First add raw route signals
            for route in file_score.route_auth:
                path = _extract_path_from_route(route)
                if path and path not in protected_endpoints:
                    protected_endpoints[path] = {"source": "AST", "required_roles": []}

            # Map decorator associations
            for func, role in file_score.auth_decorators.items():
                if role:
                    roles_set.add(role)
                # Associate the decorator role with matching paths
                # If a function name is found in route_auth, link it
                matched_path = None
                for route in file_score.route_auth:
                    if func in route:
                        path = _extract_path_from_route(route)
                        if path:
                            matched_path = path
                            break
                if matched_path:
                    if matched_path not in protected_endpoints:
                        protected_endpoints[matched_path] = {"source": "AST", "required_roles": []}
                    if role and role not in protected_endpoints[matched_path]["required_roles"]:
                        protected_endpoints[matched_path]["required_roles"].append(role)
                else:
                    # Key by function name if path mapping fails
                    protected_endpoints[func] = {
                        "source": "AST_decorator",
                        "required_roles": [role] if role else [],
                    }

            # Extract endpoints from routes if login/logout/refresh keywords are matched
            for route in file_score.route_auth:
                path = _extract_path_from_route(route)
                if path:
                    path_lower = path.lower()
                    if any(kw in path_lower for kw in ["login", "token", "signin"]):
                        if not login_endpoint or "login" in path_lower:
                            login_endpoint = path
                    if any(kw in path_lower for kw in ["logout", "signout"]):
                        logout_endpoint = path
                    if "refresh" in path_lower:
                        refresh_endpoint = path

        # 3. OpenAPI Correlation
        if openapi_spec:
            logger.info("Correlazione specifiche OpenAPI rilevata...")
            components = openapi_spec.get("components", {})
            security_schemes = components.get("securitySchemes", {})
            if security_schemes:
                for _scheme_name, scheme in security_schemes.items():
                    scheme_type = scheme.get("type", "").lower()
                    if scheme_type in ("oauth2", "openidconnect"):
                        auth_type = "OAuth2"
                    elif scheme_type == "http" and scheme.get("scheme", "").lower() == "bearer":
                        auth_type = "JWT"

            # Map protected paths from OpenAPI
            paths = openapi_spec.get("paths", {})
            for path, path_obj in paths.items():
                for method, method_obj in path_obj.items():
                    if not isinstance(method_obj, dict):
                        continue
                    # Check for security requirements at path/method level
                    security = method_obj.get("security") or openapi_spec.get("security")
                    if security:
                        if path not in protected_endpoints:
                            protected_endpoints[path] = {"source": "OpenAPI", "required_roles": []}
                        # Extract roles/scopes if present in oauth2 flow
                        for sec_item in security:
                            for scheme, scopes in sec_item.items():
                                for scope in scopes:
                                    permissions_set.add(scope)
                                    if "admin" in scope.lower():
                                        roles_set.add("admin")
                                    elif "user" in scope.lower():
                                        roles_set.add("user")

                    # Identify endpoints
                    path_lower = path.lower()
                    if any(kw in path_lower for kw in ["login", "token", "signin"]):
                        if not login_endpoint or "login" in path_lower:
                            login_endpoint = path
                    if any(kw in path_lower for kw in ["logout", "signout"]):
                        logout_endpoint = path
                    if "refresh" in path_lower:
                        refresh_endpoint = path

        # 4. Runtime Correlation
        if runtime_traffic:
            logger.info(f"Correlazione traffico runtime ({len(runtime_traffic)} entry)...")
            for entry in runtime_traffic:
                path = entry.get("path", "").split("?")[0]
                method = entry.get("method", "").upper()
                headers = entry.get("headers", {}) or {}

                # Check endpoints
                path_lower = path.lower()
                if method == "POST":
                    if any(kw in path_lower for kw in ["login", "token", "signin"]):
                        if not login_endpoint or "login" in path_lower:
                            login_endpoint = path
                    elif any(kw in path_lower for kw in ["logout", "signout"]):
                        logout_endpoint = path
                    elif "refresh" in path_lower:
                        refresh_endpoint = path

                # Check tokens and extract claims
                auth_header = headers.get("Authorization") or headers.get("authorization")
                token = None
                if auth_header and str(auth_header).lower().startswith("bearer "):
                    token = str(auth_header)[7:].strip()

                # Fallback to cookies
                if not token:
                    cookie_header = headers.get("Cookie") or headers.get("cookie")
                    if cookie_header:
                        # try to find token-like structures in cookies
                        token_match = re.search(
                            r"(?:access_token|token|session|jwt)=([^;]+)",
                            str(cookie_header),
                            re.IGNORECASE,
                        )
                        if token_match:
                            token = token_match.group(1).strip()

                if token:
                    claims = AuthenticationIntelligenceEngine.decode_token_claims(token)
                    if claims:
                        auth_type = "JWT"
                        jwt_claims_set.update(claims.keys())

                        # Extract roles
                        for role_key in [
                            "role",
                            "roles",
                            "groups",
                            "realm_access",
                            "resource_access",
                        ]:
                            if role_key in claims:
                                val = claims[role_key]
                                if isinstance(val, list):
                                    roles_set.update(str(v) for v in val)
                                elif isinstance(val, dict):
                                    # Keycloak format: realm_access = {"roles": [...]}
                                    roles_set.update(str(v) for v in val.get("roles", []))
                                else:
                                    roles_set.add(str(val))

                        # Extract permissions
                        for perm_key in ["permissions", "permission", "scope", "scopes"]:
                            if perm_key in claims:
                                val = claims[perm_key]
                                if isinstance(val, list):
                                    permissions_set.update(str(v) for v in val)
                                elif isinstance(val, str):
                                    permissions_set.update(
                                        v.strip() for v in val.split(" ") if v.strip()
                                    )

        # 5. Identity Provider Intelligence
        if identity_provider:
            idp_name = identity_provider.lower().strip()
            logger.info(
                f"Rilevato Identity Provider: {identity_provider}. Popolamento metadati OIDC..."
            )

            # Default OIDC settings for known providers
            if "keycloak" in idp_name:
                idp_metadata = {
                    "realm": "master",
                    "clients": ["security-admin-console", "admin-cli", "account"],
                    "grant_types": [
                        "authorization_code",
                        "client_credentials",
                        "password",
                        "refresh_token",
                    ],
                    "issuer": "http://localhost:8080/realms/master",
                    "jwks_uri": "http://localhost:8080/realms/master/protocol/openid-connect/certs",
                    "roles": ["admin", "user", "offline_access", "uma_authorization"],
                }
            elif "auth0" in idp_name:
                idp_metadata = {
                    "realm": "default",
                    "clients": ["webapp-client", "api-backend"],
                    "grant_types": ["authorization_code", "client_credentials", "refresh_token"],
                    "issuer": "https://auth.auth0.com/",
                    "jwks_uri": "https://auth.auth0.com/.well-known/jwks.json",
                    "roles": ["admin", "user", "editor"],
                }
            elif "cognito" in idp_name or "aws" in idp_name:
                idp_metadata = {
                    "realm": "user-pool",
                    "clients": ["client-app"],
                    "grant_types": ["authorization_code", "implicit", "refresh_token"],
                    "issuer": "https://cognito-idp.amazonaws.com/",
                    "jwks_uri": "https://cognito-idp.amazonaws.com/.well-known/jwks.json",
                    "roles": ["admin", "user"],
                }
            elif "okta" in idp_name:
                idp_metadata = {
                    "realm": "default",
                    "clients": ["okta-app"],
                    "grant_types": ["authorization_code", "client_credentials", "refresh_token"],
                    "issuer": "https://okta.com/oauth2/default",
                    "jwks_uri": "https://okta.com/oauth2/default/v1/keys",
                    "roles": ["admin", "user"],
                }
            else:
                idp_metadata = {
                    "realm": "default",
                    "grant_types": ["authorization_code", "refresh_token"],
                    "roles": ["admin", "user"],
                }

            # Enrich Roles and Claims based on IdP defaults
            roles_set.update(idp_metadata.get("roles", []))

        # SAML Correlation & Configuration extraction
        is_saml_detected = any("saml" in lib.lower() for lib in discovery_output.librerie_auth)
        saml_entity_id = None
        saml_acs_url = None
        saml_certs = []

        if is_saml_detected:
            logger.info("Librerie SAML rilevate nel Discovery. Ricerca configurazioni SAML...")
            for rel_file in discovery_output.file_configurazione_rilevanti:
                file_path = Path(rel_file)
                if file_path.is_file():
                    try:
                        content = file_path.read_text(encoding="utf-8", errors="replace")
                        # Extract ACS URL
                        acs_match = re.search(
                            r'(?:acs_url|assertionConsumerServiceUrl|acsUrl)["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                            content,
                            re.I,
                        )
                        if acs_match:
                            saml_acs_url = acs_match.group(1)
                        # Extract Entity ID
                        entity_match = re.search(
                            r'(?:entity_id|entityId|issuer|entityID)["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                            content,
                            re.I,
                        )
                        if entity_match:
                            saml_entity_id = entity_match.group(1)
                        # Extract Certificates
                        cert_matches = re.findall(
                            r"-----BEGIN CERTIFICATE-----\s*([^-]+)\s*-----END CERTIFICATE-----",
                            content,
                        )
                        for m in cert_matches:
                            saml_certs.append(m.strip().replace("\n", "").replace("\r", ""))
                    except Exception as e:
                        logger.debug(f"Errore parsing configurazioni SAML nel file {rel_file}: {e}")

            if not identity_provider:
                identity_provider = "SAML IdP"
            idp_metadata = {
                "entity_id": saml_entity_id or "urn:example:sp",
                "acs_url": saml_acs_url or "/saml/acs",
                "certificates_found": len(saml_certs),
                "certificates": saml_certs[:3],
            }

        # Ensure standard roles & claims are always represented if empty
        if not roles_set:
            roles_set.update(["admin", "user"])
        if not jwt_claims_set and auth_type in ("JWT", "OAuth2"):
            jwt_claims_set.update(["sub", "role", "roles", "exp"])

        # Extract new security metadata from AST, OpenAPI and Discovery
        jwks_signals = False
        redirect_uri_signals = False
        state_signals = False
        pkce_signals = False
        refresh_rotation_signals = False
        non_jwt_detected = set(
            discovery_output.non_jwt_mechanisms
            if hasattr(discovery_output, "non_jwt_mechanisms")
            else []
        )

        # Scan AST outputs
        for file_score in ast_output:
            all_file_signals = (
                " ".join(file_score.imports_auth)
                + " "
                + " ".join(file_score.route_auth)
                + " "
                + " ".join(file_score.chiamate_auth)
                + " "
                + " ".join(file_score.auth_functions)
                + " "
                + " ".join(file_score.env_vars_auth)
            ).lower()

            if any(
                k in all_file_signals
                for k in ["jwks", "jwk_client", "pyjwkclient", "jwksclient", "jwk-client"]
            ):
                jwks_signals = True
            if "redirect_uri" in all_file_signals:
                redirect_uri_signals = True
            if "state" in all_file_signals:
                state_signals = True
            if any(k in all_file_signals for k in ["code_challenge", "code_verifier", "pkce"]):
                pkce_signals = True
            if (
                any(
                    k in all_file_signals
                    for k in ["rotation", "rotate", "revoke", "reuse_detection", "invalidat"]
                )
                and "refresh" in all_file_signals
            ):
                refresh_rotation_signals = True

            if "basic" in all_file_signals:
                non_jwt_detected.add("Basic Auth")
            if (
                "api_key" in all_file_signals
                or "apikey" in all_file_signals
                or "x-api-key" in all_file_signals
            ):
                non_jwt_detected.add("API Key")
            if any(
                k in all_file_signals
                for k in [
                    "client.crt",
                    "client.key",
                    "mtls",
                    "mutual_tls",
                    "client-cert",
                    "client_cert",
                ]
            ):
                non_jwt_detected.add("mTLS")

        # Scan OpenAPI specs
        if openapi_spec:
            components = openapi_spec.get("components", {})
            security_schemes = components.get("securitySchemes", {})
            if security_schemes:
                for _scheme_name, scheme in security_schemes.items():
                    scheme_type = scheme.get("type", "").lower()
                    if scheme_type == "apikey" or scheme.get("name", "").lower() in (
                        "x-api-key",
                        "api_key",
                        "apikey",
                    ):
                        non_jwt_detected.add("API Key")
                    elif scheme_type == "http" and scheme.get("scheme", "").lower() == "basic":
                        non_jwt_detected.add("Basic Auth")
                    elif scheme_type == "http" and scheme.get("scheme", "").lower() == "mtls":
                        non_jwt_detected.add("mTLS")

            paths = openapi_spec.get("paths", {})
            for path, path_obj in paths.items():
                for method, method_obj in path_obj.items():
                    if not isinstance(method_obj, dict):
                        continue
                    parameters = method_obj.get("parameters", [])
                    for param in parameters:
                        param_name = param.get("name", "").lower()
                        if "redirect_uri" in param_name:
                            redirect_uri_signals = True
                        if "state" in param_name:
                            state_signals = True
                        if "code_challenge" in param_name or "code_verifier" in param_name:
                            pkce_signals = True

        # Scan crawled routes from Discovery Crawler
        if getattr(discovery_output, "crawled_routes", None):
            for route_path, method in discovery_output.crawled_routes.items():
                if route_path not in protected_endpoints:
                    protected_endpoints[route_path] = {
                        "source": "crawler",
                        "method": method,
                        "required_roles": [],
                    }
                # Also identify endpoints if they match login/logout/refresh keywords
                path_lower = route_path.lower()
                if any(kw in path_lower for kw in ["login", "token", "signin"]):
                    if not login_endpoint or "login" in path_lower:
                        login_endpoint = route_path
                if any(kw in path_lower for kw in ["logout", "signout"]):
                    logout_endpoint = route_path
                if "refresh" in path_lower:
                    refresh_endpoint = route_path

        # 6. Confidence Score Calculation
        # Complete metrics configuration
        confidence_score = 0.1  # base score
        if discovery_output.linguaggio and discovery_output.framework:
            confidence_score += 0.1
        if ast_output:
            confidence_score += 0.2
            # Check if we have auth functions / decorators
            if auth_functions_set or auth_middlewares_set:
                confidence_score += 0.1
        if openapi_spec:
            confidence_score += 0.2
        if runtime_traffic:
            confidence_score += 0.3
        if identity_provider:
            confidence_score += 0.1

        # Boost confidence score if the key stack information was found heuristically
        heuristic_boost = 0.0
        if getattr(discovery_output, "discovery_methods", None):
            heuristic_count = sum(
                1 for v in discovery_output.discovery_methods.values() if v == "heuristic"
            )
            heuristic_boost = heuristic_count * 0.05
        confidence_score += heuristic_boost

        confidence_score = min(1.0, round(confidence_score, 2))

        # 7. Refresh Token, MFA and Rate Limiting details correlation
        # Refresh token support
        refresh_token_supported = False
        if refresh_endpoint is not None or refresh_rotation_signals:
            refresh_token_supported = True
        else:
            if any("refresh" in lib.lower() for lib in discovery_output.librerie_auth) or any(
                "refresh" in func.lower() for func in auth_functions_set
            ):
                refresh_token_supported = True

        # MFA Detection
        mfa_detected = None
        mfa_type = None
        mfa_confidence = 0.0

        known_idps = ["keycloak", "auth0", "cognito", "azure", "okta"]
        has_known_idp = identity_provider and any(
            idp in identity_provider.lower() for idp in known_idps
        )

        mfa_signals = []
        for file_score in ast_output:
            mfa_signals.append(" ".join(file_score.imports_auth).lower())
            mfa_signals.append(" ".join(file_score.route_auth).lower())
            mfa_signals.append(" ".join(file_score.chiamate_auth).lower())
            mfa_signals.append(" ".join(file_score.auth_functions).lower())
            mfa_signals.append(" ".join(file_score.auth_middlewares).lower())
            mfa_signals.append(" ".join(file_score.env_vars_auth).lower())

        if openapi_spec:
            mfa_signals.append(json.dumps(openapi_spec).lower())

        for rel_file in discovery_output.file_configurazione_rilevanti:
            mfa_signals.append(rel_file.lower())

        mfa_text_combined = " ".join(mfa_signals)

        mfa_keywords = [
            "mfa",
            "totp",
            "2fa",
            "otp",
            "twofactor",
            "two_factor",
            "google_auth",
            "duo",
            "authenticator",
        ]
        has_mfa_keywords = any(kw in mfa_text_combined for kw in mfa_keywords)

        if has_known_idp or has_mfa_keywords:
            mfa_detected = True
            if any(kw in mfa_text_combined for kw in ["totp", "google_auth", "authenticator"]):
                mfa_type = "TOTP"
            elif "sms" in mfa_text_combined or "phone" in mfa_text_combined:
                mfa_type = "SMS"
            elif "email" in mfa_text_combined:
                mfa_type = "Email"
            elif any(kw in mfa_text_combined for kw in ["webauthn", "fido", "yubikey"]):
                mfa_type = "WebAuthn"
            elif has_known_idp:
                mfa_type = "IdP-Managed"
            else:
                mfa_type = "Custom"

            mfa_confidence = 0.5 if has_known_idp else 0.3
            if any(kw in mfa_text_combined for kw in ["mfa", "2fa", "totp"]):
                mfa_confidence += 0.2
            if (
                "/mfa" in mfa_text_combined
                or "/2fa" in mfa_text_combined
                or "/otp" in mfa_text_combined
            ):
                mfa_confidence += 0.2
            if any(kw in mfa_text_combined for kw in ["verify_mfa", "mfa_verify", "check_mfa"]):
                mfa_confidence += 0.1
            mfa_confidence = min(1.0, round(mfa_confidence, 2))

        # Rate Limiting detection
        rate_limiting_detected = False
        rate_limit_threshold = None

        rate_limit_libs = [
            "limiter",
            "slowapi",
            "express-rate-limit",
            "tollbooth",
            "rate_limit",
            "throttle",
        ]
        rate_limit_text_signals = []
        for file_score in ast_output:
            rate_limit_text_signals.append(" ".join(file_score.imports_auth).lower())
            rate_limit_text_signals.append(" ".join(file_score.chiamate_auth).lower())
            rate_limit_text_signals.append(" ".join(file_score.auth_middlewares).lower())
            rate_limit_text_signals.append(" ".join(file_score.route_auth).lower())

        rate_limit_combined = " ".join(rate_limit_text_signals)
        if (
            any(lib in rate_limit_combined for lib in rate_limit_libs)
            or "rate" in rate_limit_combined
            or "limit" in rate_limit_combined
        ):
            rate_limiting_detected = True

            limit_matches = re.findall(
                r"(\d+)\s*/\s*(?:minute|hour|day|min|sec)", rate_limit_combined
            )
            if limit_matches:
                rate_limit_threshold = int(limit_matches[0])
            else:
                num_matches = re.findall(
                    r"limit.*?(?:count|max|threshold|value)?.*?(\d+)", rate_limit_combined
                )
                if num_matches:
                    rate_limit_threshold = int(num_matches[0])

        # Build output model
        graph = AuthenticationKnowledgeGraph(
            authentication_type=auth_type,
            identity_provider=identity_provider,
            login_endpoint=login_endpoint,
            refresh_endpoint=refresh_endpoint,
            logout_endpoint=logout_endpoint,
            jwt_claims=sorted(jwt_claims_set),
            roles=sorted(roles_set),
            permissions=sorted(permissions_set),
            auth_middlewares=sorted(auth_middlewares_set),
            protected_endpoints=protected_endpoints,
            auth_functions=sorted(auth_functions_set),
            confidence_score=confidence_score,
            idp_metadata=idp_metadata,
            jwks_validation_enabled=jwks_signals,
            oauth_flows_metadata={
                "redirect_uri_checked": redirect_uri_signals,
                "state_checked": state_signals,
                "pkce_checked": pkce_signals,
            },
            non_jwt_mechanisms=sorted(non_jwt_detected),
            refresh_token_rotation=refresh_rotation_signals,
            saml_detected=is_saml_detected,
            refresh_token_supported=refresh_token_supported,
            mfa_detected=mfa_detected,
            mfa_type=mfa_type,
            mfa_confidence=mfa_confidence,
            rate_limiting_detected=rate_limiting_detected,
            rate_limit_threshold=rate_limit_threshold,
        )

        logger.info(f"Consolidamento completato. Confidence score: {confidence_score}")
        return graph
