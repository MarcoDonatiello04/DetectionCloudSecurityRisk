import pytest
from src.core.broken_authentication.discovery import StackInfo
from src.core.broken_authentication.ast_parser import FileScore
from src.core.broken_authentication.authentication_intelligence import (
    AuthenticationIntelligenceEngine, AuthenticationKnowledgeGraph, base64url_decode
)


def test_base64url_decode():
    # Valid base64url string for {"alg": "HS256"}
    decoded = base64url_decode("eyJhbGciOiJIUzI1NiJ9")
    assert decoded == {"alg": "HS256"}

    # Invalid input
    assert base64url_decode("invalid_base64") == {}


def test_jwt_apps_correlation():
    discovery = StackInfo(
        linguaggio="Python",
        framework="FastAPI",
        librerie_auth=["PyJWT"],
        identity_provider=None,
        file_configurazione_rilevanti=["main.py"]
    )

    ast_output = [
        FileScore(
            file="main.py",
            imports_auth=["import jwt"],
            route_auth=["@app.post('/login')", "@app.get('/api/profile')"],
            env_vars_auth=["JWT_SECRET"],
            chiamate_auth=["jwt.decode"],
            score=4,
            auth_functions=["login", "verify_token"],
            jwt_claims=["sub", "role"],
            auth_decorators={"profile": "user"},
            auth_middlewares=[]
        )
    ]

    openapi = {
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer"
                }
            }
        },
        "paths": {
            "/api/profile": {
                "get": {
                    "security": [{"bearerAuth": []}]
                }
            }
        }
    }

    graph = AuthenticationIntelligenceEngine.correlate(
        discovery_output=discovery,
        ast_output=ast_output,
        openapi_spec=openapi
    )

    assert graph.authentication_type == "JWT"
    assert graph.login_endpoint == "/login"
    assert "sub" in graph.jwt_claims
    assert "role" in graph.jwt_claims
    assert "user" in graph.roles
    assert "/api/profile" in graph.protected_endpoints
    assert graph.confidence_score > 0.5


def test_oauth2_apps_correlation():
    discovery = StackInfo(
        linguaggio="JavaScript",
        framework="Express",
        librerie_auth=["oauth2-server"],
        identity_provider=None,
        file_configurazione_rilevanti=[]
    )

    ast_output = []

    openapi = {
        "components": {
            "securitySchemes": {
                "oauth2": {
                    "type": "oauth2",
                    "flows": {}
                }
            }
        },
        "paths": {
            "/oauth/token": {
                "post": {}
            }
        }
    }

    graph = AuthenticationIntelligenceEngine.correlate(
        discovery_output=discovery,
        ast_output=ast_output,
        openapi_spec=openapi
    )

    assert graph.authentication_type == "OAuth2"
    assert graph.login_endpoint == "/oauth/token"
    assert graph.confidence_score > 0.3


def test_keycloak_apps_correlation():
    discovery = StackInfo(
        linguaggio="Java",
        framework="Spring Boot",
        librerie_auth=["spring-boot-starter-oauth2-resource-server"],
        identity_provider="Keycloak",
        file_configurazione_rilevanti=["application.yml"]
    )

    ast_output = [
        FileScore(
            file="Controller.java",
            imports_auth=[],
            route_auth=["/api/admin"],
            env_vars_auth=[],
            chiamate_auth=[],
            score=1,
            auth_functions=[],
            jwt_claims=[],
            auth_decorators={"getAdmin": "admin"},
            auth_middlewares=["KeycloakWebSecurityConfigurer"]
        )
    ]

    graph = AuthenticationIntelligenceEngine.correlate(
        discovery_output=discovery,
        ast_output=ast_output
    )

    assert graph.authentication_type == "JWT"
    assert graph.identity_provider == "Keycloak"
    assert "KeycloakWebSecurityConfigurer" in graph.auth_middlewares
    assert "admin" in graph.roles
    assert graph.idp_metadata.get("realm") == "master"
    assert "jwks_uri" in graph.idp_metadata


def test_absence_openapi_and_runtime():
    discovery = StackInfo(
        linguaggio="Python",
        framework="Flask",
        librerie_auth=["flask_login"],
        identity_provider=None,
        file_configurazione_rilevanti=[]
    )

    ast_output = [
        FileScore(
            file="app.py",
            imports_auth=["flask_login"],
            route_auth=["/signin", "/signout", "/refresh_session"],
            env_vars_auth=[],
            chiamate_auth=[],
            score=2,
            auth_functions=["signin", "signout"],
            jwt_claims=[],
            auth_decorators={},
            auth_middlewares=["AuthenticationMiddleware"]
        )
    ]

    graph = AuthenticationIntelligenceEngine.correlate(
        discovery_output=discovery,
        ast_output=ast_output,
        openapi_spec=None,
        runtime_traffic=None
    )

    # Absence of OpenAPI/runtime, fallbacks on AST route/names
    assert graph.login_endpoint == "/signin"
    assert graph.logout_endpoint == "/signout"
    assert graph.refresh_endpoint == "/refresh_session"
    assert "AuthenticationMiddleware" in graph.auth_middlewares
    # Low confidence since OpenAPI and runtime logs are missing
    assert graph.confidence_score <= 0.6


def test_runtime_traffic_correlation():
    discovery = StackInfo(
        linguaggio="Go",
        framework="Gin",
        librerie_auth=["jwt-go"],
        identity_provider=None,
        file_configurazione_rilevanti=[]
    )

    # Base64url encoded payload: {"sub":"user123","role":"operator","scope":"read write"}
    # Header: {"alg":"HS256","typ":"JWT"}
    # we simulate the base64 encoded token
    # eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6Im9wZXJhdG9yIiwic2NvcGUiOiJyZWFkIHdyaXRlIn0.signature
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6Im9wZXJhdG9yIiwic2NvcGUiOiJyZWFkIHdyaXRlIn0.signature"

    runtime_traffic = [
        {
            "method": "POST",
            "path": "/api/v1/auth/login",
            "headers": {},
            "body_params": {}
        },
        {
            "method": "GET",
            "path": "/api/v1/users/profile",
            "headers": {
                "Authorization": f"Bearer {token}"
            },
            "body_params": {}
        }
    ]

    graph = AuthenticationIntelligenceEngine.correlate(
        discovery_output=discovery,
        ast_output=[],
        runtime_traffic=runtime_traffic
    )

    assert graph.login_endpoint == "/api/v1/auth/login"
    assert "sub" in graph.jwt_claims
    assert "role" in graph.jwt_claims
    assert "operator" in graph.roles
    assert "read" in graph.permissions
    assert graph.confidence_score >= 0.4


def test_unknown_repositories():
    # Empty stack discovery and AST output to represent an unknown repo
    discovery = StackInfo(
        linguaggio="Unknown",
        framework="Unknown",
        librerie_auth=[],
        identity_provider=None,
        file_configurazione_rilevanti=[]
    )

    graph = AuthenticationIntelligenceEngine.correlate(
        discovery_output=discovery,
        ast_output=[]
    )

    assert graph.authentication_type == "Opaque"
    assert graph.confidence_score <= 0.2


def test_extra_idps_correlation():
    for idp in ["Auth0", "AWS Cognito", "Okta", "OtherIDP"]:
        discovery = StackInfo(
            linguaggio="Python",
            framework="Django",
            librerie_auth=[],
            identity_provider=idp,
            file_configurazione_rilevanti=[]
        )
        graph = AuthenticationIntelligenceEngine.correlate(
            discovery_output=discovery,
            ast_output=[]
        )
        assert graph.identity_provider == idp
        assert "roles" in graph.idp_metadata or idp == "OtherIDP"
        if idp == "Auth0":
            assert graph.idp_metadata["realm"] == "default"
            assert "webapp-client" in graph.idp_metadata["clients"]
        elif idp == "AWS Cognito":
            assert graph.idp_metadata["realm"] == "user-pool"
        elif idp == "Okta":
            assert "okta-app" in graph.idp_metadata["clients"]


def test_cookie_runtime_correlation():
    discovery = StackInfo(
        linguaggio="Python",
        framework="Flask",
        librerie_auth=[],
        identity_provider=None,
        file_configurazione_rilevanti=[]
    )
    # Token payload: {"sub": "cookie_user", "roles": ["editor"], "permissions": "write"}
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjb29raWVfdXNlciIsInJvbGVzIjpbImVkaXRvciJdLCJwZXJtaXNzaW9ucyI6IndyaXRlIn0.signature"
    runtime_traffic = [
        {
            "method": "GET",
            "path": "/api/profile",
            "headers": {
                "Cookie": f"jwt={token}"
            }
        }
    ]
    graph = AuthenticationIntelligenceEngine.correlate(
        discovery_output=discovery,
        ast_output=[],
        runtime_traffic=runtime_traffic
    )
    assert graph.authentication_type == "JWT"
    assert "cookie_user" in graph.jwt_claims or "sub" in graph.jwt_claims
    assert "editor" in graph.roles


def test_decode_token_claims_invalid():
    assert AuthenticationIntelligenceEngine.decode_token_claims(None) == {}
    assert AuthenticationIntelligenceEngine.decode_token_claims("") == {}
    assert AuthenticationIntelligenceEngine.decode_token_claims("not.a.jwt") == {}
