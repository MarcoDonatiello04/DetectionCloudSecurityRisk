import pytest
from unittest.mock import MagicMock, patch, AsyncMock
import httpx
import asyncio

from src.core.broken_authentication.dynamic_tester import (
    DynamicTester, run, EndpointNotFoundException, HealthCheckException,
    Vulnerabilita, RisultatoTest, base64url_encode, base64url_decode
)
from src.core.broken_authentication.discovery import StackInfo, Config

# --- Helper to create a mock httpx.AsyncClient ---
def create_mock_client(get_responses=None, post_responses=None):
    client = MagicMock(spec=httpx.AsyncClient)
    client.base_url = httpx.URL("http://localhost:5000")
    
    async def mock_get(url, headers=None, **kwargs):
        path = str(url).replace("http://localhost:5000", "")
        if not path.startswith("/"):
            path = "/" + path
            
        if get_responses and path in get_responses:
            resp = get_responses[path]
            if callable(resp) and not isinstance(resp, (MagicMock, AsyncMock)):
                return await resp(headers)
            return resp
        resp = MagicMock(status_code=404)
        resp.text = "Not Found"
        return resp
        
    async def mock_post(url, json=None, headers=None, **kwargs):
        path = str(url).replace("http://localhost:5000", "")
        if not path.startswith("/"):
            path = "/" + path
            
        if post_responses and path in post_responses:
            resp = post_responses[path]
            if callable(resp) and not isinstance(resp, (MagicMock, AsyncMock)):
                return await resp(json, headers)
            return resp
        resp = MagicMock(status_code=404)
        resp.text = "Not Found"
        return resp
        
    client.get = mock_get
    client.post = mock_post
    return client

# --- Tests for Health Check ---

@pytest.mark.asyncio
async def test_health_check_success():
    config = Config()
    config.docker.timeout_startup = 2
    
    mock_resp = MagicMock(status_code=200)
    mock_resp.text = "OK"
    mock_client = create_mock_client(get_responses={"/": mock_resp})
    
    tester = DynamicTester(config, client=mock_client)
    await tester.health_check()  # Should complete successfully without raising exception

@pytest.mark.asyncio
async def test_health_check_failure():
    config = Config()
    config.docker.timeout_startup = 1  # Fast timeout
    
    mock_resp = MagicMock(status_code=500)
    mock_resp.text = "Internal Server Error"
    # Return 500 for all paths to simulate failure
    mock_client = create_mock_client(get_responses={"/": mock_resp, "/health": mock_resp})
    
    tester = DynamicTester(config, client=mock_client)
    with pytest.raises(HealthCheckException) as exc_info:
        await tester.health_check()
    assert "non è raggiungibile o restituisce errori 500" in str(exc_info.value)

# --- Tests for Endpoint Discovery ---

@pytest.mark.asyncio
async def test_discover_endpoints_openapi_success():
    config = Config()
    stack = StackInfo(
        linguaggio="python",
        framework="FastAPI",
        librerie_auth=["jwt"],
        file_configurazione_rilevanti=[]
    )
    
    openapi_mock = {
        "paths": {
            "/api/v1/auth/login": {},
            "/api/v1/auth/logout": {},
            "/api/v1/auth/refresh": {},
            "/api/v1/auth/reset": {}
        }
    }
    mock_resp = MagicMock(status_code=200)
    mock_resp.json = lambda: openapi_mock
    mock_client = create_mock_client(get_responses={"/openapi.json": mock_resp})
    
    tester = DynamicTester(config, client=mock_client)
    await tester.discover_endpoints(stack, [])
    
    assert tester.endpoint_auth == "/api/v1/auth/login"
    assert tester.endpoint_logout == "/api/v1/auth/logout"
    assert tester.endpoint_refresh == "/api/v1/auth/refresh"
    assert tester.endpoint_reset == "/api/v1/auth/reset"
    assert tester.tipo_token == "jwt"

@pytest.mark.asyncio
async def test_discover_endpoints_fallback():
    config = Config()
    stack = StackInfo(
        linguaggio="python",
        framework="FastAPI",
        librerie_auth=["jwt"],
        file_configurazione_rilevanti=[]
    )
    
    # OpenAPI returns 404
    mock_client = create_mock_client()
    
    vulnerabilities = [
        Vulnerabilita(
            id="V01",
            tipo="static",
            descrizione="Static auth route",
            file="routes.py",
            linea=10,
            route_auth=[
                "@app.post('/login_fallback')",
                "@app.post('/logout_fallback')",
                "@app.post('/refresh_fallback')",
                "@app.post('/reset_fallback')"
            ]
        )
    ]
    
    tester = DynamicTester(config, client=mock_client)
    await tester.discover_endpoints(stack, vulnerabilities)
    
    assert tester.endpoint_auth == "/login_fallback"
    assert tester.endpoint_logout == "/logout_fallback"
    assert tester.endpoint_refresh == "/refresh_fallback"
    assert tester.endpoint_reset == "/reset_fallback"

@pytest.mark.asyncio
async def test_discover_endpoints_not_found():
    config = Config()
    stack = StackInfo(
        linguaggio="python",
        framework="FastAPI",
        librerie_auth=["jwt"],
        file_configurazione_rilevanti=[]
    )
    mock_client = create_mock_client()
    
    tester = DynamicTester(config, client=mock_client)
    with pytest.raises(EndpointNotFoundException):
        await tester.discover_endpoints(stack, [])

# --- Tests for T01 - T10 ---

@pytest.mark.asyncio
async def test_t01_jwt_manipulation_pass():
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_auth = "/login"
    tester.tipo_token = "jwt"
    
    # Valid JWT token
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "testuser", "exp": 1999999999}
    valid_token = base64url_encode(header) + "." + base64url_encode(payload) + ".signature"
    
    # Login mock returns token
    async def mock_login(json_body, headers):
        resp = MagicMock(status_code=200)
        resp.json = lambda: {"access_token": valid_token}
        return resp
    
    # Profile GET mock rejects manipulated tokens
    async def mock_profile(headers):
        auth = headers.get("Authorization", "") if headers else ""
        if auth.startswith("Bearer "):
            token = auth.split(" ")[1]
            parts = token.split(".")
            if len(parts) >= 2:
                try:
                    hdr = base64url_decode(parts[0])
                    if hdr.get("alg") == "none":
                        resp = MagicMock(status_code=401)
                        resp.text = "Unauthorized (alg none)"
                        return resp
                except Exception:
                    pass
            if "modified" in token:
                resp = MagicMock(status_code=401)
                resp.text = "Unauthorized (tampered)"
                return resp
        resp = MagicMock(status_code=200)
        resp.text = "OK"
        return resp

    tester._client = create_mock_client(
        get_responses={"/api/profile": mock_profile},
        post_responses={"/login": mock_login}
    )
    
    result = await tester._test_t01_jwt_manipulation()
    assert result.stato == "PASS"

@pytest.mark.asyncio
async def test_t01_jwt_manipulation_fail():
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_auth = "/login"
    tester.tipo_token = "jwt"
    
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "testuser", "exp": 1999999999}
    valid_token = base64url_encode(header) + "." + base64url_encode(payload) + ".signature"
    
    async def mock_login(json_body, headers):
        resp = MagicMock(status_code=200)
        resp.json = lambda: {"access_token": valid_token}
        return resp
    
    # Profile returns 200 even for manipulated token (vulnerability!)
    async def mock_profile(headers):
        resp = MagicMock(status_code=200)
        resp.text = "Welcome admin"
        return resp

    tester._client = create_mock_client(
        get_responses={"/api/profile": mock_profile},
        post_responses={"/login": mock_login}
    )
    
    result = await tester._test_t01_jwt_manipulation()
    assert result.stato == "FAIL"
    assert result.severita == "CRITICAL"

@pytest.mark.asyncio
async def test_t02_expired_token():
    config = Config()
    tester = DynamicTester(config)
    
    # Expired token request to profile returns 401 (secure)
    resp = MagicMock(status_code=401)
    resp.text = "Token expired"
    mock_client = create_mock_client(get_responses={"/api/profile": resp})
    tester._client = mock_client
    
    result = await tester._test_t02_expired_token()
    assert result.stato == "PASS"

@pytest.mark.asyncio
async def test_t03_brute_force_rate_limiting_detected():
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_auth = "/login"
    
    # Mock returns 429 to trigger rate limit protection
    resp = MagicMock(status_code=429)
    resp.text = "Too Many Requests"
    mock_client = create_mock_client(post_responses={"/login": resp})
    tester._client = mock_client
    
    result = await tester._test_t03_brute_force_rate_limiting()
    assert result.stato == "PASS"
    assert "Rilevato blocco di sicurezza" in result.dettagli

@pytest.mark.asyncio
async def test_t03_brute_force_rate_limiting_missing():
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_auth = "/login"
    
    # Mock returns 401 continuously (no rate limiting)
    resp = MagicMock(status_code=401)
    resp.text = "Unauthorized"
    mock_client = create_mock_client(post_responses={"/login": resp})
    tester._client = mock_client
    
    result = await tester._test_t03_brute_force_rate_limiting()
    assert result.stato == "FAIL"
    assert "Nessun meccanismo di rate limiting" in result.dettagli

@pytest.mark.asyncio
async def test_t04_user_enumeration():
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_auth = "/login"
    
    # Different responses for nonexistent user (404) vs wrong password (401)
    async def mock_login(json_body, headers):
        if json_body.get("username") == "not_existent_user_9876":
            resp = MagicMock(status_code=404)
            resp.text = "User not found"
            return resp
        resp = MagicMock(status_code=401)
        resp.text = "Wrong password"
        return resp

    mock_client = create_mock_client(post_responses={"/login": mock_login})
    tester._client = mock_client
    
    result = await tester._test_t04_user_enumeration()
    assert result.stato == "FAIL"
    assert "Status code diversi" in result.dettagli or "messaggi di errore differiscono" in result.dettagli

@pytest.mark.asyncio
async def test_t05_token_reuse_post_logout():
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_auth = "/login"
    tester.endpoint_logout = "/logout"
    
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "testuser"}
    token = base64url_encode(header) + "." + base64url_encode(payload) + ".signature"
    
    async def mock_login(json_body, headers):
        resp = MagicMock(status_code=200)
        resp.json = lambda: {"access_token": token}
        return resp
        
    logged_out = False
    async def mock_logout(json_body, headers):
        nonlocal logged_out
        logged_out = True
        resp = MagicMock(status_code=200)
        resp.text = "Logged out"
        return resp
        
    async def mock_profile(headers):
        if logged_out:
            resp = MagicMock(status_code=401)
            resp.text = "Unauthorized"
            return resp
        resp = MagicMock(status_code=200)
        resp.text = "Profile"
        return resp

    mock_client = create_mock_client(
        get_responses={"/api/profile": mock_profile},
        post_responses={"/login": mock_login, "/logout": mock_logout}
    )
    tester._client = mock_client
    
    result = await tester._test_t05_token_reuse_post_logout()
    assert result.stato == "PASS"

@pytest.mark.asyncio
async def test_t06_token_refresh():
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_refresh = "/refresh"
    
    resp = MagicMock(status_code=400)
    resp.text = "Bad Request"
    mock_client = create_mock_client(post_responses={"/refresh": resp})
    tester._client = mock_client
    
    result = await tester._test_t06_token_refresh()
    assert result.stato == "PASS"

@pytest.mark.asyncio
async def test_t07_weak_password_reset():
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_reset = "/reset"
    
    # Reset password returns token leaks (vulnerable)
    resp = MagicMock(status_code=200)
    resp.text = '{"status":"ok", "token":"leak123"}'
    mock_client = create_mock_client(post_responses={"/reset": resp})
    tester._client = mock_client
    
    result = await tester._test_t07_weak_password_reset()
    assert result.stato == "FAIL"

@pytest.mark.asyncio
async def test_t08_privilege_escalation():
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_auth = "/login"
    tester.tipo_token = "jwt"
    
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "testuser", "role": "user"}
    token = base64url_encode(header) + "." + base64url_encode(payload) + ".signature"
    
    async def mock_login(json_body, headers):
        resp = MagicMock(status_code=200)
        resp.json = lambda: {"access_token": token}
        return resp
        
    # Rejects escalated role
    async def mock_admin(headers):
        auth = headers.get("Authorization", "") if headers else ""
        if auth.startswith("Bearer "):
            tkn = auth.split(" ")[1]
            parts = tkn.split(".")
            if len(parts) >= 2:
                try:
                    payl = base64url_decode(parts[1])
                    if payl.get("role") == "admin" or payl.get("isAdmin") is True:
                        if len(parts) == 3 and parts[2] == "":
                            resp = MagicMock(status_code=401)
                            resp.text = "Unauthorized"
                            return resp
                        resp = MagicMock(status_code=200)
                        resp.text = "Admin Area"
                        return resp
                except Exception:
                    pass
        resp = MagicMock(status_code=403)
        resp.text = "Forbidden"
        return resp

    mock_client = create_mock_client(
        get_responses={"/api/admin": mock_admin},
        post_responses={"/login": mock_login}
    )
    tester._client = mock_client
    
    result = await tester._test_t08_privilege_escalation()
    assert result.stato == "PASS"

@pytest.mark.asyncio
async def test_t09_cookie_security_flags_fail():
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_auth = "/login"
    
    # Returns login response cookie header without HttpOnly and Secure flags
    mock_resp = MagicMock(status_code=200)
    mock_resp.headers.get_list.return_value = ["session=123; Path=/"]
    mock_client = create_mock_client(post_responses={"/login": mock_resp})
    tester._client = mock_client
    
    result = await tester._test_t09_cookie_security_flags()
    assert result.stato == "FAIL"
    assert "HttpOnly, Secure" in result.dettagli

@pytest.mark.asyncio
async def test_t09_cookie_security_flags_pass():
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_auth = "/login"
    
    mock_resp = MagicMock(status_code=200)
    mock_resp.headers.get_list.return_value = ["session=123; Path=/; HttpOnly; Secure"]
    mock_client = create_mock_client(post_responses={"/login": mock_resp})
    tester._client = mock_client
    
    result = await tester._test_t09_cookie_security_flags()
    assert result.stato == "PASS"

@pytest.mark.asyncio
async def test_t10_sensitive_info_disclosure():
    config = Config()
    tester = DynamicTester(config)
    
    # Returns a Python traceback leak (vulnerable)
    error_resp = MagicMock(status_code=500)
    error_resp.text = "Traceback (most recent call last):\nFile 'app.py', line 12\nZeroDivisionError"
    mock_client = create_mock_client(get_responses={"/api/invalid_path_error_trigger_987": error_resp})
    tester._client = mock_client
    
    result = await tester._test_t10_sensitive_info_disclosure()
    assert result.stato == "FAIL"
    assert "Stack trace Python" in result.dettagli

# --- Test run() function ---

@pytest.mark.asyncio
async def test_run_function():
    config = Config()
    config.docker.timeout_startup = 2
    
    stack = StackInfo(
        linguaggio="python",
        framework="FastAPI",
        librerie_auth=["jwt"],
        file_configurazione_rilevanti=[]
    )
    
    openapi_mock = {
        "paths": {
            "/api/v1/auth/login": {},
        }
    }
    doc_resp = MagicMock(status_code=200)
    doc_resp.json = lambda: openapi_mock
    
    # Login return response
    login_resp = MagicMock(status_code=200)
    login_resp.json = lambda: {"access_token": "token"}
    login_resp.headers.get_list.return_value = []
    
    profile_resp = MagicMock(status_code=401)
    profile_resp.text = "Unauthorized"
    
    admin_resp = MagicMock(status_code=401)
    admin_resp.text = "Unauthorized"
    
    invalid_resp = MagicMock(status_code=404)
    invalid_resp.text = "Not Found"
    
    get_resps = {
        "/": MagicMock(status_code=200),
        "/openapi.json": doc_resp,
        "/api/profile": profile_resp,
        "/api/admin": admin_resp,
        "/api/invalid_path_error_trigger_987": invalid_resp
    }
    
    post_resps = {
        "/api/v1/auth/login": login_resp
    }
    
    mock_client = create_mock_client(get_responses=get_resps, post_responses=post_resps)
    
    with patch("src.core.broken_authentication.dynamic_tester.DynamicTester._get_client", return_value=mock_client):
        results = await run(stack, [], config)
        
        assert len(results) == 10
        assert all(isinstance(r, RisultatoTest) for r in results)
