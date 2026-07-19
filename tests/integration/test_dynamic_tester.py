from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.core.broken_authentication.discovery import Config, StackInfo
from src.core.broken_authentication.dynamic_tester import (
    DynamicTester,
    EndpointNotFoundException,
    HealthCheckException,
    RisultatoTest,
    Vulnerabilita,
    base64url_decode,
    base64url_encode,
    run,
)


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
        file_configurazione_rilevanti=[],
    )

    openapi_mock = {
        "paths": {
            "/api/v1/auth/login": {},
            "/api/v1/auth/logout": {},
            "/api/v1/auth/refresh": {},
            "/api/v1/auth/reset": {},
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
        file_configurazione_rilevanti=[],
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
                "@app.post('/reset_fallback')",
            ],
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
        file_configurazione_rilevanti=[],
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
        get_responses={"/api/profile": mock_profile}, post_responses={"/login": mock_login}
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
        get_responses={"/api/profile": mock_profile}, post_responses={"/login": mock_login}
    )

    result = await tester._test_t01_jwt_manipulation()
    assert result.stato == "FAIL"
    assert result.severita == "CRITICAL"


@pytest.mark.asyncio
async def test_t02_expired_token_pass_valid_sig():
    """
    PASS case: login succeeds, expired token (valid sig) is correctly rejected (401).
    """
    import base64 as _base64
    import hashlib as _hashlib
    import hmac as _hmac

    TEST_SECRET = "test-jwt-secret"

    config = Config()
    config.target.username = "user"
    config.target.password = "pass"

    from src.core.broken_authentication.authentication_intelligence import (
        AuthenticationKnowledgeGraph,
    )

    auth_intel = AuthenticationKnowledgeGraph(jwt_secret=TEST_SECRET, confidence_score=1.0)
    tester = DynamicTester(config, auth_intel=auth_intel)
    tester.endpoint_auth = "/login"

    # Build a real validly-signed token for the login mock
    import json as _json

    hdr_b = (
        _base64.urlsafe_b64encode(_json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        .rstrip(b"=")
        .decode()
    )
    pld_b = (
        _base64.urlsafe_b64encode(_json.dumps({"sub": "user", "exp": 9999999999}).encode())
        .rstrip(b"=")
        .decode()
    )
    si = f"{hdr_b}.{pld_b}".encode()
    raw_sig = _hmac.new(TEST_SECRET.encode(), si, _hashlib.sha256).digest()
    sig_b = _base64.urlsafe_b64encode(raw_sig).rstrip(b"=").decode()
    valid_token = f"{hdr_b}.{pld_b}.{sig_b}"

    async def mock_login(json_body, headers):
        resp = MagicMock(status_code=200)
        resp.json = lambda: {"access_token": valid_token}
        return resp

    # Profile rejects expired tokens (correct behaviour)
    profile_resp = MagicMock(status_code=401)
    profile_resp.text = "Token expired"

    mock_client = create_mock_client(
        get_responses={"/api/profile": profile_resp}, post_responses={"/login": mock_login}
    )
    tester._client = mock_client

    result = await tester._test_t02_expired_token()
    assert result.stato == "PASS", f"Expected PASS, got {result.stato}: {result.dettagli}"


@pytest.mark.asyncio
async def test_t02_expired_token_fail_valid_sig():
    """
    FAIL case: login succeeds, expired token (valid sig) is accepted (200).
    The test MUST detect this as a vulnerability.
    This matches VULN-02 exact scenario.
    """
    import base64 as _base64
    import hashlib as _hashlib
    import hmac as _hmac

    TEST_SECRET = "jwt-secret-do-not-use-in-prod"

    config = Config()
    config.target.username = "testuser"
    config.target.password = "testpass123"

    from src.core.broken_authentication.authentication_intelligence import (
        AuthenticationKnowledgeGraph,
    )

    auth_intel = AuthenticationKnowledgeGraph(jwt_secret=TEST_SECRET, confidence_score=1.0)
    tester = DynamicTester(config, auth_intel=auth_intel)
    tester.endpoint_auth = "/login"

    import json as _json

    hdr_b = (
        _base64.urlsafe_b64encode(_json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        .rstrip(b"=")
        .decode()
    )
    pld_b = (
        _base64.urlsafe_b64encode(_json.dumps({"sub": "testuser", "exp": 9999999999}).encode())
        .rstrip(b"=")
        .decode()
    )
    si = f"{hdr_b}.{pld_b}".encode()
    raw_sig = _hmac.new(TEST_SECRET.encode(), si, _hashlib.sha256).digest()
    sig_b = _base64.urlsafe_b64encode(raw_sig).rstrip(b"=").decode()
    valid_token = f"{hdr_b}.{pld_b}.{sig_b}"

    async def mock_login(json_body, headers):
        resp = MagicMock(status_code=200)
        resp.json = lambda: {"access_token": valid_token}
        return resp

    # Vulnerable app: accepts expired token (returns 200)
    profile_ok = MagicMock(status_code=200)
    profile_ok.text = '{"username":"testuser","role":"user"}'

    mock_client = create_mock_client(
        get_responses={"/api/profile": profile_ok}, post_responses={"/login": mock_login}
    )
    tester._client = mock_client

    result = await tester._test_t02_expired_token()
    assert result.stato == "FAIL", (
        f"Expired token with valid signature accepted → should be FAIL, got {result.stato}: {result.dettagli}"
    )
    assert "exp=1" in result.dettagli or "scaduti" in result.dettagli


@pytest.mark.asyncio
async def test_t02_expired_no_login_no_secret_inconclusive():
    """
    INCONCLUSIVE: login fails AND no jwt_secret → cannot build a valid-sig token.
    """
    config = Config()
    config.target.username = "user"
    config.target.password = "wrong"

    tester = DynamicTester(config)
    tester.endpoint_auth = "/login"

    # Login always fails
    async def mock_login(json_body, headers):
        return MagicMock(status_code=401)

    mock_client = create_mock_client(post_responses={"/login": mock_login})
    tester._client = mock_client

    result = await tester._test_t02_expired_token()
    assert result.stato == "INCONCLUSIVE", (
        f"No login + no secret should be INCONCLUSIVE, got {result.stato}: {result.dettagli}"
    )
    assert "firma valida" in result.dettagli or "segreto" in result.dettagli


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
async def test_t11_user_enumeration():
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_auth = "/login"

    # Different responses for nonexistent user vs wrong password (both return 401 to avoid A.1 status code gate)
    async def mock_login(json_body, headers):
        if json_body.get("username") == "not_existent_user_9876":
            resp = MagicMock(status_code=401)
            resp.text = "User not found or does not exist"
            return resp
        resp = MagicMock(status_code=401)
        resp.text = "Wrong password for this user"
        return resp

    mock_client = create_mock_client(post_responses={"/login": mock_login})
    tester._client = mock_client

    result = await tester._test_t11_user_enumeration()
    assert result.stato == "FAIL"
    assert "messaggi di errore differiscono" in result.dettagli


@pytest.mark.asyncio
async def test_t11_user_enumeration_structural_fail():
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_auth = "/login"

    # NON-REGRESSION: both fail with 400 Bad Request (structural format error)
    # → must remain INCONCLUSIVE after the T11 rewrite.
    async def mock_login(json_body, headers):
        resp = MagicMock(status_code=400)
        resp.text = "Bad Request: Schema validation failed"
        return resp

    mock_client = create_mock_client(post_responses={"/login": mock_login})
    tester._client = mock_client

    result = await tester._test_t11_user_enumeration()
    assert result.stato == "INCONCLUSIVE", (
        f"400/400 should be INCONCLUSIVE, got {result.stato}: {result.dettagli}"
    )
    # Message updated in T11 rewrite
    assert "non riconducibili" in result.dettagli or "formato non supportato" in result.dettagli


@pytest.mark.asyncio
async def test_t11_vuln05_exact_scenario_404_vs_401_fail():
    """
    VULN-05 exact scenario: non-existent user → 404, wrong password → 401.
    This is the primary user-enumeration signal and MUST produce FAIL.
    Previously this was incorrectly classified as INCONCLUSIVE.
    """
    config = Config()
    config.target.username = "testuser"
    tester = DynamicTester(config)
    tester.endpoint_auth = "/login"

    async def mock_login(json_body, headers):
        if json_body.get("username") == "not_existent_user_9876":
            resp = MagicMock(status_code=404)
            resp.text = '{"error": "User not found"}'
            return resp
        # existing user, wrong password
        resp = MagicMock(status_code=401)
        resp.text = '{"error": "Invalid password"}'
        return resp

    mock_client = create_mock_client(post_responses={"/login": mock_login})
    tester._client = mock_client

    result = await tester._test_t11_user_enumeration()
    assert result.stato == "FAIL", (
        f"404 vs 401 is a direct enumeration signal — expected FAIL, got {result.stato}: {result.dettagli}"
    )
    assert "404" in result.dettagli and "401" in result.dettagli


@pytest.mark.asyncio
async def test_t11_both_500_inconclusive():
    """
    Both requests fail with 500 Server Error.
    Neither is auth-recognizable — INCONCLUSIVE.
    """
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_auth = "/login"

    async def mock_login(json_body, headers):
        resp = MagicMock(status_code=500)
        resp.text = "Internal Server Error"
        return resp

    mock_client = create_mock_client(post_responses={"/login": mock_login})
    tester._client = mock_client

    result = await tester._test_t11_user_enumeration()
    assert result.stato == "INCONCLUSIVE", f"500/500 should be INCONCLUSIVE, got {result.stato}"


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
        post_responses={"/login": mock_login, "/logout": mock_logout},
    )
    tester._client = mock_client

    result = await tester._test_t05_token_reuse_post_logout()
    assert result.stato == "PASS"


@pytest.mark.asyncio
async def test_t12_refresh_token_reuse_pass():
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_auth = "/login"
    tester.endpoint_refresh = "/refresh"

    async def mock_login(json_body, headers):
        resp = MagicMock(status_code=200)
        resp.json = lambda: {"access_token": "acc123", "refresh_token": "ref123"}
        return resp

    refresh_calls = 0

    async def mock_refresh(json_body, headers):
        nonlocal refresh_calls
        refresh_calls += 1
        if refresh_calls == 1:
            resp = MagicMock(status_code=200)
            resp.json = lambda: {"access_token": "acc456", "refresh_token": "ref456"}
            return resp
        else:
            resp = MagicMock(status_code=400)
            resp.text = "Token already used"
            return resp

    mock_client = create_mock_client(
        post_responses={"/login": mock_login, "/refresh": mock_refresh}
    )
    tester._client = mock_client

    result = await tester._test_t12_refresh_token_reuse()
    assert result.stato == "PASS"


@pytest.mark.asyncio
async def test_t12_refresh_token_reuse_fail():
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_auth = "/login"
    tester.endpoint_refresh = "/refresh"

    async def mock_login(json_body, headers):
        resp = MagicMock(status_code=200)
        resp.json = lambda: {"access_token": "acc123", "refresh_token": "ref123"}
        return resp

    async def mock_refresh(json_body, headers):
        resp = MagicMock(status_code=200)
        resp.json = lambda: {"access_token": "acc456", "refresh_token": "ref456"}
        return resp

    mock_client = create_mock_client(
        post_responses={"/login": mock_login, "/refresh": mock_refresh}
    )
    tester._client = mock_client

    result = await tester._test_t12_refresh_token_reuse()
    assert result.stato == "FAIL"


@pytest.mark.asyncio
async def test_t13_refresh_token_rotation_pass():
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_auth = "/login"
    tester.endpoint_refresh = "/refresh"

    async def mock_login(json_body, headers):
        resp = MagicMock(status_code=200)
        resp.json = lambda: {"access_token": "acc123", "refresh_token": "ref123"}
        return resp

    used_tokens = set()

    async def mock_refresh(json_body, headers):
        tok = json_body.get("refresh_token")
        if tok == "ref123" and tok not in used_tokens:
            used_tokens.add(tok)
            resp = MagicMock(status_code=200)
            resp.json = lambda: {"access_token": "acc456", "refresh_token": "ref456"}
            return resp
        resp = MagicMock(status_code=400)
        resp.text = "Invalid refresh token"
        return resp

    mock_client = create_mock_client(
        post_responses={"/login": mock_login, "/refresh": mock_refresh}
    )
    tester._client = mock_client

    result = await tester._test_t13_refresh_token_rotation()
    assert result.stato == "PASS"


@pytest.mark.asyncio
async def test_t13_refresh_token_rotation_fail():
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_auth = "/login"
    tester.endpoint_refresh = "/refresh"

    async def mock_login(json_body, headers):
        resp = MagicMock(status_code=200)
        resp.json = lambda: {"access_token": "acc123", "refresh_token": "ref123"}
        return resp

    async def mock_refresh(json_body, headers):
        resp = MagicMock(status_code=200)
        resp.json = lambda: {"access_token": "acc456", "refresh_token": "ref123"}
        return resp

    mock_client = create_mock_client(
        post_responses={"/login": mock_login, "/refresh": mock_refresh}
    )
    tester._client = mock_client

    result = await tester._test_t13_refresh_token_rotation()
    assert result.stato == "FAIL"


@pytest.mark.asyncio
async def test_t14_infinite_lifetime_refresh_token_pass():
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_auth = "/login"

    import time

    from src.core.broken_authentication.dynamic_tester import base64url_encode

    hdr = base64url_encode({"alg": "HS256"})
    now = int(time.time())
    pld = base64url_encode({"sub": "user", "iat": now, "exp": now + 864000})
    valid_jwt = f"{hdr}.{pld}.sig"

    async def mock_login(json_body, headers):
        resp = MagicMock(status_code=200)
        resp.json = lambda: {"access_token": "acc", "refresh_token": valid_jwt}
        return resp

    mock_client = create_mock_client(post_responses={"/login": mock_login})
    tester._client = mock_client

    result = await tester._test_t14_infinite_lifetime_refresh_token()
    assert result.stato == "PASS"


@pytest.mark.asyncio
async def test_t14_infinite_lifetime_refresh_token_fail():
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_auth = "/login"

    import time

    from src.core.broken_authentication.dynamic_tester import base64url_encode

    hdr = base64url_encode({"alg": "HS256"})
    now = int(time.time())
    pld = base64url_encode({"sub": "user", "iat": now, "exp": now + 40 * 86400})
    invalid_jwt = f"{hdr}.{pld}.sig"

    async def mock_login(json_body, headers):
        resp = MagicMock(status_code=200)
        resp.json = lambda: {"access_token": "acc", "refresh_token": invalid_jwt}
        return resp

    mock_client = create_mock_client(post_responses={"/login": mock_login})
    tester._client = mock_client

    result = await tester._test_t14_infinite_lifetime_refresh_token()
    assert result.stato == "FAIL"


@pytest.mark.asyncio
async def test_t15_parallel_refresh_abuse_pass():
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_auth = "/login"
    tester.endpoint_refresh = "/refresh"

    async def mock_login(json_body, headers):
        resp = MagicMock(status_code=200)
        resp.json = lambda: {"access_token": "acc", "refresh_token": "ref123"}
        return resp

    refresh_calls = 0

    async def mock_refresh(json_body, headers):
        nonlocal refresh_calls
        refresh_calls += 1
        if refresh_calls == 1:
            resp = MagicMock(status_code=200)
            resp.json = lambda: {"access_token": "acc2", "refresh_token": "ref2"}
            return resp
        else:
            resp = MagicMock(status_code=400)
            return resp

    mock_client = create_mock_client(
        post_responses={"/login": mock_login, "/refresh": mock_refresh}
    )
    tester._client = mock_client

    result = await tester._test_t15_parallel_refresh_abuse()
    assert result.stato == "PASS"


@pytest.mark.asyncio
async def test_t15_parallel_refresh_abuse_fail():
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_auth = "/login"
    tester.endpoint_refresh = "/refresh"

    async def mock_login(json_body, headers):
        resp = MagicMock(status_code=200)
        resp.json = lambda: {"access_token": "acc", "refresh_token": "ref123"}
        return resp

    async def mock_refresh(json_body, headers):
        resp = MagicMock(status_code=200)
        resp.json = lambda: {"access_token": "acc2", "refresh_token": "ref2"}
        return resp

    mock_client = create_mock_client(
        post_responses={"/login": mock_login, "/refresh": mock_refresh}
    )
    tester._client = mock_client

    result = await tester._test_t15_parallel_refresh_abuse()
    assert result.stato == "FAIL"


@pytest.mark.asyncio
async def test_t16_weak_password_reset():
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_reset = "/reset"

    resp = MagicMock(status_code=200)
    resp.text = '{"status":"ok", "token":"leak123"}'
    mock_client = create_mock_client(post_responses={"/reset": resp})
    tester._client = mock_client

    result = await tester._test_t16_weak_password_reset()
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
        get_responses={"/api/admin": mock_admin}, post_responses={"/login": mock_login}
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
    error_resp.text = (
        "Traceback (most recent call last):\nFile 'app.py', line 12\nZeroDivisionError"
    )
    mock_client = create_mock_client(
        get_responses={"/api/invalid_path_error_trigger_987": error_resp}
    )
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
        file_configurazione_rilevanti=[],
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
        "/api/invalid_path_error_trigger_987": invalid_resp,
    }

    post_resps = {"/api/v1/auth/login": login_resp}

    mock_client = create_mock_client(get_responses=get_resps, post_responses=post_resps)

    with patch(
        "src.core.broken_authentication.dynamic_tester.DynamicTester._get_client",
        return_value=mock_client,
    ):
        results = await run(stack, [], config)

        assert len(results) == 22
        assert all(isinstance(r, RisultatoTest) for r in results)


from src.core.broken_authentication.authentication_intelligence import AuthenticationKnowledgeGraph


@pytest.mark.asyncio
async def test_target_environment_production_gating():
    config = Config()
    tester = DynamicTester(config, target_environment="production", allow_destructive_tests=False)
    tester.endpoint_auth = "/login"

    result = await tester._test_t03_brute_force_rate_limiting()
    assert result.stato == "SKIPPED"
    assert "ambiente di produzione" in result.dettagli


@pytest.mark.asyncio
async def test_rate_limiting_and_audit_logging():
    config = Config()
    mock_resp = MagicMock(status_code=200)
    mock_client = create_mock_client(get_responses={"/api/profile": mock_resp})

    tester = DynamicTester(config, client=mock_client, rate_limit_delay=0.01)

    client = tester._get_client()
    await client.get("/api/profile")

    assert len(tester.request_audit_log) == 1
    assert tester.request_audit_log[0]["method"] == "GET"
    assert "/api/profile" in tester.request_audit_log[0]["url"]


@pytest.mark.asyncio
async def test_confidence_gating():
    config = Config()
    auth_intel = AuthenticationKnowledgeGraph(confidence_score=0.3)
    tester = DynamicTester(config, auth_intel=auth_intel, confidence_threshold=0.4)

    res_t04 = await tester._test_t04_token_replay()
    res_t07 = await tester._test_t07_key_confusion()
    res_t08 = await tester._test_t08_privilege_escalation()

    assert res_t04.stato == "SKIPPED"
    assert res_t07.stato == "SKIPPED"
    assert res_t08.stato == "SKIPPED"


@pytest.mark.asyncio
async def test_t17_jwks_validation():
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_auth = "/login"
    tester.tipo_token = "jwt"

    async def mock_login(json_body, headers):
        resp = MagicMock(status_code=200)
        resp.json = lambda: {"access_token": "a.b.c"}
        return resp

    mock_client = create_mock_client(
        get_responses={"/api/profile": MagicMock(status_code=200)},
        post_responses={"/login": mock_login},
    )
    tester._client = mock_client

    result = await tester._test_t17_jwks_validation()
    assert result.stato == "FAIL"


@pytest.mark.asyncio
async def test_t18_oauth2_oidc_security():
    config = Config()
    auth_intel = AuthenticationKnowledgeGraph(
        identity_provider="Keycloak",
        oauth_flows_metadata={"state_checked": False, "pkce_checked": False},
    )
    tester = DynamicTester(config, auth_intel=auth_intel)
    result = await tester._test_t18_oauth2_oidc_security()
    assert result.stato == "FAIL"
    assert "Mancanza parametro 'state'" in result.dettagli


@pytest.mark.asyncio
async def test_t19_non_jwt_credentials():
    config = Config()
    auth_intel = AuthenticationKnowledgeGraph(non_jwt_mechanisms=["API Key", "Basic Auth"])
    config.target.base_url = "http://localhost:5000"

    mock_client = create_mock_client(get_responses={"/api/data": MagicMock(status_code=200)})
    tester = DynamicTester(config, client=mock_client, auth_intel=auth_intel)

    result = await tester._test_t19_non_jwt_credentials()
    assert result.stato == "FAIL"
    assert "Basic Auth trasmesso in chiaro" in result.dettagli


@pytest.mark.asyncio
async def test_t02_expired_token_fail():
    """Legacy test — now expects INCONCLUSIVE because a token with an invalid
    signature ('invalidsignature') cannot reach the exp check. The new T02
    logic correctly returns INCONCLUSIVE when it cannot build a validly-signed
    expired token (no login + no jwt_secret in auth_intel)."""
    config = Config()
    tester = DynamicTester(config)
    # No endpoint_auth set and no auth_intel.jwt_secret — cannot build a signed token.
    # Profile returning 200 would be irrelevant: test stops before calling it.
    resp = MagicMock(status_code=200)
    resp.text = "Success"
    mock_client = create_mock_client(get_responses={"/api/profile": resp})
    tester._client = mock_client

    result = await tester._test_t02_expired_token()
    # With no login endpoint and no jwt_secret, the new T02 returns INCONCLUSIVE.
    assert result.stato == "INCONCLUSIVE"
    assert "firma valida" in result.dettagli or "segreto" in result.dettagli


@pytest.mark.asyncio
async def test_t04_token_replay_pass():
    config = Config()
    auth_intel = AuthenticationKnowledgeGraph(confidence_score=1.0)
    tester = DynamicTester(config, auth_intel=auth_intel)
    tester.endpoint_auth = "/login"
    tester.tipo_token = "jwt"

    async def mock_login(json_body, headers):
        r = MagicMock(status_code=200)
        r.json = lambda: {"access_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig"}
        return r

    mock_client = create_mock_client(
        get_responses={"/api/profile": MagicMock(status_code=401)},
        post_responses={"/login": mock_login},
    )
    tester._client = mock_client

    result = await tester._test_t04_token_replay()
    assert result.stato == "PASS"


@pytest.mark.asyncio
async def test_t04_token_replay_fail():
    config = Config()
    auth_intel = AuthenticationKnowledgeGraph(confidence_score=1.0)
    tester = DynamicTester(config, auth_intel=auth_intel)
    tester.endpoint_auth = "/login"
    tester.tipo_token = "jwt"

    async def mock_login(json_body, headers):
        r = MagicMock(status_code=200)
        r.json = lambda: {"access_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig"}
        return r

    mock_client = create_mock_client(
        get_responses={"/api/profile": MagicMock(status_code=200)},
        post_responses={"/login": mock_login},
    )
    tester._client = mock_client

    result = await tester._test_t04_token_replay()
    assert result.stato == "FAIL"


@pytest.mark.asyncio
async def test_t06_session_fixation_pass():
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_auth = "/login"

    res1 = MagicMock(status_code=200)
    res1.headers = {"Set-Cookie": "session_id=session123; Path=/"}

    res2 = MagicMock(status_code=200)
    res2.headers = {"Set-Cookie": "session_id=session456; Path=/"}

    mock_client = create_mock_client(get_responses={"/": res1}, post_responses={"/login": res2})
    tester._client = mock_client

    result = await tester._test_t06_session_fixation()
    assert result.stato == "PASS"


@pytest.mark.asyncio
async def test_t06_session_fixation_fail():
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_auth = "/login"

    res1 = MagicMock(status_code=200)
    res1.headers = {"Set-Cookie": "session_id=session123; Path=/"}

    res2 = MagicMock(status_code=200)
    res2.headers = {"Set-Cookie": "session_id=session123; Path=/"}

    mock_client = create_mock_client(get_responses={"/": res1}, post_responses={"/login": res2})
    tester._client = mock_client

    result = await tester._test_t06_session_fixation()
    assert result.stato == "FAIL"


@pytest.mark.asyncio
async def test_t07_key_confusion_pass():
    config = Config()
    auth_intel = AuthenticationKnowledgeGraph(confidence_score=1.0)
    tester = DynamicTester(config, auth_intel=auth_intel)
    tester.endpoint_auth = "/login"
    tester.tipo_token = "jwt"

    async def mock_login(json_body, headers):
        r = MagicMock(status_code=200)
        r.json = lambda: {"access_token": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig"}
        return r

    mock_client = create_mock_client(
        get_responses={"/api/profile": MagicMock(status_code=401)},
        post_responses={"/login": mock_login},
    )
    tester._client = mock_client

    result = await tester._test_t07_key_confusion()
    assert result.stato == "PASS"


@pytest.mark.asyncio
async def test_t07_key_confusion_fail():
    config = Config()
    auth_intel = AuthenticationKnowledgeGraph(confidence_score=1.0)
    tester = DynamicTester(config, auth_intel=auth_intel)
    tester.endpoint_auth = "/login"
    tester.tipo_token = "jwt"

    async def mock_login(json_body, headers):
        r = MagicMock(status_code=200)
        r.json = lambda: {"access_token": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig"}
        return r

    mock_client = create_mock_client(
        get_responses={"/api/profile": MagicMock(status_code=200)},
        post_responses={"/login": mock_login},
    )
    tester._client = mock_client

    result = await tester._test_t07_key_confusion()
    assert result.stato == "FAIL"


@pytest.mark.asyncio
async def test_t08_privilege_escalation_fail():
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

    async def mock_admin(headers):
        return MagicMock(status_code=200, text="Admin Area")

    mock_client = create_mock_client(
        get_responses={"/api/admin": mock_admin}, post_responses={"/login": mock_login}
    )
    tester._client = mock_client

    result = await tester._test_t08_privilege_escalation()
    assert result.stato == "FAIL"


# --- Tests for T20 (Rate Limiting Bypass) ---


@pytest.mark.asyncio
async def test_t20_rate_limiting_bypass_skipped():
    config = Config()
    tester = DynamicTester(config, target_environment="production", allow_destructive_tests=False)
    result = await tester._test_t20_rate_limiting_bypass()
    assert result.stato == "SKIPPED"


@pytest.mark.asyncio
async def test_t20_rate_limiting_bypass_inconclusive():
    config = Config()
    tester = DynamicTester(config, target_environment="staging", allow_destructive_tests=True)
    tester.endpoint_auth = "/login"

    mock_client = create_mock_client(post_responses={"/login": MagicMock(status_code=401)})
    tester._client = mock_client

    result = await tester._test_t20_rate_limiting_bypass()
    assert result.stato == "INCONCLUSIVE"


@pytest.mark.asyncio
async def test_t20_rate_limiting_bypass_fail():
    config = Config()
    tester = DynamicTester(config, target_environment="staging", allow_destructive_tests=True)
    tester.endpoint_auth = "/login"

    request_count = 0

    async def mock_login(json_body, headers):
        nonlocal request_count
        request_count += 1
        if headers and any(
            h in headers for h in ["X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"]
        ):
            return MagicMock(status_code=401)
        if request_count > 5:
            return MagicMock(status_code=429)
        return MagicMock(status_code=401)

    mock_client = create_mock_client(post_responses={"/login": mock_login})
    tester._client = mock_client

    result = await tester._test_t20_rate_limiting_bypass()
    assert result.stato == "FAIL"
    assert "X-Forwarded-For" in result.dettagli


@pytest.mark.asyncio
async def test_t20_rate_limiting_bypass_pass():
    config = Config()
    tester = DynamicTester(config, target_environment="staging", allow_destructive_tests=True)
    tester.endpoint_auth = "/login"

    request_count = 0

    async def mock_login(json_body, headers):
        nonlocal request_count
        request_count += 1
        if request_count > 5:
            return MagicMock(status_code=429)
        return MagicMock(status_code=401)

    mock_client = create_mock_client(post_responses={"/login": mock_login})
    tester._client = mock_client

    result = await tester._test_t20_rate_limiting_bypass()
    assert result.stato == "PASS"


# --- Tests for T21 (MFA Testing) ---


@pytest.mark.asyncio
async def test_t21_mfa_testing_inconclusive():
    config = Config()
    tester = DynamicTester(config)
    result = await tester._test_t21_mfa_testing()
    assert result.stato == "INCONCLUSIVE"


@pytest.mark.asyncio
async def test_t21_mfa_testing_logical_bypass():
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_mfa = "/mfa"

    async def mock_mfa(json_body, headers):
        if json_body.get("code") == "":
            return MagicMock(status_code=200)
        return MagicMock(status_code=401)

    mock_client = create_mock_client(post_responses={"/mfa": mock_mfa})
    tester._client = mock_client

    result = await tester._test_t21_mfa_testing()
    assert result.stato == "FAIL"
    assert result.severita == "CRITICAL"


@pytest.mark.asyncio
async def test_t21_mfa_testing_brute_force_skipped_prod():
    config = Config()
    tester = DynamicTester(config, target_environment="production", allow_destructive_tests=False)
    tester.endpoint_mfa = "/mfa"

    mock_client = create_mock_client(post_responses={"/mfa": MagicMock(status_code=401)})
    tester._client = mock_client

    result = await tester._test_t21_mfa_testing()
    assert result.stato == "PASS"


@pytest.mark.asyncio
async def test_t21_mfa_testing_brute_force_fail():
    config = Config()
    tester = DynamicTester(config, target_environment="staging", allow_destructive_tests=True)
    tester.endpoint_mfa = "/mfa"

    mock_client = create_mock_client(post_responses={"/mfa": MagicMock(status_code=401)})
    tester._client = mock_client

    result = await tester._test_t21_mfa_testing()
    assert result.stato == "FAIL"
    assert "Nessun rate limiting rilevato sull'endpoint MFA" in result.dettagli


@pytest.mark.asyncio
async def test_t21_mfa_testing_brute_force_pass():
    config = Config()
    tester = DynamicTester(config, target_environment="staging", allow_destructive_tests=True)
    tester.endpoint_mfa = "/mfa"

    request_count = 0

    async def mock_mfa(json_body, headers):
        nonlocal request_count
        request_count += 1
        if request_count > 5:
            return MagicMock(status_code=429)
        return MagicMock(status_code=401)

    mock_client = create_mock_client(post_responses={"/mfa": mock_mfa})
    tester._client = mock_client

    result = await tester._test_t21_mfa_testing()
    assert result.stato == "PASS"


# --- Tests for T22 (SAML Security) ---


@pytest.mark.asyncio
async def test_t22_saml_security_skipped():
    config = Config()
    tester = DynamicTester(config)
    result = await tester._test_t22_saml_security()
    assert result.stato == "INCONCLUSIVE"


@pytest.mark.asyncio
async def test_t22_saml_security_fail_xsw():
    config = Config()
    auth_intel = AuthenticationKnowledgeGraph(saml_detected=True)
    tester = DynamicTester(config, auth_intel=auth_intel)

    mock_client = create_mock_client(
        post_responses={"/saml/acs": MagicMock(status_code=200, text="")}
    )
    tester._client = mock_client

    result = await tester._test_t22_saml_security()
    assert result.stato == "FAIL"
    assert "XML Signature Wrapping" in result.dettagli


@pytest.mark.asyncio
async def test_t22_saml_security_fail_xxe():
    config = Config()
    auth_intel = AuthenticationKnowledgeGraph(saml_detected=True)
    tester = DynamicTester(config, auth_intel=auth_intel)

    async def mock_acs(data, headers):
        resp = MagicMock(status_code=200)
        resp.text = "Error resolving entity: invalid-dns-test-url.local/xxe.xml"
        return resp

    mock_client = create_mock_client(post_responses={"/saml/acs": mock_acs})
    tester._client = mock_client

    result = await tester._test_t22_saml_security()
    assert result.stato == "FAIL"
    assert "XXE" in result.dettagli


@pytest.mark.asyncio
async def test_t22_saml_security_pass():
    config = Config()
    auth_intel = AuthenticationKnowledgeGraph(saml_detected=True)
    tester = DynamicTester(config, auth_intel=auth_intel)

    mock_client = create_mock_client(
        post_responses={"/saml/acs": MagicMock(status_code=400, text="Bad Request")}
    )
    tester._client = mock_client

    result = await tester._test_t22_saml_security()
    assert result.stato == "PASS"


@pytest.mark.asyncio
async def test_t11_user_enumeration_different_non_auth_codes():
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_auth = "/login"

    # 400 vs 500 status codes: different but both are non-auth failures (A.1)
    calls = []

    async def mock_login(json_body, headers):
        if not calls:
            calls.append(1)
            return MagicMock(status_code=400, text="Bad Request")
        return MagicMock(status_code=500, text="Internal Server Error")

    tester._client = create_mock_client(post_responses={"/login": mock_login})
    result = await tester._test_t11_user_enumeration()
    assert result.stato == "INCONCLUSIVE"
    # Message updated in T11 rewrite (was: 'formato non riconosciuto o errore server')
    assert "non riconducibili" in result.dettagli or "formato non supportato" in result.dettagli


@pytest.mark.asyncio
async def test_login_adaptive_openapi_schema():
    config = Config()
    config.target.username = "test_user_val"
    config.target.password = "pwd_val"

    openapi_spec = {
        "paths": {
            "/login": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "email": {"type": "string"},
                                        "password": {"type": "string"},
                                    },
                                    "required": ["email", "password"],
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    tester = DynamicTester(config, openapi_spec=openapi_spec)
    tester.endpoint_auth = "/login"

    # Verify that client receives the key 'email' instead of 'username'
    async def mock_post(json_body, headers):
        assert "email" in json_body
        assert json_body["email"] == "test_user_val"
        assert json_body["password"] == "pwd_val"
        resp = MagicMock(status_code=200)
        resp.json = lambda: {"token": "my_jwt_token"}
        return resp

    tester._client = create_mock_client(post_responses={"/login": mock_post})
    token = await tester._login_and_get_token(tester._client)
    assert token == "my_jwt_token"
    assert tester.auth_strategy == "schema-derived"


@pytest.mark.asyncio
async def test_login_adaptive_fallback_aliases():
    config = Config()
    config.target.username = "user_val"
    config.target.password = "pwd_val"

    tester = DynamicTester(config)
    tester.endpoint_auth = "/login"

    # We want to test fallback where the server rejects "username" (400) but accepts "user" (401)
    calls = []

    async def mock_post(json_body, headers):
        calls.append(json_body)
        if "user" in json_body and "password" in json_body:
            return MagicMock(status_code=401, text="Unauthorized credentials")
        return MagicMock(status_code=400, text="Bad fields")

    tester._client = create_mock_client(post_responses={"/login": mock_post})
    token = await tester._login_and_get_token(tester._client)
    assert token is None
    assert tester.auth_strategy == "alias-fallback-5"
    assert len(calls) == 5


@pytest.mark.asyncio
async def test_discover_endpoints_decoupled():
    config = Config()
    auth_intel = AuthenticationKnowledgeGraph(login_endpoint="/auth/signin")
    tester = DynamicTester(config, auth_intel=auth_intel)

    openapi_spec = {
        "paths": {
            "/auth/signin": {"post": {}},
            "/auth/verify-mfa": {"post": {}},
            "/auth/reset-pwd": {"post": {}},
        }
    }
    tester.openapi_spec = openapi_spec
    tester._client = create_mock_client()

    from src.core.broken_authentication.discovery import StackInfo

    stack = StackInfo(
        linguaggio="python",
        framework="FastAPI",
        librerie_auth=["jwt"],
        file_configurazione_rilevanti=[],
    )

    await tester.discover_endpoints(stack, [])
    assert tester.endpoint_auth == "/auth/signin"
    assert tester.endpoint_mfa == "/auth/verify-mfa"
    assert tester.endpoint_reset == "/auth/reset-pwd"


# ---------------------------------------------------------------------------
# T06 – Session Fixation: new INCONCLUSIVE guard tests (Punto 2)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_t06_session_fixation_no_pre_login_cookie_inconclusive():
    """
    If no pre-login cookie is ever issued (Flask client-side sessions),
    the test MUST return INCONCLUSIVE rather than PASS.
    """
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_auth = "/login"

    # All GET probes return responses with NO Set-Cookie header
    no_cookie_get = MagicMock(status_code=200)
    no_cookie_get.headers = {}  # no Set-Cookie key at all

    login_resp = MagicMock(status_code=200)
    login_resp.headers = {"Set-Cookie": "session=abc123; Path=/; HttpOnly"}

    mock_client = create_mock_client(
        get_responses={
            "/": no_cookie_get,
            "/api/admin": no_cookie_get,
            "/api/profile": no_cookie_get,
        },
        post_responses={"/login": login_resp},
    )
    tester._client = mock_client

    result = await tester._test_t06_session_fixation()
    assert result.stato == "INCONCLUSIVE", (
        f"Expected INCONCLUSIVE when no pre-login cookie exists, got {result.stato}: {result.dettagli}"
    )
    assert "client-side" in result.dettagli or "prima del login" in result.dettagli


@pytest.mark.asyncio
async def test_t06_session_fixation_no_post_login_cookie_inconclusive():
    """
    If the login endpoint sets no cookie, the test MUST return INCONCLUSIVE.
    """
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_auth = "/login"

    pre_login_resp = MagicMock(status_code=200)
    pre_login_resp.headers = {"Set-Cookie": "session=pre123; Path=/; HttpOnly"}

    no_cookie_login = MagicMock(status_code=200)
    no_cookie_login.headers = {}  # login sets no cookie

    mock_client = create_mock_client(
        get_responses={"/": pre_login_resp}, post_responses={"/login": no_cookie_login}
    )
    tester._client = mock_client

    result = await tester._test_t06_session_fixation()
    assert result.stato == "INCONCLUSIVE", (
        f"Expected INCONCLUSIVE when login sets no cookie, got {result.stato}: {result.dettagli}"
    )


@pytest.mark.asyncio
async def test_t06_session_fixation_same_id_fail():
    """
    Regression: when both pre-login and post-login cookies are present and equal,
    the result MUST still be FAIL.
    """
    config = Config()
    tester = DynamicTester(config)
    tester.endpoint_auth = "/login"

    same_session = MagicMock(status_code=200)
    same_session.headers = {"Set-Cookie": "session=FIXED_SESSION_ID; Path=/; HttpOnly"}

    mock_client = create_mock_client(
        get_responses={"/": same_session}, post_responses={"/login": same_session}
    )
    tester._client = mock_client

    result = await tester._test_t06_session_fixation()
    assert result.stato == "FAIL", (
        f"Expected FAIL for same session ID pre/post login, got {result.stato}"
    )
    assert "rigenerata" in result.dettagli
