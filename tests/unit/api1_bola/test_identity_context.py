"""
Test di IdentityManager e DatabaseSeeder guidati dal contratto del bersaglio:
provider `static_tokens` senza Keycloak, fallback su JWT fittizi, payload di seeding
con gli username del contratto e lettura degli ID creati riportati dall'harness (D2).
"""

from unittest.mock import MagicMock, patch

import jwt

from src.core.api1_bola.target_config import BolaTargetConfig, IdentitySpec
from src.core.identity_context import DatabaseSeeder, IdentityManager, SeedOutcome

MODULE = "src.core.identity_context"


def _jwt(sub: str, username: str, roles: list[str]) -> str:
    return jwt.encode(
        {"sub": sub, "preferred_username": username, "roles": roles}, "k", algorithm="HS256"
    )


def _static_config(**overrides) -> BolaTargetConfig:
    return BolaTargetConfig(
        identity_provider="static_tokens",
        users={
            "victim": IdentitySpec("alice", "user", token_env="T_VICTIM"),
            "peer": IdentitySpec("bob", "user", token_env="T_PEER"),
            "privileged": IdentitySpec("root", "admin", token_env="T_PRIV"),
        },
        **overrides,
    )


# ─── IdentityManager ─────────────────────────────────────────────────────────


def test_static_tokens_provider_never_calls_keycloak(monkeypatch):
    monkeypatch.setenv("T_VICTIM", _jwt("sub-a", "alice", ["user"]))
    monkeypatch.setenv("T_PEER", _jwt("sub-b", "bob", ["user"]))
    monkeypatch.setenv("T_PRIV", _jwt("sub-c", "root", ["admin"]))

    with patch(f"{MODULE}.requests.post") as post:
        manager = IdentityManager(config=_static_config())
        matrix = manager.get_headers_for_identities()

    post.assert_not_called()
    assert matrix["userA"]["Authorization"].endswith(_jwt("sub-a", "alice", ["user"]))
    assert matrix["anonymous"] == {}
    assert manager.identity_map == {"victim": "sub-a", "peer": "sub-b", "privileged": "sub-c"}
    assert manager.role_map == {"sub-a": "user", "sub-b": "user", "sub-c": "admin"}


def test_static_tokens_missing_env_falls_back_to_mock_jwt(monkeypatch):
    for var in ("T_VICTIM", "T_PEER", "T_PRIV"):
        monkeypatch.delenv(var, raising=False)
    manager = IdentityManager(config=_static_config())
    matrix = manager.get_headers_for_identities()

    token = matrix["userC"]["Authorization"].split(" ", 1)[1]
    payload = jwt.decode(token, options={"verify_signature": False})
    # Il mock riflette username e ruolo del contratto, non "admin_user" cablato
    assert payload["preferred_username"] == "root"
    assert payload["roles"] == ["admin"]
    assert manager.role_map[payload["sub"]] == "admin"
    assert len(set(manager.uuids.values())) == 3


def test_keycloak_provider_uses_contract_realm_client_and_env_password(monkeypatch):
    monkeypatch.setenv("VICTIM_PW", "pw-from-env")
    cfg = BolaTargetConfig(
        keycloak_url="http://idp.local:8080/",
        realm="acme",
        client_id="acme-client",
        users={
            "victim": IdentitySpec("alice", "user", password_env="VICTIM_PW"),
            "peer": IdentitySpec("bob", "user"),
            "privileged": IdentitySpec("root", "admin"),
        },
    )
    response = MagicMock(status_code=200)
    response.json.return_value = {"access_token": _jwt("sub-a", "alice", ["user"])}
    with patch(f"{MODULE}.requests.post", return_value=response) as post:
        manager = IdentityManager(config=cfg)
        manager.get_headers_for_identities()

    assert manager.token_url == "http://idp.local:8080/realms/acme/protocol/openid-connect/token"
    first_call = post.call_args_list[0]
    assert first_call.kwargs["data"]["client_id"] == "acme-client"
    assert first_call.kwargs["data"]["username"] == "alice"
    assert first_call.kwargs["data"]["password"] == "pw-from-env"


def test_explicit_keycloak_url_overrides_contract():
    manager = IdentityManager(config=BolaTargetConfig(), keycloak_url="http://cli.local:1234")
    assert manager.token_url.startswith("http://cli.local:1234/realms/myrealm/")


# ─── DatabaseSeeder (D2) ─────────────────────────────────────────────────────

ENDPOINTS = [
    {"path": "/api/projects/{id}", "methods": ["GET"], "resource_name": "projects"},
    {"path": "/api/invoices/{id}", "methods": ["GET"], "resource_name": "invoices"},
]
UUIDS = {"victim": "sub-a", "peer": "sub-b", "privileged": "sub-c"}


def _seed_response(body: dict, status: int = 200) -> MagicMock:
    response = MagicMock(status_code=status)
    response.json.return_value = body
    return response


def test_seed_payload_uses_contract_usernames_and_harness_path():
    cfg = _static_config(base_url="http://target.local:5000", seed_path="/__qa/seed")
    with patch(f"{MODULE}.requests.post", return_value=_seed_response({"status": "ok"})) as post:
        seeder = DatabaseSeeder(config=cfg)
        outcome = seeder.seed_target_application(ENDPOINTS, UUIDS)

    assert post.call_args.args[0] == "http://target.local:5000/__qa/seed"
    payload = post.call_args.kwargs["json"]
    # UUID -> username del contratto (alice/bob/root), non gli username di default
    assert payload["projects"] == {"sub-a": "alice", "sub-b": "bob", "sub-c": "root"}
    assert payload["invoices"] == {"sub-a": "alice", "sub-b": "bob", "sub-c": "root"}
    assert isinstance(outcome, SeedOutcome) and outcome.success is True
    assert outcome.resource_ids == {}


def test_seed_reads_created_ids_reported_by_harness():
    """D2: se l'harness riporta gli ID creati, vengono mappati sui ruoli logici."""
    body = {
        "status": "ok",
        "ids": {
            "projects": {"alice": "P1", "bob": "P2", "root": "P9"},
            "invoices": {"alice": "I1"},
        },
    }
    with patch(f"{MODULE}.requests.post", return_value=_seed_response(body)):
        outcome = DatabaseSeeder(config=_static_config()).seed_target_application(ENDPOINTS, UUIDS)

    assert outcome.success is True
    assert outcome.resource_ids == {
        "projects": {"victim": "P1", "peer": "P2", "privileged": "P9"},
        "invoices": {"victim": "I1"},
    }


def test_seed_returns_failure_when_uuid_missing():
    with patch(f"{MODULE}.requests.post") as post:
        outcome = DatabaseSeeder(config=_static_config()).seed_target_application(
            ENDPOINTS, {"victim": "sub-a", "peer": None, "privileged": "sub-c"}
        )
    post.assert_not_called()
    assert outcome.success is False


def test_seed_without_endpoints_is_noop():
    outcome = DatabaseSeeder(config=_static_config()).seed_target_application([], UUIDS)
    assert outcome.success is True and outcome.resource_ids == {}


def test_seed_non_200_is_unsuccessful():
    with patch(f"{MODULE}.requests.post", return_value=_seed_response({"error": "x"}, status=500)):
        outcome = DatabaseSeeder(config=_static_config()).seed_target_application(ENDPOINTS, UUIDS)
    assert outcome.success is False
