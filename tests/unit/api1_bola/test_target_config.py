"""
Test del contratto cooperante del bersaglio BOLA (config/bola_target.yaml):
loader con fallback sui default, override chiave per chiave, provider supportati,
credenziali lette solo dall'ambiente e riscrittura dell'host per il container di ZAP.
"""

import pytest

from src.core.api1_bola.target_config import (
    IDENTITY_KEYS,
    BolaTargetConfig,
    IdentitySpec,
    load_bola_target_config,
    rewrite_host_for_zap,
)


def test_loader_falls_back_to_defaults_when_file_is_missing(tmp_path):
    cfg = load_bola_target_config(str(tmp_path / "missing.yaml"))
    assert cfg == BolaTargetConfig()
    assert cfg.identity_provider == "keycloak"
    assert cfg.harness_paths == ("/test/seed", "/test/snapshot", "/test/rollback")
    assert cfg.usernames == {"victim": "user_a", "peer": "user_b", "privileged": "admin_user"}
    assert cfg.roles == {"victim": "user", "peer": "user", "privileged": "admin"}


def test_shipped_config_matches_lab_defaults():
    # Il file versionato descrive il laboratorio: nessuna deriva silenziosa dai default
    shipped = load_bola_target_config("config/bola_target.yaml")
    assert shipped == BolaTargetConfig()


def test_loader_overrides_only_present_keys(tmp_path):
    custom = tmp_path / "target.yaml"
    custom.write_text(
        """
target:
  base_url: http://staging.example.com
  zap_internal_host: target-container
harness:
  seed: /__qa/seed
identities:
  provider: static_tokens
  realm: acme
  users:
    victim: {username: alice, role: user, token_env: ALICE_JWT}
    privileged: {role: owner}
assessment:
  allow_mutations: true
""",
        encoding="utf-8",
    )
    cfg = load_bola_target_config(str(custom))
    assert cfg.base_url == "http://staging.example.com"
    assert cfg.zap_internal_host == "target-container"
    assert cfg.seed_path == "/__qa/seed"
    assert cfg.snapshot_path == "/test/snapshot"  # non sovrascritto
    assert cfg.identity_provider == "static_tokens"
    assert cfg.realm == "acme"
    assert cfg.client_id == "security-platform-client"  # default
    assert cfg.identity("victim") == IdentitySpec("alice", "user", "USER_A_PASSWORD", "ALICE_JWT")
    # peer intatto, privileged con solo il ruolo cambiato
    assert cfg.identity("peer").username == "user_b"
    assert cfg.identity("privileged").username == "admin_user"
    assert cfg.identity("privileged").role == "owner"
    assert cfg.allow_mutations is True
    assert cfg.seed_url() == "http://staging.example.com/__qa/seed"
    assert cfg.snapshot_url("http://localhost:9999/") == "http://localhost:9999/test/snapshot"


def test_unknown_provider_falls_back_to_keycloak(tmp_path):
    custom = tmp_path / "target.yaml"
    custom.write_text("identities:\n  provider: ldap\n", encoding="utf-8")
    assert load_bola_target_config(str(custom)).identity_provider == "keycloak"


def test_traffic_provider_implies_assessment_identities(tmp_path):
    custom = tmp_path / "target.yaml"
    custom.write_text("identities:\n  provider: traffic\n", encoding="utf-8")
    assert load_bola_target_config(str(custom)).uses_traffic_identities is True


def test_credentials_come_from_environment_not_yaml(monkeypatch):
    spec = IdentitySpec("alice", "user", password_env="ALICE_PW", token_env="ALICE_JWT")
    monkeypatch.delenv("ALICE_PW", raising=False)
    monkeypatch.delenv("ALICE_JWT", raising=False)
    assert spec.password("fallback") == "fallback"
    assert spec.token() == ""
    monkeypatch.setenv("ALICE_PW", "s3cret")
    monkeypatch.setenv("ALICE_JWT", "eyJ.abc.def")
    assert spec.password("fallback") == "s3cret"
    assert spec.token() == "eyJ.abc.def"


def test_identity_key_for_username():
    cfg = BolaTargetConfig()
    assert cfg.identity_key_for_username("user_b") == "peer"
    assert cfg.identity_key_for_username("nobody") is None
    assert set(cfg.users) == set(IDENTITY_KEYS)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://localhost:5000/api/x?y=1", "http://api-server:5000/api/x?y=1"),
        ("http://127.0.0.1/api/x", "http://api-server/api/x"),
        ("https://staging.example.com:8443/api", "https://staging.example.com:8443/api"),
        ("http://api-server:5000/api", "http://api-server:5000/api"),
    ],
)
def test_rewrite_host_for_zap(url, expected):
    assert rewrite_host_for_zap(url, "api-server") == expected
    assert BolaTargetConfig().to_zap_url(url) == expected


def test_rewrite_host_for_zap_disabled_with_empty_host():
    assert rewrite_host_for_zap("http://localhost:5000/x", "") == "http://localhost:5000/x"
