"""
Test del generatore di attacchi BOLA (ContextAwareAttackGenerator): gli ID delle risorse
arrivano dall'orchestratore (`resource_ids`), non dal claim `sub`; l'ultimo `{id}` di un
path annidato è l'oggetto bersaglio; l'host locale viene riscritto per il container di ZAP.
"""

from unittest.mock import MagicMock, patch

import pytest

from src.core.api1_bola.attack_vector import (
    ContextAwareAttackGenerator,
    IdentityProfile,
    substitute_path_ids,
)

HEADERS = {
    "userA": {"Authorization": "Bearer tokenA"},
    "userB": {"Authorization": "Bearer tokenB"},
    "userC": {"Authorization": "Bearer tokenC"},
    "anonymous": {},
}
RESOURCE_IDS = {"victim": "res-victim", "peer": "res-peer", "privileged": "res-admin"}
PROFILES = {
    "victim": IdentityProfile(role="user", username="user_a", uuid="uuid-victim"),
    "peer": IdentityProfile(role="user", username="user_b", uuid="uuid-peer"),
    "privileged": IdentityProfile(role="admin", username="admin_user", uuid="uuid-admin"),
}


@pytest.fixture
def mock_request():
    with patch("src.core.api1_bola.attack_vector.requests.request") as m:
        response = MagicMock()
        response.status_code = 200
        response.text = '{"status": "success"}'
        m.return_value = response
        yield m


def _urls(mock_request) -> list[str]:
    return [c.args[1] for c in mock_request.call_args_list]


def test_execute_tampering_methods(mock_request):
    vector = ContextAwareAttackGenerator(zap_proxy_url="http://localhost:8090")

    vector.execute_tampering(
        method="POST",
        target_base_url="http://localhost:5000",
        path="/api/orders/{id}",
        headers_matrix=HEADERS,
        resource_ids=RESOURCE_IDS,
        profiles=PROFILES,
    )

    # 3 scenari * 3 richieste (legittima, attacco, anonima) = 9 chiamate a requests.request
    assert mock_request.call_count == 9

    # Prima chiamata: il proprietario (victim) sulla propria risorsa, owner dal profilo
    args, kwargs = mock_request.call_args_list[0]
    assert args[0] == "POST"
    assert kwargs["json"]["owner"] == "user_a"
    assert kwargs["headers"]["Authorization"] == "Bearer tokenA"

    mock_request.reset_mock()
    vector.execute_tampering(
        method="PATCH",
        target_base_url="http://localhost:5000",
        path="/api/orders/{id}",
        headers_matrix=HEADERS,
        resource_ids=RESOURCE_IDS,
        profiles=PROFILES,
    )
    assert mock_request.call_count == 9
    args, kwargs = mock_request.call_args_list[0]
    assert args[0] == "PATCH"
    assert kwargs["json"]["owner"] == "user_a"


def test_resource_ids_are_used_instead_of_subs(mock_request):
    """Gli ID creati dal seeding finiscono nell'URL: il claim sub non viene più dedotto."""
    vector = ContextAwareAttackGenerator(zap_proxy_url="http://localhost:8090")
    results = vector.execute_tampering(
        method="GET",
        target_base_url="http://localhost:5000",
        path="/api/orders/{id}",
        headers_matrix=HEADERS,
        resource_ids=RESOURCE_IDS,
        profiles=PROFILES,
    )
    by_name = {r["scenario_name"]: r for r in results}
    assert (
        by_name["BOLA Orizzontale"]["target_url"] == "http://localhost:5000/api/orders/res-victim"
    )
    assert by_name["BOLA Verticale"]["target_url"] == "http://localhost:5000/api/orders/res-admin"
    assert by_name["Privilegio Legittimo"]["resource_id"] == "res-victim"
    assert by_name["BOLA Orizzontale"]["owner"] == "victim"
    assert by_name["BOLA Orizzontale"]["attacker"] == "peer"
    assert "uuid-victim" not in " ".join(_urls(mock_request))


def test_missing_resource_id_skips_scenarios(mock_request):
    vector = ContextAwareAttackGenerator(zap_proxy_url="http://localhost:8090")
    results = vector.execute_tampering(
        method="GET",
        target_base_url="http://localhost:5000",
        path="/api/orders/{id}",
        headers_matrix=HEADERS,
        resource_ids={"victim": "only-victim"},
    )
    assert results == []
    mock_request.assert_not_called()


def test_zap_url_rewrites_local_host_from_config(mock_request):
    vector = ContextAwareAttackGenerator(
        zap_proxy_url="http://localhost:8090", zap_internal_host="target-container"
    )
    results = vector.execute_tampering(
        method="GET",
        target_base_url="http://127.0.0.1:5000",
        path="/api/orders/{id}",
        headers_matrix=HEADERS,
        resource_ids=RESOURCE_IDS,
    )
    assert results[0]["zap_target_url"] == "http://target-container:5000/api/orders/res-victim"
    # La richiesta reale passa dal proxy con l'host interno di ZAP
    assert _urls(mock_request)[0] == "http://target-container:5000/api/orders/res-victim"
    # Un bersaglio remoto non viene toccato
    remote = vector.execute_tampering(
        method="GET",
        target_base_url="https://staging.example.com",
        path="/api/orders/{id}",
        headers_matrix=HEADERS,
        resource_ids=RESOURCE_IDS,
    )
    assert remote[0]["zap_target_url"] == "https://staging.example.com/api/orders/res-victim"


# ─── D3: path annidati, l'ultimo {id} è l'oggetto bersaglio ─────────────────


def test_substitute_path_ids_targets_last_placeholder():
    assert substitute_path_ids("/api/users/{id}/projects/{id}", "P1", "U1") == (
        "/api/users/U1/projects/P1"
    )
    # Senza id genitore, tutti i placeholder ricevono l'ID bersaglio
    assert substitute_path_ids("/api/users/{id}/projects/{id}", "P1") == (
        "/api/users/P1/projects/P1"
    )
    assert substitute_path_ids("/api/orders/{id}", "O1", "ignored") == "/api/orders/O1"
    assert substitute_path_ids("/api/profile", "O1") == "/api/profile"


def test_nested_path_uses_owner_uuid_for_parent_and_resource_id_for_target(mock_request):
    vector = ContextAwareAttackGenerator(zap_proxy_url="http://localhost:8090")
    results = vector.execute_tampering(
        method="GET",
        target_base_url="http://localhost:5000",
        path="/api/users/{id}/projects/{id}",
        headers_matrix=HEADERS,
        resource_ids=RESOURCE_IDS,
        profiles=PROFILES,
    )
    by_name = {r["scenario_name"]: r["target_url"] for r in results}
    # Orizzontale: peer attacca il progetto di victim, sotto l'utente victim
    assert (
        by_name["BOLA Orizzontale"]
        == "http://localhost:5000/api/users/uuid-victim/projects/res-victim"
    )
    # Verticale: la risorsa è dell'admin, il genitore è l'UUID dell'admin
    assert (
        by_name["BOLA Verticale"] == "http://localhost:5000/api/users/uuid-admin/projects/res-admin"
    )
