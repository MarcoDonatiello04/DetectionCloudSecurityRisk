"""
Test end-to-end della modalità Assessment (D4): a partire da traffico fixture, la
pipeline D-AST inferisce le identità, sceglie gli oggetti da attaccare (ID osservati)
e genera gli scenari — senza seeding/snapshot/rollback. Verifica anche che i metodi
mutanti (PUT/PATCH/DELETE) siano esclusi di default e riabilitabili con allow_mutations.

Nessun servizio reale: ZAP è mockato e `requests.request` (le chiamate d'attacco)
è mockato per registrare metodo e URL di ogni scenario.
"""

import base64
import json
from unittest.mock import MagicMock, patch

import pytest

from src.core.api1_bola.dynamic_orchestrator import DynamicOrchestrator

DYN = "src.core.api1_bola.dynamic_orchestrator"
ATTACK = "src.core.api1_bola.attack_vector"


def _jwt(sub: str, roles: list[str]) -> str:
    def seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    return f"{seg({'alg': 'HS256'})}.{seg({'sub': sub, 'roles': roles})}.sig"


VICTIM = _jwt("uuid-victim", ["user"])
PEER = _jwt("uuid-peer", ["user"])
ADMIN = _jwt("uuid-admin", ["admin"])

# Traffico osservato: victim e peer possiedono ordini distinti, l'admin un altro.
TRAFFIC = [
    {
        "method": "GET",
        "path": "/api/orders/101",
        "status": 200,
        "headers": {"Authorization": f"Bearer {VICTIM}"},
    },
    {
        "method": "GET",
        "path": "/api/orders/202",
        "status": 200,
        "headers": {"Authorization": f"Bearer {PEER}"},
    },
    {
        "method": "GET",
        "path": "/api/orders/900",
        "status": 200,
        "headers": {"Authorization": f"Bearer {ADMIN}"},
    },
]

INVENTORY = [
    {"api": {"endpoint": "/api/orders/{id}", "method": "GET"}},
    {"api": {"endpoint": "/api/orders/{id}", "method": "DELETE"}},
]


@pytest.fixture
def attack_request():
    """Mock di requests.request usato dalle chiamate d'attacco reali."""
    with patch(f"{ATTACK}.requests.request") as m:
        resp = MagicMock(status_code=200)
        resp.text = '{"ok": true}'
        resp.json.return_value = {"ok": True}
        m.return_value = resp
        yield m


def _run(tmp_path, attack_request, **kwargs):
    with patch(f"{DYN}.ZAPv2") as zap_cls:
        # ZAP riporta subito il completamento: evita il polling in _wait_for_scan_completion
        zap_cls.return_value.ascan.status.return_value = "100"
        orch = DynamicOrchestrator(assessment_mode=True, zap_proxy_url="http://zap.local", **kwargs)
        findings = orch.run_dast_pipeline(
            api_inventory=INVENTORY, output_dir=str(tmp_path), raw_traffic=TRAFFIC
        )
    calls = [
        (c.kwargs.get("method") or c.args[0], c.args[1]) for c in attack_request.call_args_list
    ]
    return orch, findings, calls


def test_assessment_selects_identities_and_targets_observed_ids(tmp_path, attack_request):
    orch, findings, calls = _run(tmp_path, attack_request)

    # Nessun seeding/snapshot/rollback in Assessment Mode
    assert orch.assessment_mode is True
    methods_used = {m for m, _ in calls}
    assert methods_used == {"GET"}  # DELETE escluso di default

    urls = [url for _, url in calls]
    # BOLA orizzontale: si attacca l'ordine 101 (della vittima) con il token del peer
    assert any(url.endswith("/api/orders/101") for url in urls)
    # BOLA verticale: si attacca l'ordine 900 (dell'admin)
    assert any(url.endswith("/api/orders/900") for url in urls)
    # 3 scenari * 3 chiamate (owner/attacker/anon) = 9 richieste sul solo GET
    assert len(calls) == 9
    assert findings, "la pipeline deve produrre findings di sbarramento"


def test_assessment_excludes_mutations_by_default(tmp_path, attack_request):
    _, _, calls = _run(tmp_path, attack_request)
    assert all(method == "GET" for method, _ in calls)


def test_allow_mutations_reenables_destructive_methods(tmp_path, attack_request):
    _, _, calls = _run(tmp_path, attack_request, allow_mutations=True)
    methods_used = {m for m, _ in calls}
    assert methods_used == {"GET", "DELETE"}
