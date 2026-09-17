"""
La cancellazione di una scansione BOLA dalla dashboard passa per un registro
scan_id -> orchestrator: ogni scansione ha il proprio segnale, nessuno stato di classe.
"""

import threading
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from src.presentation.api import server


def _fake_orchestrator() -> MagicMock:
    fake = MagicMock()
    fake.target_base_url = "http://localhost:5000"
    fake.is_cancelled = False
    fake.zap_controller.test_results = []
    return fake


def _clear_registry():
    with server._active_bola_scans_lock:
        server._active_bola_scans.clear()


def test_cancel_targets_only_the_requested_scan():
    _clear_registry()
    first, second = _fake_orchestrator(), _fake_orchestrator()
    server._register_bola_scan("scan-1", first)
    server._register_bola_scan("scan-2", second)

    response = TestClient(server.app).post("/cancel-bola-scan", params={"scan_id": "scan-1"})

    assert response.json() == {"status": "cancelled", "scan_ids": ["scan-1"]}
    first.cancel.assert_called_once()
    second.cancel.assert_not_called()
    _clear_registry()


def test_cancel_without_id_stops_every_active_scan():
    _clear_registry()
    first, second = _fake_orchestrator(), _fake_orchestrator()
    server._register_bola_scan("scan-1", first)
    server._register_bola_scan("scan-2", second)

    response = TestClient(server.app).post("/cancel-bola-scan")

    assert response.json()["status"] == "cancelled"
    assert sorted(response.json()["scan_ids"]) == ["scan-1", "scan-2"]
    first.cancel.assert_called_once()
    second.cancel.assert_called_once()
    _clear_registry()


def test_cancel_unknown_scan_is_a_noop():
    _clear_registry()
    response = TestClient(server.app).post("/cancel-bola-scan", params={"scan_id": "ghost"})
    assert response.json() == {"status": "not_found", "scan_ids": []}


def test_scan_is_registered_during_run_and_removed_after(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _clear_registry()
    fake = _fake_orchestrator()
    seen_during_run: dict[str, list[str]] = {}

    def capture_registry(**_):
        with server._active_bola_scans_lock:
            seen_during_run["ids"] = list(server._active_bola_scans)

    fake.run_dast_pipeline.side_effect = capture_registry

    with patch("src.core.api1_bola.dynamic_orchestrator.DynamicOrchestrator", return_value=fake):
        response = TestClient(server.app).post("/bola-scan")

    scan_id = response.json()["meta"]["scan_id"]
    assert seen_during_run["ids"] == [scan_id]
    assert server._active_bola_scans == {}
    assert response.json()["meta"]["cancelled"] is False


def test_scan_is_unregistered_when_pipeline_fails(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _clear_registry()
    fake = _fake_orchestrator()
    fake.run_dast_pipeline.side_effect = RuntimeError("ZAP down")

    with patch("src.core.api1_bola.dynamic_orchestrator.DynamicOrchestrator", return_value=fake):
        response = TestClient(server.app).post("/bola-scan")

    assert "error" in response.json()["meta"]
    assert server._active_bola_scans == {}


def test_cancel_reaches_a_real_orchestrator_event():
    # Il registro deve propagare il cancel() fino al threading.Event del ZapController reale.
    _clear_registry()
    event = threading.Event()
    with (
        patch("src.core.api1_bola.dynamic_orchestrator.ZAPv2"),
        patch("src.core.api1_bola.dynamic_orchestrator.IdentityManager"),
        patch("src.core.api1_bola.dynamic_orchestrator.DatabaseSeeder"),
    ):
        from src.core.api1_bola.dynamic_orchestrator import DynamicOrchestrator

        orchestrator = DynamicOrchestrator(
            target_base_url="http://t.local",
            keycloak_url="http://kc.local",
            zap_proxy_url="http://zap.local",
            cancel_event=event,
        )
    server._register_bola_scan("real", orchestrator)

    TestClient(server.app).post("/cancel-bola-scan", params={"scan_id": "real"})

    assert event.is_set()
    assert orchestrator.zap_controller.is_cancelled is True
    _clear_registry()
