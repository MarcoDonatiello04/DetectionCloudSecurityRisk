"""
Test di robustezza del motore di attacco BOLA (ZapController / DynamicOrchestrator):
cancellazione per istanza, timeout del polling ZAP, metodi presi dall'inventario
e snapshot/rollback limitato ai metodi che mutano lo stato.
"""

import threading
from unittest.mock import MagicMock, patch

import pytest

from src.core.api1_bola import dynamic_orchestrator as dyn
from src.core.api1_bola.dynamic_orchestrator import (
    ALL_HTTP_METHODS,
    DynamicOrchestrator,
    ZapController,
)

MODULE = "src.core.api1_bola.dynamic_orchestrator"
TARGET = "http://target.local"
HEADERS = {"userA": {"Authorization": "A"}, "userB": {"Authorization": "B"}}


@pytest.fixture
def zap_mock():
    with patch(f"{MODULE}.ZAPv2") as zap_cls:
        # Senza questo il polling finale vedrebbe int(MagicMock) == 1 e attenderebbe il timeout
        zap_cls.return_value.ascan.status.return_value = "100"
        yield zap_cls.return_value


@pytest.fixture
def state_engine():
    with patch(f"{MODULE}.APIStateEngine") as engine:
        yield engine


@pytest.fixture
def attack_generator():
    with patch(f"{MODULE}.ContextAwareAttackGenerator") as gen_cls:
        gen_cls.return_value.execute_tampering.return_value = []
        yield gen_cls.return_value


def _run(controller: ZapController, endpoints, tmp_path, **kwargs):
    controller.run_differential_scan(
        target_base_url=TARGET,
        dynamic_endpoints=endpoints,
        headers_matrix=HEADERS,
        identity_uuids={"victim": "a", "peer": "b", "privileged": "c"},
        role_map={},
        output_dir=str(tmp_path),
        **kwargs,
    )


def _tested_methods(attack_generator) -> list[str]:
    return [c.kwargs["method"] for c in attack_generator.execute_tampering.call_args_list]


# ─── B3: metodi presi dall'inventario ───────────────────────────────────────


def test_select_methods_uses_inventory_and_falls_back_to_get():
    assert ZapController._select_methods({"methods": ["delete", "GET"]}, False) == [
        "GET",
        "DELETE",
    ]
    assert ZapController._select_methods({"methods": []}, False) == ["GET"]
    assert ZapController._select_methods({}, False) == ["GET"]
    assert ZapController._select_methods({"methods": ["GET"]}, True) == list(ALL_HTTP_METHODS)


def test_scan_tests_only_declared_methods(zap_mock, state_engine, attack_generator, tmp_path):
    controller = ZapController("http://zap.local")
    _run(controller, [{"path": "/api/orders/{id}", "methods": ["GET"]}], tmp_path)
    assert _tested_methods(attack_generator) == ["GET"]


def test_scan_all_methods_flag_is_exhaustive(zap_mock, state_engine, attack_generator, tmp_path):
    controller = ZapController("http://zap.local")
    _run(
        controller,
        [{"path": "/api/orders/{id}", "methods": ["GET"]}],
        tmp_path,
        test_all_methods=True,
    )
    assert _tested_methods(attack_generator) == list(ALL_HTTP_METHODS)


# ─── B4: snapshot/rollback solo per metodi mutanti ──────────────────────────


def test_snapshot_rollback_only_for_state_mutating_methods(
    zap_mock, state_engine, attack_generator, tmp_path
):
    controller = ZapController("http://zap.local")
    _run(
        controller,
        [{"path": "/api/orders/{id}", "methods": ["GET", "DELETE", "PUT"]}],
        tmp_path,
    )
    assert _tested_methods(attack_generator) == ["GET", "PUT", "DELETE"]
    # GET non altera lo stato: due soli snapshot/rollback (PUT e DELETE)
    assert state_engine.take_snapshot.call_count == 2
    assert state_engine.trigger_rollback.call_count == 2


def test_no_snapshot_when_state_management_disabled(
    zap_mock, state_engine, attack_generator, tmp_path
):
    controller = ZapController("http://zap.local")
    _run(
        controller,
        [{"path": "/api/orders/{id}", "methods": ["DELETE"]}],
        tmp_path,
        use_state_management=False,
    )
    state_engine.take_snapshot.assert_not_called()
    state_engine.trigger_rollback.assert_not_called()


# ─── B1: cancellazione per istanza ──────────────────────────────────────────


def test_cancel_event_is_per_instance(zap_mock):
    first = ZapController("http://zap.local")
    second = ZapController("http://zap.local")
    first.cancel()
    assert first.is_cancelled is True
    assert second.is_cancelled is False
    assert not hasattr(ZapController, "_is_cancelled")


def test_cancel_stops_scan_loop(zap_mock, state_engine, attack_generator, tmp_path):
    controller = ZapController("http://zap.local")

    # Il primo attacco cancella la scansione: nessun altro metodo/endpoint viene esercitato
    def tamper_then_cancel(**_):
        controller.cancel()
        return []

    attack_generator.execute_tampering.side_effect = tamper_then_cancel
    _run(
        controller,
        [
            {"path": "/api/orders/{id}", "methods": ["GET", "DELETE"]},
            {"path": "/api/invoices/{id}", "methods": ["GET"]},
        ],
        tmp_path,
    )
    assert attack_generator.execute_tampering.call_count == 1
    zap_mock.ascan.stop_all_scans.assert_called_once()


def test_cancelled_scan_does_not_leak_into_new_instance(
    zap_mock, state_engine, attack_generator, tmp_path
):
    cancelled = ZapController("http://zap.local")
    cancelled.cancel()
    _run(cancelled, [{"path": "/api/orders/{id}", "methods": ["GET"]}], tmp_path)
    assert attack_generator.execute_tampering.call_count == 0

    fresh = ZapController("http://zap.local")
    _run(fresh, [{"path": "/api/orders/{id}", "methods": ["GET"]}], tmp_path)
    assert attack_generator.execute_tampering.call_count == 1


def test_orchestrator_shares_cancel_event_with_controller(zap_mock):
    with patch(f"{MODULE}.IdentityManager"), patch(f"{MODULE}.DatabaseSeeder"):
        orchestrator = DynamicOrchestrator(
            target_base_url=TARGET,
            keycloak_url="http://kc.local",
            zap_proxy_url="http://zap.local",
        )
        other = DynamicOrchestrator(
            target_base_url=TARGET,
            keycloak_url="http://kc.local",
            zap_proxy_url="http://zap.local",
        )
    orchestrator.cancel()
    assert orchestrator.is_cancelled is True
    assert orchestrator.zap_controller.is_cancelled is True
    assert other.is_cancelled is False
    assert other.zap_controller.is_cancelled is False


def test_orchestrator_accepts_injected_cancel_event(zap_mock):
    event = threading.Event()
    with patch(f"{MODULE}.IdentityManager"), patch(f"{MODULE}.DatabaseSeeder"):
        orchestrator = DynamicOrchestrator(
            target_base_url=TARGET,
            keycloak_url="http://kc.local",
            zap_proxy_url="http://zap.local",
            cancel_event=event,
        )
    event.set()
    assert orchestrator.zap_controller.cancel_event is event
    assert orchestrator.is_cancelled is True


# ─── B2: polling ZAP con timeout ────────────────────────────────────────────


def test_wait_for_scan_completion_times_out_and_stops_scans(zap_mock, monkeypatch):
    zap_mock.ascan.status.return_value = "99"  # ZAP bloccato al 99%
    monkeypatch.setattr(dyn, "ZAP_ACTIVE_SCAN_TIMEOUT_SECONDS", 10)
    clock = iter([0.0, 5.0, 11.0])  # deadline=10: primo giro sotto soglia, secondo oltre
    monkeypatch.setattr(dyn.time, "monotonic", lambda: next(clock))

    controller = ZapController("http://zap.local")
    controller.cancel_event = MagicMock(wraps=controller.cancel_event)
    controller.cancel_event.is_set.return_value = False
    controller.cancel_event.wait.return_value = False

    controller._wait_for_scan_completion()

    assert zap_mock.ascan.status.call_count == 2
    zap_mock.ascan.stop_all_scans.assert_called_once()


def test_wait_for_scan_completion_returns_when_done(zap_mock, monkeypatch):
    zap_mock.ascan.status.side_effect = ["40", "100"]
    monkeypatch.setattr(dyn.time, "monotonic", lambda: 0.0)
    controller = ZapController("http://zap.local")
    controller.cancel_event = MagicMock(wraps=controller.cancel_event)
    controller.cancel_event.is_set.return_value = False
    controller.cancel_event.wait.return_value = False

    controller._wait_for_scan_completion()

    assert zap_mock.ascan.status.call_count == 2
    zap_mock.ascan.stop_all_scans.assert_not_called()


def test_wait_for_scan_completion_honours_cancellation(zap_mock):
    zap_mock.ascan.status.return_value = "10"
    controller = ZapController("http://zap.local")
    controller.cancel()

    controller._wait_for_scan_completion()

    zap_mock.ascan.status.assert_not_called()
    zap_mock.ascan.stop_all_scans.assert_called_once()
