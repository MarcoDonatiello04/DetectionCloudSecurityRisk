"""
Sezione "Bersagli esterni" della dashboard (src/presentation/api/external_targets.py).

I test usano un registro e cartelle temporanei: non avviano container né dashboard e non
toccano i bersagli dell'insieme di prova.
"""

from datetime import datetime
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.presentation.api import external_targets as et

REGISTRY = """
version: 1
targets:
  app_target:
    label: App di prova
    target_dir: {code}
    base_url: http://127.0.0.1:9
    output_dir: {out}
    bola_config: config/bola_target.yaml
    port: 8199
    compose_dir: {code}
    compose_build: true
    traffic: true
  iac_only:
    label: Solo Terraform
    target_dir: {code}
    base_url: http://127.0.0.1:9
    output_dir: {out}
    bola_config: config/bola_target.yaml
    port: 8198
"""


@pytest.fixture
def registry(tmp_path, monkeypatch):
    code, out = tmp_path / "code", tmp_path / "out"
    code.mkdir()
    out.mkdir()
    path = tmp_path / "registry.yaml"
    path.write_text(REGISTRY.format(code=code, out=out), encoding="utf-8")
    monkeypatch.setattr(et, "REGISTRY_PATH", path)
    monkeypatch.setattr(et, "ARCHIVE_DIR", tmp_path / "risultati")
    monkeypatch.setattr(et, "LOGS_DIR", tmp_path / "logs")
    monkeypatch.setattr(et, "_tool_versions", lambda: "commit: test\n")
    return et.load_registry()


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(et.router)
    return TestClient(app)


def test_project_registry_is_consistent():
    targets = et.load_registry(Path("config/targets/registry.yaml"))
    assert {"vampi", "vampi_sicuro", "dvapi", "sadcloud"} <= set(targets)
    ports = [t.port for t in targets.values()]
    assert len(ports) == len(set(ports)) and 8000 not in ports
    assert not targets["sadcloud"].has_app and not targets["sadcloud"].traffic


def test_dashboard_is_dedicated_and_without_panel(registry):
    target = registry["app_target"]
    env = target.dashboard_env()
    assert env["TARGET_DIR"] == target.target_dir
    assert env["OUTPUT_DIR"] == target.output_dir
    assert env["EXTERNAL_TARGETS_PANEL"] == "0"
    cmd = et.dashboard_command(target)
    assert "--reload" not in cmd
    assert cmd[cmd.index("--port") + 1] == "8199"
    assert cmd[cmd.index("--host") + 1] == "127.0.0.1"


def test_compose_build_flag(registry):
    assert et.app_up_command(registry["app_target"])[-1] == "--build"
    assert "--build" not in et.app_up_command(registry["iac_only"])


def test_status_lists_targets_without_reading_reports(registry, client):
    (Path(registry["app_target"].output_dir) / "core_findings.json").write_text("{}")
    data = client.get("/api/external-targets").json()
    by_id = {t["id"]: t for t in data["targets"]}
    assert by_id["iac_only"]["has_app"] is False
    evidence = {e["file"]: e["present"] for e in by_id["app_target"]["evidence"]}
    assert evidence["core_findings.json"] is True
    assert evidence["bola_scan_results.json"] is False


def test_actions_refused_for_non_local_clients(registry, client):
    # Il TestClient si presenta come host "testclient", cioè non locale.
    for action in ("app/start", "traffic", "dashboard/start", "archive", "scan"):
        assert client.post(f"/api/external-targets/app_target/{action}").status_code == 403


def test_archive_never_overwrites(registry):
    target = registry["app_target"]
    (Path(target.output_dir) / "core_findings.json").write_text("{}")
    day = datetime(2026, 10, 1)
    first = et.archive_evidence(target, now=day)
    second = et.archive_evidence(target, now=day)
    assert first.name == "2026-10-01_app_target"
    assert second.name == "2026-10-01_app_target_2"
    assert (first / "core_findings.json").exists()
    assert (first / "versioni.txt").read_text() == "commit: test\n"


def test_archive_without_reports_is_refused(registry):
    with pytest.raises(et.HTTPException) as err:
        et.archive_evidence(
            registry["iac_only"].__class__(
                **{**registry["iac_only"].__dict__, "output_dir": str(et.ARCHIVE_DIR / "vuota")}
            )
        )
    assert err.value.status_code == 404


def _run_steps(steps):
    import io

    log = io.StringIO()
    codes = []
    for step in steps:
        codes.append(step(log))
        if codes[-1] != 0:
            break
    return codes, log.getvalue()


def test_prepare_skips_what_is_already_running(registry, monkeypatch):
    launched = []
    monkeypatch.setattr(et, "_services_up", lambda: True)
    monkeypatch.setattr(et, "_port_open", lambda host, port, timeout=0.5: True)
    monkeypatch.setattr(et, "_url_reachable", lambda url, timeout=2.0: True)
    monkeypatch.setattr(
        et, "_command_step", lambda cmd, cwd=None: lambda log: launched.append(cmd) or 0
    )
    monkeypatch.setattr(
        et, "_launch_dashboard", lambda t: {"status": "already_running", "url": "u"}
    )
    codes, log = _run_steps(et.prepare_steps(registry["app_target"], with_traffic=True))
    assert all(c == 0 for c in codes)
    assert "già attivi" in log and "già in esecuzione" in log
    # L'unico comando eseguito è il traffico: servizi e applicazione erano già attivi.
    assert launched == [et.traffic_command(registry["app_target"])]


def test_prepare_without_traffic_and_without_app(registry, monkeypatch):
    launched = []
    monkeypatch.setattr(et, "_services_up", lambda: True)
    monkeypatch.setattr(et, "_port_open", lambda host, port, timeout=0.5: True)
    monkeypatch.setattr(et, "_url_reachable", lambda url, timeout=2.0: True)
    monkeypatch.setattr(
        et, "_command_step", lambda cmd, cwd=None: lambda log: launched.append(cmd) or 0
    )
    monkeypatch.setattr(et, "_launch_dashboard", lambda t: {"status": "started", "url": "u"})
    codes, log = _run_steps(et.prepare_steps(registry["app_target"], with_traffic=False))
    assert launched == [] and "saltato" in log
    codes, _ = _run_steps(et.prepare_steps(registry["iac_only"]))
    assert all(c == 0 for c in codes)


def test_prepare_stops_when_app_does_not_answer(registry, monkeypatch):
    monkeypatch.setattr(et, "_services_up", lambda: True)
    monkeypatch.setattr(et, "_port_open", lambda host, port, timeout=0.5: True)
    monkeypatch.setattr(et, "_url_reachable", lambda url, timeout=2.0: False)
    monkeypatch.setattr(et, "_command_step", lambda cmd, cwd=None: lambda log: 0)
    monkeypatch.setattr(et, "APP_WAIT_SECONDS", 0)
    codes, log = _run_steps(et.prepare_steps(registry["app_target"]))
    assert codes[-1] == 1 and "tempo scaduto" in log


def test_compose_overrides_are_applied(tmp_path):
    target = et.ExternalTarget(
        id="x",
        label="x",
        target_dir=".",
        base_url="http://127.0.0.1:9",
        output_dir=".",
        bola_config="c.yaml",
        port=8197,
        compose_dir=".",
        compose_overrides=("config/targets/dvapi.compose.override.yml",),
    )
    up = et.app_up_command(target)
    assert up[:4] == ["docker", "compose", "-f", "docker-compose.yml"]
    assert up[5].endswith("config/targets/dvapi.compose.override.yml") and Path(up[5]).is_absolute()
    assert et.app_down_command(target)[-1] == "down"


def test_metrics_endpoint_requires_ground_truth_and_evidence(
    registry, client, tmp_path, monkeypatch
):
    # Bersaglio senza riferimento di verità: 404 esplicito, nessun calcolo
    monkeypatch.setattr(et, "GROUND_TRUTH_DIR", tmp_path / "gt")
    assert client.get("/api/external-targets/app_target/metrics").status_code == 404
    gt = tmp_path / "gt"
    gt.mkdir()
    (gt / "app_target.yaml").write_text(
        'voci:\n  - id: X01\n    punto_esposizione: {metodo: GET, percorso: "/a/{id}"}\n'
        "    categoria_owasp_2023: API1\n",
        encoding="utf-8",
    )
    out = Path(registry["app_target"].output_dir)
    (out / "core_findings.json").write_text(
        '{"findings": {"bola": [{"method": "GET", "endpoint": "/a/7", "is_vulnerable": true}]}}'
    )
    data = client.get("/api/external-targets/app_target/metrics").json()
    assert data["complessivo"]["vp"] == 1 and data["complessivo"]["recall"] == 1.0


class _FakeResponse:
    def __init__(self, payload):
        import json

        self._body = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _fake_opener(monkeypatch, handler):
    class Opener:
        def open(self, request, timeout=None):
            return handler(request, timeout)

    monkeypatch.setattr(et.urllib.request, "build_opener", lambda *a: Opener())


def test_scan_runs_in_dedicated_dashboard_after_prepare(registry, monkeypatch):
    calls = []
    monkeypatch.setattr(et, "prepare_steps", lambda t, with_traffic: [lambda log: 0])

    def handler(request, timeout):
        calls.append((request.full_url, request.get_method(), timeout))
        return _FakeResponse({"benchmark": [{"name": "BFLA", "status": "SUCCESS", "findings": 3}]})

    _fake_opener(monkeypatch, handler)
    codes, log = _run_steps(et.scan_steps(registry["app_target"], run_bola=False))
    assert codes == [0, 0]
    assert calls == [("http://127.0.0.1:8199/api/scan/non-bola", "POST", et.SCAN_TIMEOUT_SECONDS)]
    assert "BFLA: SUCCESS · 3 findings" in log and "1 moduli, 3 findings" in log

    calls.clear()
    _run_steps(et.scan_steps(registry["app_target"], run_bola=True))
    assert calls[0][0].endswith("/api/scan/all") and calls[0][2] == et.SCAN_TIMEOUT_BOLA_SECONDS


def test_scan_traffic_only_with_bola(registry, monkeypatch):
    seen = []
    monkeypatch.setattr(
        et, "prepare_steps", lambda t, with_traffic: seen.append(with_traffic) or []
    )
    et.scan_steps(registry["app_target"], run_bola=False)
    et.scan_steps(registry["app_target"], run_bola=True)
    assert seen == [False, True]


def test_scan_failure_is_reported(registry, monkeypatch):
    monkeypatch.setattr(et, "prepare_steps", lambda t, with_traffic: [])

    def handler(request, timeout):
        raise OSError("connessione rifiutata")

    _fake_opener(monkeypatch, handler)
    codes, log = _run_steps(et.scan_steps(registry["iac_only"], run_bola=False))
    assert codes == [1] and "connessione rifiutata" in log
