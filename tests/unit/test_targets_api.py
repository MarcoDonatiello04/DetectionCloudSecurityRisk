"""
Bersagli selezionabili dalla dashboard principale (src/presentation/api/server.py): sintesi e
findings dell'ultima scansione letti dalla cartella dei report di ciascun bersaglio.
"""

import json

import pytest
from fastapi.testclient import TestClient

from src.presentation.api import external_targets as et
from src.presentation.api import server

REGISTRY = """
version: 1
targets:
  esterno:
    label: Bersaglio esterno
    target_dir: {code}
    base_url: http://127.0.0.1:9
    output_dir: {out}
    bola_config: config/bola_target.yaml
    port: 8197
"""

MODULES = [
    {"name": "BOLA (Broken Object Level Authorization)", "status": "SKIPPED", "findings": 0},
    {"name": "SSRF", "dir": "src/core/api7_ssrf", "status": "SUCCESS", "findings": 2, "time": 1.5},
]


@pytest.fixture
def client(tmp_path, monkeypatch):
    main_out, ext_out, code = tmp_path / "main", tmp_path / "ext", tmp_path / "code"
    for d in (main_out, ext_out, code):
        d.mkdir()
    registry = tmp_path / "registry.yaml"
    registry.write_text(REGISTRY.format(code=code, out=ext_out), encoding="utf-8")
    monkeypatch.setattr(et, "REGISTRY_PATH", registry)
    monkeypatch.setattr(et, "dashboard_running", lambda target: False)
    monkeypatch.setattr(server, "OUTPUT_DIR", str(main_out))
    # Stato del modulo: parti da un bersaglio noto, così i test non dipendono dall'ordine.
    monkeypatch.setattr(server, "CURRENT_TARGET_ID", "repo_target")
    (ext_out / "benchmark_results.json").write_text(json.dumps(MODULES))
    (ext_out / "core_findings.json").write_text(
        json.dumps({"modules": MODULES, "findings": {"ssrf": [{"title": "a"}, {"title": "b"}]}})
    )
    return TestClient(server.app)


def test_targets_list_each_target_with_its_own_results(client):
    body = client.get("/api/targets").json()
    targets = {t["id"]: t for t in body["targets"]}
    # Il catalogo unico include i bersagli locali (repo target) e quelli del registro esterno.
    assert "repo_target" in targets
    assert body["current"] in targets
    assert targets["esterno"]["summary"]["totals"]["findings"] == 2
    assert targets["esterno"]["results_url"] == "/unified-results?target=esterno"
    assert targets["esterno"]["external"] is True


def test_select_target_switches_current(client):
    # Passa al bersaglio esterno del registro e verifica che diventi il corrente.
    resp = client.post("/api/select-target", params={"id": "esterno"})
    assert resp.status_code == 200
    assert resp.json()["current"] == "esterno"
    assert client.get("/api/targets").json()["current"] == "esterno"


def test_select_unknown_target_is_404(client):
    assert client.post("/api/select-target", params={"id": "non-esiste"}).status_code == 404


def test_select_target_blocked_during_bola_scan(client, monkeypatch):
    # Con una scansione BOLA registrata, lo switch è rifiutato con 409.
    monkeypatch.setitem(server._active_bola_scans, "scan-xyz", object())
    assert client.post("/api/select-target", params={"id": "esterno"}).status_code == 409


def test_findings_of_saved_scan_per_target(client):
    data = client.get("/api/targets/esterno/findings").json()
    assert data["label"] == "Bersaglio esterno"
    assert [m["name"] for m in data["modules"]] == [m["name"] for m in MODULES]
    assert len(data["findings"]["ssrf"]) == 2
    empty = client.get("/api/targets/principale/findings").json()
    assert empty["modules"] == [] and empty["findings"] == {}
    assert client.get("/api/targets/sconosciuto/findings").status_code == 404


STATIC_REPORT = [
    {"source": "CHECKOV", "title": "S3 senza cifratura"},
    {"source": "CHECKOV", "title": "SG aperto"},
    {"source": "SPECTRAL", "title": "operationId mancante"},
]


def test_static_analysis_is_reported_per_target(client, tmp_path):
    (tmp_path / "ext" / "unified_security_report.json").write_text(json.dumps(STATIC_REPORT))
    targets = {t["id"]: t for t in client.get("/api/targets").json()["targets"]}
    static = targets["esterno"]["static"]
    assert static["available"] is True and static["total"] == 3
    assert static["by_source"] == {"CHECKOV": 2, "SPECTRAL": 1}
    assert static["generated_at"]


def test_saved_reports_are_read_from_the_requested_target(client, tmp_path):
    ext, main = tmp_path / "ext", tmp_path / "main"
    (ext / "unified_security_report.json").write_text(json.dumps(STATIC_REPORT))
    (ext / "bola_scan_results.json").write_text(
        json.dumps({"meta": {"total_tests": 4}, "results": []})
    )
    (ext / "openapi_merged.yaml").write_text("openapi: 3.0.0\n")
    (main / "unified_security_report.json").write_text("[]")

    assert len(client.get("/api/report?target=esterno").json()) == 3
    assert client.get("/api/report").json() == []  # senza target: bersaglio corrente
    assert client.get("/api/bola-report?target=esterno").json()["meta"]["total_tests"] == 4
    assert client.get("/api/openapi-spec?target=esterno").json()["spec"] == "openapi: 3.0.0\n"
    assert client.get("/api/report?target=sconosciuto").status_code == 404


def test_targets_sharing_code_are_told_apart_by_output_dir():
    from src.presentation.api import target_catalog as tc

    vampi = "data/test_targets/external/vampi"
    assert tc.match_by_dirs(vampi, output_dir="output/external/vampi_sicuro") == "vampi_sicuro"
    assert tc.match_by_dirs(vampi, output_dir="output/external/vampi") == "vampi"


def test_switching_target_reloads_its_bola_contract(monkeypatch):
    from src.core.api1_bola import target_config as tc

    loaded = []
    monkeypatch.setattr(server, "load_bola_target_config", lambda path: loaded.append(path) or path)
    monkeypatch.setattr(server, "reset_bola_target_config", lambda cfg: None)
    monkeypatch.setattr(server.os, "makedirs", lambda *a, **k: None)
    monkeypatch.delenv("OPENAPI_SPEC_PATH", raising=False)  # ripristinata a fine test
    for attr in ("TARGET_DIR", "TARGET_BASE_URL", "OUTPUT_DIR", "CURRENT_TARGET_ID"):
        monkeypatch.setattr(server, attr, getattr(server, attr))
    catalog = server._catalog()
    server._apply_target(catalog["vampi_sicuro"])
    server._apply_target(catalog["repo_target"])
    assert loaded == ["config/targets/vampi_sicuro_bola.yaml", None]
    assert tc  # il modulo resta importabile
