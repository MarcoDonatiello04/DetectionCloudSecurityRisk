"""
Validazione del modulo BOPLA sulle applicazioni gemelle
(data/test_targets/broken_object_property_level_authorization).

L'intera pipeline (inventario, inferenza, prove dinamiche, punteggio) gira sul codice reale di
ciascuna variante; le richieste HTTP del tester vengono instradate verso `handle()` dell'app,
che mantiene uno stato in memoria, quindi la verifica di persistenza e' effettiva.
"""

import base64
import importlib.util
import json
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.parse import urlparse

import pytest

from src.core.api2_broken_auth.discovery import Config
from src.core.api3_bopla.orchestrator import BOPLAOrchestrator

PROJECT_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists())
TWINS_DIR = PROJECT_ROOT / "data/test_targets/broken_object_property_level_authorization"
ALL_TESTS = {"T01", "T02", "T03", "T04", "T05", "T06", "T07"}


def _token(sub: str) -> str:
    payload = base64.urlsafe_b64encode(json.dumps({"sub": sub}).encode()).decode().rstrip("=")
    return f"Bearer eyJhbGciOiJub25lIn0.{payload}.sig"


HEADERS_MATRIX = {
    "userA": {"Authorization": _token("alice")},
    "userC": {"Authorization": _token("admin")},
}


def _load_app(variant: str):
    path = TWINS_DIR / variant / "app.py"
    spec = importlib.util.spec_from_file_location(f"bopla_twin_{variant}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.reset()
    return module


def _route_to(app):
    def side_effect(method, url, **kwargs):
        status, body = app.handle(
            method, urlparse(url).path, kwargs.get("headers"), kwargs.get("json")
        )
        resp = MagicMock()
        resp.status_code = status
        resp.text = json.dumps(body)
        resp.json.return_value = body
        return resp

    return side_effect


def _run(variant: str, tmp_path):
    app = _load_app(variant)
    config = Config()
    config.output.path = str(tmp_path)
    spec = json.loads((TWINS_DIR / "openapi.json").read_text())
    traffic = json.loads((TWINS_DIR / "client_traffic.json").read_text())
    with patch("requests.request", side_effect=_route_to(app)):
        return BOPLAOrchestrator(config).run_assessment(
            repo_path=str(TWINS_DIR / variant),
            openapi_spec=spec,
            runtime_traffic=traffic,
            headers_matrix=HEADERS_MATRIX,
        )


def test_vulnerable_twin_every_test_confirms_its_condition(tmp_path):
    report = _run("vulnerable_app", tmp_path)

    confirmed = {f["test_id"] for f in report["findings"] if f["verified"]}
    assert confirmed == ALL_TESTS
    confirmed_props = {f["property_name"] for f in report["findings"] if f["verified"]}
    assert confirmed_props <= {"salary", "role"}
    assert report["dynamic_phase_executed"] is True
    assert report["score"] == 0
    assert report["risk_level"] == "CRITICAL"


def test_secure_twin_produces_no_confirmed_finding(tmp_path):
    report = _run("secure_app", tmp_path)

    confirmed = [f for f in report["findings"] if f["verified"]]
    assert confirmed == [], [(f["test_id"], f["property_name"]) for f in confirmed]
    assert report["dynamic_phase_executed"] is True
    assert report["score"] == 100
    assert report["risk_level"] == "LOW"

    # The differential tests still ran and recorded the properties as protected.
    protected = {(f["test_id"], f["property_name"]) for f in report["findings"]}
    assert {("T06", "salary"), ("T06", "role"), ("T07", "salary"), ("T07", "role")} <= protected


@pytest.mark.parametrize("variant", ["vulnerable_app", "secure_app"])
def test_static_phases_infer_the_same_protected_properties(variant, tmp_path):
    report = _run(variant, tmp_path)
    user = report["graph"]["objects"]["User"]["properties"]
    protected = {name for name, node in user.items() if node["authorization_contexts"]}
    # Ordinary fields and the ownership check (current_user.id != user.id) are not protected.
    assert protected == {"salary", "role"}
