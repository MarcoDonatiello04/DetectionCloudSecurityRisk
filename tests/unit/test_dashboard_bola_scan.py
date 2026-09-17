"""L'endpoint /bola-scan della dashboard deve passare il traffico catturato alla pipeline D-AST."""

import json
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from src.presentation.api import server


def test_bola_scan_forwards_captured_traffic(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "output").mkdir()
    traffic = [{"method": "GET", "path": "/api/projects/7", "status": 200, "headers": {}}]
    (tmp_path / "output" / "raw_traffic.json").write_text(json.dumps(traffic), encoding="utf-8")

    fake_orchestrator = MagicMock()
    fake_orchestrator.target_base_url = "http://localhost:5000"
    fake_orchestrator.is_cancelled = False
    fake_orchestrator.zap_controller.test_results = []

    with patch(
        "src.core.api1_bola.dynamic_orchestrator.DynamicOrchestrator",
        return_value=fake_orchestrator,
    ):
        response = TestClient(server.app).post("/bola-scan")

    assert response.status_code == 200
    assert "error" not in response.json()["meta"]
    fake_orchestrator.run_dast_pipeline.assert_called_once()
    assert fake_orchestrator.run_dast_pipeline.call_args.kwargs["raw_traffic"] == traffic
