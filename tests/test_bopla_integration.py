import os
import pytest
import json
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock

from src.core.broken_authentication.discovery import Config
from src.core.bopla.orchestrator import BOPLAOrchestrator
from src.core.bopla.models import PropertyInventory


@pytest.fixture
def temp_output_dir(tmp_path):
    # Returns a temporary path to use as output directory
    return tmp_path / "output"


@pytest.fixture
def mock_config(temp_output_dir):
    config = Config()
    config.output.path = str(temp_output_dir)
    return config


@pytest.fixture
def mock_headers():
    return {
        "userA": {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyX2FfdXVpZCJ9.sig"},
        "userC": {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91dWlkIn0.sig"}
    }


@patch("requests.request")
def test_bopla_orchestrator_full_pipeline(mock_req, mock_config, mock_headers, tmp_path):
    # Set up some mock files in repo_path to allow AST scanning to run
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    py_model = repo_path / "models.py"
    py_model.write_text("""
class User:
    id: int
    salary: float
""", encoding="utf-8")

    # Mock openapi spec
    openapi_spec = {
        "components": {
            "schemas": {
                "User": {
                    "properties": {
                        "id": {"type": "integer"}
                    }
                }
            }
        }
    }

    # Mock runtime traffic
    runtime_traffic = [
        {
            "method": "GET",
            "path": "/api/users/123",
            "response": {"id": 123, "salary": 5000}
        }
    ]

    # Mock HTTP responses for dynamic tester
    def mock_side_effect(method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if method == "GET":
            resp.text = '{"id": 123, "salary": 5000}'
            resp.json.return_value = {"id": 123, "salary": 5000}
        else:
            resp.text = '{"status": "success"}'
            resp.json.return_value = {"status": "success"}
        return resp
    mock_req.side_effect = mock_side_effect

    orchestrator = BOPLAOrchestrator(mock_config)
    report = orchestrator.run_assessment(
        repo_path=str(repo_path),
        openapi_spec=openapi_spec,
        runtime_traffic=runtime_traffic,
        headers_matrix=mock_headers
    )

    # 1. Verify report statistics
    assert report["objects_discovered"] == 1
    assert report["properties_discovered"] == 2  # id and salary
    assert len(report["findings"]) > 0

    # 2. Verify files are created
    output_bopla_dir = Path(mock_config.output.path) / "bopla"
    assert output_bopla_dir.exists()
    assert (output_bopla_dir / "bopla_report.json").exists()
    assert (output_bopla_dir / "bopla_report.md").exists()

    # Load and verify JSON contents
    with open(output_bopla_dir / "bopla_report.json", "r") as jf:
        saved_report = json.load(jf)
        assert saved_report["score"] < 100
        assert saved_report["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")


def test_bopla_orchestrator_graceful_degradation(mock_config, tmp_path):
    # Run with empty inputs and verify it still runs without raising exceptions
    repo_path = tmp_path / "empty_repo"
    repo_path.mkdir()

    orchestrator = BOPLAOrchestrator(mock_config)
    report = orchestrator.run_assessment(
        repo_path=str(repo_path),
        openapi_spec=None,
        runtime_traffic=None,
        headers_matrix=None
    )

    assert report["objects_discovered"] == 0
    assert report["properties_discovered"] == 0
    assert report["score"] == 100
    assert report["risk_level"] == "LOW"

    # Files should still be generated
    output_bopla_dir = Path(mock_config.output.path) / "bopla"
    assert (output_bopla_dir / "bopla_report.json").exists()
    assert (output_bopla_dir / "bopla_report.md").exists()
