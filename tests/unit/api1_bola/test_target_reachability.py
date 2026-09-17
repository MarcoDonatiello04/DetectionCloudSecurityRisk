"""Check di raggiungibilita' del target cooperante prima della fase D-AST."""

from unittest.mock import MagicMock, patch

import pytest
import requests

from src.core.api1_bola.dynamic_orchestrator import (
    OrchestratorError,
    TargetUnreachableError,
    ensure_target_reachable,
)


@patch("src.core.api1_bola.dynamic_orchestrator.requests.get")
def test_target_reachable_when_snapshot_returns_200(mock_get):
    mock_get.return_value = MagicMock(status_code=200)

    ensure_target_reachable("http://localhost:5000/")

    mock_get.assert_called_once()
    assert mock_get.call_args.args[0] == "http://localhost:5000/test/snapshot"


@patch("src.core.api1_bola.dynamic_orchestrator.requests.get")
def test_connection_error_raises_explicit_error(mock_get):
    mock_get.side_effect = requests.ConnectionError("refused")

    with pytest.raises(TargetUnreachableError) as exc_info:
        ensure_target_reachable("http://localhost:5000")

    message = str(exc_info.value)
    assert "/test/snapshot" in message
    assert "api-server" in message
    assert isinstance(exc_info.value, OrchestratorError)


@patch("src.core.api1_bola.dynamic_orchestrator.requests.get")
def test_non_200_means_no_cooperative_harness(mock_get):
    mock_get.return_value = MagicMock(status_code=404)

    with pytest.raises(TargetUnreachableError, match="HTTP 404"):
        ensure_target_reachable("http://localhost:5000")
