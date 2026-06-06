import pytest
from unittest.mock import MagicMock
from src.core.bola.assertion_engine import APIAssertionEngine

def test_evaluate_bola_assertion_identical_response():
    # Scenario dove la risposta di Bob è identica a quella di Alice (Delta = 0)
    res_alice = MagicMock()
    res_alice.status_code = 200
    res_alice.text = '{"id": "123", "owner": "alice", "data": "Alice data"}'
    res_alice.json.return_value = {"id": "123", "owner": "alice", "data": "Alice data"}

    res_bob = MagicMock()
    res_bob.status_code = 200
    res_bob.text = '{"id": "123", "owner": "alice", "data": "Alice data"}'
    res_bob.json.return_value = {"id": "123", "owner": "alice", "data": "Alice data"}

    result = APIAssertionEngine.evaluate_bola_assertion(
        method="GET",
        res_alice=res_alice,
        res_bob=res_bob,
        requesting_user_role="user",
        resource_owner_role="user"
    )

    # Poiché Delta = 0, l'isolamento è violato -> Vulnerabile a BOLA Orizzontale
    assert result["is_vulnerable"] is True
    assert result["verdict"] == "BOLA ORIZZONTALE"
    assert result["structural_similarity_assertion"] is True


def test_evaluate_bola_assertion_different_response():
    res_alice = MagicMock()
    res_alice.status_code = 200
    res_alice.text = '{"id": "123", "owner": "alice", "data": "Alice data"}'
    res_alice.json.return_value = {"id": "123", "owner": "alice", "data": "Alice data"}

    res_bob = MagicMock()
    res_bob.status_code = 200
    # La risposta di Bob differisce in lunghezza (Delta != 0), indicando isolamento corretto
    res_bob.text = '{"error": "not found", "code": 404}'
    res_bob.json.return_value = {"error": "not found", "code": 404}

    result = APIAssertionEngine.evaluate_bola_assertion(
        method="GET",
        res_alice=res_alice,
        res_bob=res_bob,
        requesting_user_role="user",
        resource_owner_role="user"
    )

    # Poiché Delta != 0, l'isolamento dei dati ha retto -> SAFE
    assert result["is_vulnerable"] is False
    assert result["verdict"] == "SAFE"
    assert result["structural_similarity_assertion"] is False
