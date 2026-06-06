import pytest
from unittest.mock import MagicMock
from src.core.bola.assertion_engine import APIAssertionEngine

def test_evaluate_bola_assertion_same_structure_different_values():
    # Mocking responses with same structure but different lengths (different values)
    res_alice = MagicMock()
    res_alice.status_code = 200
    res_alice.text = '{"id": "123", "owner": "alice", "data": "Alice data"}'
    res_alice.json.return_value = {"id": "123", "owner": "alice", "data": "Alice data"}

    res_bob = MagicMock()
    res_bob.status_code = 200
    # Bob has a different length response due to longer values, but identical keys
    res_bob.text = '{"id": "123", "owner": "alice", "data": "Some very long data that changes response length completely!"}'
    res_bob.json.return_value = {"id": "123", "owner": "alice", "data": "Some very long data that changes response length completely!"}

    # Under old logic, since len(res_bob.text) != len(res_alice.text),
    # structural_similarity_assertion would be True, leading to non-vulnerable (SAFE) verdict.
    # Under new logic, it should detect the structural similarity and flag as vulnerable (BOLA).
    result = APIAssertionEngine.evaluate_bola_assertion(
        method="GET",
        res_alice=res_alice,
        res_bob=res_bob,
        requesting_user_role="user",
        resource_owner_role="user"
    )

    assert result["is_vulnerable"] is True
    assert result["verdict"] == "BOLA ORIZZONTALE"
    assert result["structural_similarity_assertion"] is False


def test_evaluate_bola_assertion_different_structure():
    res_alice = MagicMock()
    res_alice.status_code = 200
    res_alice.text = '{"id": "123", "owner": "alice", "data": "Alice data"}'
    res_alice.json.return_value = {"id": "123", "owner": "alice", "data": "Alice data"}

    res_bob = MagicMock()
    res_bob.status_code = 200
    # Bob gets a totally different structure (e.g. error message, but still returns 200 status)
    res_bob.text = '{"error": "not found", "code": 404}'
    res_bob.json.return_value = {"error": "not found", "code": 404}

    result = APIAssertionEngine.evaluate_bola_assertion(
        method="GET",
        res_alice=res_alice,
        res_bob=res_bob,
        requesting_user_role="user",
        resource_owner_role="user"
    )

    # Since structures are different (key overlap is small), it should be marked as safe from BOLA.
    assert result["is_vulnerable"] is False
    assert result["verdict"] == "SAFE"
    assert result["structural_similarity_assertion"] is True
