import json
from unittest.mock import MagicMock

from src.core.api1_bola.assertion_engine import APIAssertionEngine


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
        resource_owner_role="user",
    )

    # Stesso oggetto restituito all'attaccante: isolamento violato -> BOLA Orizzontale
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
    # La risposta di Bob è un oggetto diverso, indicando isolamento corretto
    res_bob.text = '{"error": "not found", "code": 404}'
    res_bob.json.return_value = {"error": "not found", "code": 404}

    result = APIAssertionEngine.evaluate_bola_assertion(
        method="GET",
        res_alice=res_alice,
        res_bob=res_bob,
        requesting_user_role="user",
        resource_owner_role="user",
    )

    # Oggetto diverso e nessun riferimento alla vittima -> SAFE
    assert result["is_vulnerable"] is False
    assert result["verdict"] == "SAFE"
    assert result["structural_similarity_assertion"] is False


def _response(status_code: int, body: str, json_body=None):
    """Costruisce una risposta HTTP finta: json() solleva ValueError se il body non è JSON."""
    res = MagicMock()
    res.status_code = status_code
    res.text = body
    if json_body is None:
        res.json.side_effect = ValueError("not json")
    else:
        res.json.return_value = json_body
    return res


def _evaluate(res_alice, res_bob, **kwargs):
    return APIAssertionEngine.evaluate_bola_assertion(
        method="GET",
        res_alice=res_alice,
        res_bob=res_bob,
        requesting_user_role="user",
        resource_owner_role="user",
        **kwargs,
    )


def test_same_object_with_volatile_fields_is_still_a_violation():
    # Caso della repo target: il body contiene "accessed_by": <username>, quindi Alice e Bob
    # ottengono lo stesso oggetto con lunghezze diverse. Il confronto in byte lo perdeva.
    alice = {"id": "123", "owner": "user_a", "accessed_by": "user_a", "data": "segreto"}
    bob = {"id": "123", "owner": "user_a", "accessed_by": "user_b_long", "data": "segreto"}
    res_alice = _response(200, json.dumps(alice), alice)
    res_bob = _response(200, json.dumps(bob), bob)
    assert len(res_alice.text) != len(res_bob.text)

    result = _evaluate(res_alice, res_bob)

    assert result["structural_similarity_assertion"] is True
    assert result["is_vulnerable"] is True
    assert result["verdict"] == "BOLA ORIZZONTALE"


def test_different_objects_with_same_length_are_not_a_violation():
    # Falso positivo del confronto in byte: body diversi ma stessa lunghezza
    alice = {"id": "123", "data": "AAAA"}
    bob = {"id": "456", "data": "BBBB"}
    res_alice = _response(200, json.dumps(alice), alice)
    res_bob = _response(200, json.dumps(bob), bob)
    assert len(res_alice.text) == len(res_bob.text)

    result = _evaluate(res_alice, res_bob)

    assert result["structural_similarity_assertion"] is False
    assert result["is_vulnerable"] is False


def test_attacker_body_citing_victim_id_is_a_violation_even_if_bodies_diverge():
    victim_id = "6f1c2b6e-1111-4a2a-9d3e-aaaaaaaaaaaa"
    alice = {"id": victim_id, "owner": "user_a", "data": "full", "secret": "x"}
    bob = {"id": victim_id, "owner": "user_a", "summary": "partial view"}
    result = _evaluate(
        _response(200, json.dumps(alice), alice),
        _response(200, json.dumps(bob), bob),
        resource_id=victim_id,
    )

    assert result["structural_similarity_assertion"] is False
    assert result["victim_reference_assertion"] is True
    assert result["is_vulnerable"] is True


def test_victim_reference_requires_success_status():
    victim_id = "6f1c2b6e-1111-4a2a-9d3e-aaaaaaaaaaaa"
    alice = {"id": victim_id}
    bob = {"error": "Risorsa non trovata", "id": victim_id}
    result = _evaluate(
        _response(200, json.dumps(alice), alice),
        _response(404, json.dumps(bob), bob),
        resource_id=victim_id,
    )

    assert result["victim_reference_assertion"] is False
    assert result["is_vulnerable"] is False


def test_non_json_bodies_fall_back_to_text_equality():
    same = _evaluate(_response(200, "<html>a</html>"), _response(200, "<html>a</html>"))
    diff = _evaluate(_response(200, "<html>ab</html>"), _response(200, "<html>ba</html>"))

    assert same["structural_similarity_assertion"] is True
    assert same["is_vulnerable"] is True
    assert diff["structural_similarity_assertion"] is False
    assert diff["is_vulnerable"] is False


def test_volatile_fields_are_read_from_config(tmp_path):
    from src.core.api1_bola.bola_config import reset_bola_config
    from src.core.config import load_bola_config

    custom = tmp_path / "bola.yaml"
    custom.write_text("structural_match:\n  volatile_fields: [etag]\n", encoding="utf-8")
    reset_bola_config(load_bola_config(str(custom)))
    try:
        alice = {"id": "1", "etag": "a", "accessed_by": "user_a"}
        bob = {"id": "1", "etag": "b", "accessed_by": "user_b"}
        result = _evaluate(
            _response(200, json.dumps(alice), alice), _response(200, json.dumps(bob), bob)
        )
        # 'etag' è volatile per questa config, 'accessed_by' non più: oggetti diversi
        assert result["structural_similarity_assertion"] is False
    finally:
        reset_bola_config(None)
