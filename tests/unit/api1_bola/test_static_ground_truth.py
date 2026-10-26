"""Ground truth del rilevatore statico API1: una regola OA attesa per endpoint, app sicura pulita."""

from tests.unit.api1_bola.validate_static_ground_truth import GROUND_TRUTH, run_validation


def test_static_ground_truth_validation():
    outcome = run_validation(verbose=False)
    details = outcome["details"]
    assert details["vulnerable_app"]["fn"] == [], "regole mancate sull'app vulnerabile"
    assert details["vulnerable_app"]["fp"] == [], "finding non attesi sull'app vulnerabile"
    assert outcome["secure_fp"] == 0, details["secure_app"]["fp"]
    assert outcome["tpr"] == 100.0
    assert outcome["results"]["TN"] == 1


def test_every_rule_has_ground_truth_in_both_languages():
    expected = GROUND_TRUTH["vulnerable_app"]
    for rule in ("OA-001", "OA-002", "OA-003", "OA-004", "OA-005"):
        files = {f for f, r, _m, _p in expected if r == rule}
        assert files == {"app.py", "server.js"}, f"{rule} senza caso Flask ed Express"
