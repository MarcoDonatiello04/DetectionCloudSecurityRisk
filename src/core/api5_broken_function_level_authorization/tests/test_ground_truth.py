from src.core.api5_broken_function_level_authorization.tests.validate_ground_truth import _run_validation

def test_ground_truth_validation():
    res = _run_validation(verbose=True)
    assert res["tpr"] == 100.0
    assert res["fpr"] == 0.0
    assert res["results"]["TP"] == 6
    assert res["results"]["TN"] == 1
    assert res["results"]["FP"] == 0
    assert res["results"]["FN"] == 0
