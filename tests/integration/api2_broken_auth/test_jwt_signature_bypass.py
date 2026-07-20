"""Test della regola statica S01 — JWT Signature Verification Bypass (CWE-347)."""

from pathlib import Path

from src.core.api2_broken_auth.rules import jwt_signature_bypass as rule

PROJECT_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists())
FIXTURES = PROJECT_ROOT / "src" / "core" / "api2_broken_auth" / "fixtures"


def test_tp_on_repo_target_identity():
    """TP reale: identity.py di repo_target ricade sulla decodifica non verificata."""
    src = (PROJECT_ROOT / "data/test_targets" / "repo_target" / "identity.py").read_text()
    findings = rule.analyze(src, "identity.py")
    assert any(f.rule_id == "S01" for f in findings), "Atteso finding S01 su identity.py"
    assert any(f.function_name == "_decode_payload_only" for f in findings)


def test_tn_on_verified_decode_fixture():
    """TN: una decodifica verificata (solo jwt.decode con algorithms) non produce finding."""
    src = (FIXTURES / "secure_jwt_decode.py").read_text()
    findings = rule.analyze(src, "secure_jwt_decode.py")
    assert findings == [], f"Nessun finding atteso sulla fixture sicura, trovati: {findings}"


def test_tn_on_syntactically_invalid_source():
    """Robustezza: sorgente non parsabile non solleva eccezione."""
    assert rule.analyze("def broken(:\n", "bad.py") == []
