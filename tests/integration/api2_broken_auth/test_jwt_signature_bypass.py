"""Test della regola statica S01 — JWT Signature Verification Bypass (CWE-347)."""

import textwrap
from pathlib import Path

import pytest

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


def _analyze(body: str) -> list:
    return rule.analyze(textwrap.dedent(body), "sample.py")


def test_tn_manual_read_after_verified_decode():
    """TN: la lettura manuale avviene solo dopo una verifica firma che propaga l'errore."""
    src = """
    import base64, json, jwt

    def read_header(token, key):
        claims = jwt.decode(token, key, algorithms=["RS256"])
        header = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
        return claims, header
    """
    assert _analyze(src) == []


@pytest.mark.parametrize(
    "src",
    [
        pytest.param(
            """
            import base64, json, jwt

            def decode(token, key):
                try:
                    return jwt.decode(token, key, algorithms=["RS256"])
                except Exception:
                    return json.loads(base64.urlsafe_b64decode(token.split(".")[1]))
            """,
            id="fallback-in-except",
        ),
        pytest.param(
            """
            import base64, json, jwt

            def decode(token, key):
                claims = None
                try:
                    claims = jwt.decode(token, key, algorithms=["RS256"])
                except Exception:
                    pass
                if claims is None:
                    claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1]))
                return claims
            """,
            id="verification-error-swallowed",
        ),
        pytest.param(
            """
            import base64, json, jwt

            def decode(token):
                jwt.decode(token, options={"verify_signature": False})
                return json.loads(base64.urlsafe_b64decode(token.split(".")[1]))
            """,
            id="verification-disabled",
        ),
        pytest.param(
            """
            import base64, json, jwt

            def decode(token, key):
                claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1]))
                jwt.decode(token, key, algorithms=["RS256"])
                return claims
            """,
            id="verification-after-manual-read",
        ),
    ],
)
def test_tp_manual_read_not_guarded_by_verification(src):
    """TP: una chiamata di verifica presente non basta se non protegge la lettura manuale."""
    findings = _analyze(src)
    assert [f.function_name for f in findings] == ["decode"]


def test_nested_function_reported_only_once():
    """Il pattern in una funzione interna segnala solo quella, non la funzione esterna."""
    src = """
    import base64, json

    def outer(token):
        def inner(tok):
            return json.loads(base64.urlsafe_b64decode(tok.split(".")[1]))

        return inner(token)
    """
    assert [f.function_name for f in _analyze(src)] == ["inner"]


def test_nested_verification_does_not_guard_outer_function():
    """Una verifica dentro una funzione annidata non protegge la lettura manuale esterna."""
    src = """
    import base64, json, jwt

    def outer(token, key):
        def verify():
            return jwt.decode(token, key, algorithms=["RS256"])

        return json.loads(base64.urlsafe_b64decode(token.split(".")[1]))
    """
    assert [f.function_name for f in _analyze(src)] == ["outer"]
