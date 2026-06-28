"""Smoke test — upload rule module API is accessible."""
from src.core.unrestricted_resource_consumption.rules.upload import UploadRule

def test_rule_has_analyze_python():
    assert callable(getattr(UploadRule, "analyze_python", None))

def test_rule_has_analyze_javascript():
    assert callable(getattr(UploadRule, "analyze_javascript", None))

def test_rule_ids_defined():
    assert UploadRule.rule_id.startswith("RC-")
    assert UploadRule.cwe_id.startswith("CWE-")
    assert UploadRule.severity in ("HIGH", "MEDIUM", "LOW")
