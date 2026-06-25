"""Smoke test — timeout rule module API is accessible."""
from src.core.api4_unrestricted_resource_consumption.rules.timeout import TimeoutRule

def test_rule_has_analyze_python():
    assert callable(getattr(TimeoutRule, "analyze_python", None))

def test_rule_has_analyze_javascript():
    assert callable(getattr(TimeoutRule, "analyze_javascript", None))

def test_rule_ids_defined():
    assert TimeoutRule.rule_id.startswith("RC-")
    assert TimeoutRule.cwe_id.startswith("CWE-")
    assert TimeoutRule.severity in ("HIGH", "MEDIUM", "LOW")
