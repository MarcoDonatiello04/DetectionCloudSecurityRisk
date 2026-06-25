"""Smoke test — loop_bounds rule module API is accessible."""
from src.core.api4_unrestricted_resource_consumption.rules.loop_bounds import LoopBoundsRule

def test_rule_has_analyze_python():
    assert callable(getattr(LoopBoundsRule, "analyze_python", None))

def test_rule_has_analyze_javascript():
    assert callable(getattr(LoopBoundsRule, "analyze_javascript", None))

def test_rule_ids_defined():
    assert LoopBoundsRule.rule_id.startswith("RC-")
    assert LoopBoundsRule.cwe_id.startswith("CWE-")
    assert LoopBoundsRule.severity in ("HIGH", "MEDIUM", "LOW")
