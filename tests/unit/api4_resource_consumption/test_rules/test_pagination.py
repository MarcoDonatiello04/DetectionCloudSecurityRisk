"""Smoke test — pagination rule module API is accessible."""

from src.core.api4_resource_consumption.rules.pagination import PaginationRule


def test_rule_has_analyze_python():
    assert callable(getattr(PaginationRule, "analyze_python", None))


def test_rule_has_analyze_javascript():
    assert callable(getattr(PaginationRule, "analyze_javascript", None))


def test_rule_ids_defined():
    assert PaginationRule.rule_id.startswith("RC-")
    assert PaginationRule.cwe_id.startswith("CWE-")
    assert PaginationRule.severity in ("HIGH", "MEDIUM", "LOW")
