"""Smoke test — graphql_batching rule module API is accessible."""

from src.core.unrestricted_resource_consumption.rules.graphql_batching import GraphQLBatchingRule


def test_rule_has_analyze_python():
    assert callable(getattr(GraphQLBatchingRule, "analyze_python", None))


def test_rule_has_analyze_javascript():
    assert callable(getattr(GraphQLBatchingRule, "analyze_javascript", None))


def test_rule_ids_defined():
    assert GraphQLBatchingRule.rule_id.startswith("RC-")
    assert GraphQLBatchingRule.cwe_id.startswith("CWE-")
    assert GraphQLBatchingRule.severity in ("HIGH", "MEDIUM", "LOW")
