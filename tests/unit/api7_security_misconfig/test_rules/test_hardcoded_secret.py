import ast
from pathlib import Path

from src.core.api7_security_misconfig.rules.hardcoded_secret import analyze


def test_hardcoded_secret():
    content = """
API_KEY = "sk-1234567890abcdef"
"""
    tree = ast.parse(content)
    findings = analyze(tree, Path("app.py"), content)
    assert len(findings) == 1
    assert findings[0].rule_id == "SC-005"
    assert findings[0].severity == "CRITICAL"
