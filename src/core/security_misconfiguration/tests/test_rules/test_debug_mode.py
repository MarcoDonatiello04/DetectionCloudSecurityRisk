import ast
from pathlib import Path

from src.core.security_misconfiguration.rules.debug_mode import analyze


def test_debug_mode_flask():
    content = """
app.run(debug=True)
"""
    tree = ast.parse(content)
    findings = analyze(tree, Path("app.py"), content)
    assert len(findings) == 1
    assert findings[0].rule_id == "SC-002"


def test_debug_mode_django():
    content = """
DEBUG = True
"""
    tree = ast.parse(content)
    findings = analyze(tree, Path("settings.py"), content)
    assert len(findings) == 1
    assert findings[0].rule_id == "SC-002"
