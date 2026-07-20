import ast
from pathlib import Path

from src.core.api7_security_misconfig.rules.verbose_error_handler import analyze


def test_verbose_errorhandler():
    content = """
@app.errorhandler(Exception)
def handle(e):
    return traceback.format_exc(), 500
"""
    tree = ast.parse(content)
    findings = analyze(tree, Path("app.py"), content)
    assert len(findings) == 1
    assert findings[0].rule_id == "SC-003"
