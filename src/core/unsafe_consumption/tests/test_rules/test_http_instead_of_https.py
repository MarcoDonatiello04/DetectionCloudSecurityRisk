import ast
from pathlib import Path

from src.core.unsafe_consumption.rules import http_instead_of_https


def test_http_instead_of_https_vulnerable():
    code = """
response = requests.get("http://partner-api.com/businesses")
"""
    tree = ast.parse(code)
    findings = http_instead_of_https.analyze(tree, Path("app.py"), code)
    assert len(findings) == 1
    assert findings[0].rule_id == "UC-002"
    assert findings[0].severity == "HIGH"
    assert findings[0].evidence == 'requests.get("http://partner-api.com/businesses")'


def test_http_instead_of_https_secure():
    code = """
response = requests.get("https://partner-api.com/businesses")
localhost_call = requests.get("http://localhost:5000/api")
"""
    tree = ast.parse(code)
    findings = http_instead_of_https.analyze(tree, Path("app.py"), code)
    assert len(findings) == 0
