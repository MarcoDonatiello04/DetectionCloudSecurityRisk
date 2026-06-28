import ast
from pathlib import Path
from src.core.api10_unsafe_consumption.rules import unvalidated_external_data

def test_unvalidated_external_data_vulnerable():
    code = """
response = requests.get("https://api.partner.com/businesses")
data = response.json()
db.execute(f"INSERT INTO businesses VALUES ('{data['name']}')")
"""
    tree = ast.parse(code)
    findings = unvalidated_external_data.analyze(tree, Path("app.py"), code)
    assert len(findings) == 1
    assert findings[0].rule_id == "UC-001"
    assert findings[0].severity == "HIGH"
    assert findings[0].evidence == "db.execute(f\"INSERT INTO businesses VALUES ('{data['name']}')\")"

def test_unvalidated_external_data_secure():
    code = """
response = requests.get("https://api.partner.com/businesses")
data = BusinessSchema(**response.json())
db.execute("INSERT INTO businesses VALUES (?)", (data.name,))
"""
    tree = ast.parse(code)
    findings = unvalidated_external_data.analyze(tree, Path("app.py"), code)
    assert len(findings) == 0
