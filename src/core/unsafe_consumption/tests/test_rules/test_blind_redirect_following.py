import ast
from pathlib import Path
from src.core.unsafe_consumption.rules import blind_redirect_following

def test_blind_redirect_following_vulnerable():
    code = """
MEDICAL_API = "https://medical-provider.com/store"
requests.post(MEDICAL_API, json={"patient": patient_data}, allow_redirects=True)
"""
    tree = ast.parse(code)
    findings = blind_redirect_following.analyze(tree, Path("app.py"), code)
    assert len(findings) == 1
    assert findings[0].rule_id == "UC-003"
    assert findings[0].severity == "HIGH"
    assert findings[0].evidence == 'requests.post(MEDICAL_API, json={"patient": patient_data}, allow_redirects=True)'

def test_blind_redirect_following_secure():
    code = """
MEDICAL_API = "https://medical-provider.com/store"
requests.post(MEDICAL_API, json={"patient": patient_data}, allow_redirects=False)
"""
    tree = ast.parse(code)
    findings = blind_redirect_following.analyze(tree, Path("app.py"), code)
    assert len(findings) == 0
