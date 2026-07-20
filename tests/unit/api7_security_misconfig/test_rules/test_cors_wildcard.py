import ast
from pathlib import Path

from src.core.api7_security_misconfig.rules.cors_wildcard import analyze


def test_cors_wildcard_python_flask():
    content = """
from flask_cors import CORS
CORS(app)
"""
    tree = ast.parse(content)
    findings = analyze(tree, Path("app.py"), content)
    assert len(findings) == 1
    assert findings[0].rule_id == "SC-001"
    assert findings[0].severity == "HIGH"


def test_cors_wildcard_fastapi_critical():
    content = """
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
)
"""
    tree = ast.parse(content)
    findings = analyze(tree, Path("app.py"), content)
    assert len(findings) == 1
    assert findings[0].rule_id == "SC-001"
    assert findings[0].severity == "CRITICAL"


def test_cors_wildcard_js():
    content = "app.use(cors())"
    findings = analyze(None, Path("server.js"), content)
    assert len(findings) == 1
    assert findings[0].rule_id == "SC-001"
    assert findings[0].evidence == "app.use(cors())"
