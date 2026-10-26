import ast
from pathlib import Path

from src.core.api8_security_misconfig.rules.unrestricted_http_methods import analyze


def test_mutating_route_without_methods_detected():
    content = """
from flask import Flask
app = Flask(__name__)

@app.route("/api/users/delete")
def delete_user():
    return {"status": "deleted"}
"""
    tree = ast.parse(content)
    findings = analyze(tree, Path("app.py"), content)
    assert len(findings) == 1
    assert findings[0].rule_id == "SC-008"
    assert findings[0].severity == "HIGH"
    assert "delete" in findings[0].evidence.lower()


def test_route_with_overly_permissive_methods():
    content = """
from flask import Flask
app = Flask(__name__)

@app.route("/api/resource", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def handle_resource():
    return {"status": "ok"}
"""
    tree = ast.parse(content)
    findings = analyze(tree, Path("app.py"), content)
    assert len(findings) == 1
    assert findings[0].rule_id == "SC-008"
    assert findings[0].severity == "MEDIUM"


def test_safe_restricted_routes_clean():
    content = """
from flask import Flask
app = Flask(__name__)

@app.route("/api/users", methods=["GET"])
def list_users():
    return {"users": []}

@app.route("/api/users/create", methods=["POST"])
def create_user():
    return {"id": 1}
"""
    tree = ast.parse(content)
    findings = analyze(tree, Path("app.py"), content)
    assert len(findings) == 0


def test_express_all_methods_detected():
    content = "app.all('/api/users/modify', handler)"
    findings = analyze(None, Path("server.js"), content)
    assert len(findings) == 1
    assert findings[0].rule_id == "SC-008"
