import ast
from pathlib import Path

from src.core.api8_security_misconfig.rules.missing_cache_control import analyze


def test_sensitive_route_missing_cache_control():
    # Scenario #2 OWASP API8: GET /dm/user_updates or /api/user/profile
    content = """
from flask import Flask, jsonify
app = Flask(__name__)

@app.route("/api/user/profile")
def get_user_profile():
    return jsonify({"email": "user@example.com", "balance": 100})

@app.route("/dm/user_updates.json")
def get_direct_messages():
    return jsonify({"messages": ["secret private message"]})
"""
    tree = ast.parse(content)
    findings = analyze(tree, Path("app.py"), content)
    assert len(findings) == 2
    for f in findings:
        assert f.rule_id == "SC-009"
        assert f.category == "missing_cache_control"
        assert f.severity == "HIGH"


def test_sensitive_route_with_cache_control_clean():
    content = """
from flask import Flask, make_response, jsonify
app = Flask(__name__)

@app.route("/api/user/profile")
def get_user_profile():
    resp = make_response(jsonify({"email": "user@example.com"}))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    return resp
"""
    tree = ast.parse(content)
    findings = analyze(tree, Path("app.py"), content)
    assert len(findings) == 0


def test_public_non_sensitive_route_clean():
    content = """
from flask import Flask, jsonify
app = Flask(__name__)

@app.route("/health")
def health_check():
    return jsonify({"status": "ok"})

@app.route("/static/catalog")
def get_catalog():
    return jsonify({"items": ["book", "pen"]})
"""
    tree = ast.parse(content)
    findings = analyze(tree, Path("app.py"), content)
    assert len(findings) == 0
