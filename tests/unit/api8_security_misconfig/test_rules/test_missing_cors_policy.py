import tempfile
from pathlib import Path

from src.core.api8_security_misconfig.rules.missing_cors_policy import analyze_global


def test_missing_cors_policy_detected():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        app_file = tmp_path / "app.py"
        app_file.write_text("""
from flask import Flask
app = Flask(__name__)

@app.route("/api/data")
def get_data():
    return {"data": 123}
""")

        findings = analyze_global(str(tmp_path))
        assert len(findings) == 1
        assert findings[0].rule_id == "SC-006"
        assert findings[0].category == "missing_cors_policy"
        assert findings[0].severity == "MEDIUM"


def test_missing_cors_policy_not_triggered_when_configured():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        app_file = tmp_path / "app.py"
        app_file.write_text("""
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins=["https://example.com"])
""")

        findings = analyze_global(str(tmp_path))
        assert len(findings) == 0


def test_missing_cors_policy_ignored_for_non_api_code():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        script_file = tmp_path / "script.py"
        script_file.write_text("""
import math

def calculate(x):
    return math.sqrt(x)
""")

        findings = analyze_global(str(tmp_path))
        assert len(findings) == 0
