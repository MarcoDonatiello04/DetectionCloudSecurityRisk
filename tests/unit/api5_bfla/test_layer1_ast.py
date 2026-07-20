import pathlib
import tempfile

from src.core.api5_bfla.layers.layer1_ast import analyze_ast


def test_analyze_ast_empty():
    with tempfile.TemporaryDirectory() as tmpdir:
        findings = analyze_ast(tmpdir)
        assert findings == []


def test_analyze_ast_simple_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        file_path = pathlib.Path(tmpdir) / "app.py"
        file_path.write_text("def index(): pass")
        findings = analyze_ast(tmpdir)
        assert findings == []


def test_bf001_does_not_duplicate_bf002_finding():
    """
    Un endpoint con solo @login_required deve produrre BF-002,
    non BF-001 + BF-002 sullo stesso endpoint.
    """
    content = """
from flask import Flask
app = Flask(__name__)

@app.put("/users/<int:user_id>/role")
@login_required
def update_role(user_id):
    user.role = "admin"
"""
    from src.core.api5_bfla import detector

    report = detector.analyze_content(content)
    findings_on_endpoint = [f for f in report.findings if f.endpoint and "/users/" in f.endpoint]
    rule_ids = {f.rule_id for f in findings_on_endpoint}
    assert "BF-001" not in rule_ids, "BF-001 non deve coesistere con BF-002 sullo stesso endpoint"
    assert "BF-002" in rule_ids


def test_bf001_does_not_duplicate_bf006_finding():
    """
    Un endpoint /debug/ deve produrre BF-006, non BF-001 + BF-006.
    """
    content = """
from flask import Flask
app = Flask(__name__)

@app.get("/debug/token-info")
def debug_info():
    pass
"""
    from src.core.api5_bfla import detector

    report = detector.analyze_content(content)
    findings_on_endpoint = [f for f in report.findings if f.endpoint and "/debug/" in f.endpoint]
    rule_ids = {f.rule_id for f in findings_on_endpoint}
    assert "BF-001" not in rule_ids, "BF-001 non deve coesistere con BF-006 sullo stesso endpoint"
    assert "BF-006" in rule_ids
