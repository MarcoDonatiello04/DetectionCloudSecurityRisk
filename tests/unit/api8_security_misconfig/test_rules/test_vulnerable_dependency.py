import tempfile
from pathlib import Path

from src.core.api8_security_misconfig.rules.vulnerable_dependency import analyze


def test_vulnerable_dependency_cve_detected():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("""
flask==1.1.2
werkzeug==1.0.1
pyyaml==5.3.1
""")

        findings = analyze(str(tmp_path))
        assert len(findings) == 3
        rule_ids = {f.rule_id for f in findings}
        assert rule_ids == {"SC-007"}
        severities = {f.severity for f in findings}
        assert "HIGH" in severities
        evidences = " ".join(f.evidence for f in findings)
        assert "CVE-2023-30861" in evidences
        assert "CVE-2023-25577" in evidences
        assert "CVE-2020-14343" in evidences


def test_unpinned_dependency_detected():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("""
requests
urllib3
""")

        findings = analyze(str(tmp_path))
        assert len(findings) == 2
        for f in findings:
            assert f.rule_id == "SC-007"
            assert f.severity == "MEDIUM"
            assert "Unpinned dependency" in f.evidence


def test_secure_pinned_dependency_clean():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("""
flask==3.0.3
werkzeug==3.0.3
pyyaml==6.0.1
requests==2.32.3
""")

        findings = analyze(str(tmp_path))
        assert len(findings) == 0


def test_package_json_vulnerable_dependency():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pkg_file = tmp_path / "package.json"
        pkg_file.write_text("""
{
  "name": "my-app",
  "dependencies": {
    "express": "4.16.1",
    "lodash": "*"
  }
}
""")

        findings = analyze(str(tmp_path))
        assert len(findings) == 2
        severities = {f.severity for f in findings}
        assert "HIGH" in severities  # express
        assert "MEDIUM" in severities  # unpinned lodash
