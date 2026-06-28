from pathlib import Path
from src.core.broken_function_level_authorization.rules.missing_deny_by_default import MissingDenyByDefaultRule

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"

def test_missing_deny_by_default_vulnerable():
    vuln_settings = FIXTURES_DIR / "vulnerable_app" / "settings.py"
    findings = MissingDenyByDefaultRule.analyze_config(vuln_settings)
    
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "BF-005"
    assert f.severity == "MEDIUM"
    assert f.confidence == 0.95
    assert "DEFAULT_PERMISSION_CLASSES" in f.missing_guard

def test_missing_deny_by_default_secure():
    secure_settings = FIXTURES_DIR / "secure_app" / "settings.py"
    findings = MissingDenyByDefaultRule.analyze_config(secure_settings)
    
    assert len(findings) == 0


def analyze_rule(content: str, file_path: Path):
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        temp_file = Path(tmpdir) / file_path.name
        temp_file.write_text(content, encoding="utf-8")
        # Run analyze_config with the temp file paths updated
        findings = MissingDenyByDefaultRule.analyze_config(temp_file)
        # Update file_path to settings.py to match expectation
        for f in findings:
            f.file_path = str(file_path)
        return findings


def test_bf005_evidence_shows_dict_keys():
    """Evidence BF-005 deve mostrare le chiavi presenti nel dict."""
    content = '''
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
    ],
}
'''
    findings = analyze_rule(content, file_path=Path("settings.py"))
    assert len(findings) == 1
    evidence = findings[0].evidence
    assert "DEFAULT_AUTHENTICATION_CLASSES" in evidence
    assert "DEFAULT_PERMISSION_CLASSES" in evidence
    assert "AllowAny" in evidence


def test_bf005_evidence_not_generic():
    """Evidence non deve essere 'dictionary assigned at line X'."""
    content = '''
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': ['rest_framework.authentication.SessionAuthentication'],
}
'''
    findings = analyze_rule(content, file_path=Path("settings.py"))
    assert len(findings) == 1
    assert "dictionary assigned" not in findings[0].evidence

