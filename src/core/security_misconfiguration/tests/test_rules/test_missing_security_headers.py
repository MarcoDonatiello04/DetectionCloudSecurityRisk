from pathlib import Path
from src.core.security_misconfiguration.rules.missing_security_headers import analyze_global

def test_security_headers_signals(tmp_path):
    # Test directory with no security headers -> should produce finding
    findings = analyze_global(str(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule_id == "SC-004"
    assert findings[0].file_path == str(tmp_path)

    # Add Talisman to a file -> should be clean
    f = tmp_path / "app.py"
    f.write_text("Talisman(app)")
    findings = analyze_global(str(tmp_path))
    assert len(findings) == 0
