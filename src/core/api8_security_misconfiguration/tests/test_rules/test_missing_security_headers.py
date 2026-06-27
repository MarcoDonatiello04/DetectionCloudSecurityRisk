from pathlib import Path
from src.core.api8_security_misconfiguration.rules.missing_security_headers import check_file_for_signals

def test_security_headers_signals(tmp_path):
    # Test Talisman
    f = tmp_path / "app.py"
    f.write_text("Talisman(app)")
    assert check_file_for_signals(f) is True

    # Test Helmet
    f_js = tmp_path / "server.js"
    f_js.write_text("app.use(helmet())")
    assert check_file_for_signals(f_js) is True
