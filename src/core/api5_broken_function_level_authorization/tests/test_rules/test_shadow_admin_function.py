from pathlib import Path
from tree_sitter import Parser, Language
import tree_sitter_python as tspython
from src.core.api5_broken_function_level_authorization.rules.shadow_admin_function import ShadowAdminFunctionRule

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"

def test_shadow_admin_function_vulnerable():
    vuln_file = FIXTURES_DIR / "vulnerable_app" / "app.py"
    content = vuln_file.read_bytes()
    
    parser = Parser(Language(tspython.language()))
    tree = parser.parse(content)
    
    findings = ShadowAdminFunctionRule.analyze_python(tree.root_node, str(vuln_file))
    
    # We expect 2 shadow findings:
    # 1. /debug/token-info (HIGH)
    # 2. /test/create-admin (HIGH)
    assert len(findings) == 2
    
    debug_finding = next(f for f in findings if "debug" in f.endpoint)
    assert debug_finding.rule_id == "BF-006"
    assert debug_finding.severity == "HIGH"
    
    test_finding = next(f for f in findings if "test" in f.endpoint)
    assert test_finding.rule_id == "BF-006"
    assert test_finding.severity == "HIGH"

def test_shadow_admin_function_secure():
    code = b"""
@app.get("/debug/token-info")
@login_required
@require_role("admin")
def debug_token_info():
    pass
"""
    parser = Parser(Language(tspython.language()))
    tree = parser.parse(code)
    
    findings = ShadowAdminFunctionRule.analyze_python(tree.root_node, "test.py")
    
    # Secure app has require_role on /debug/token-info, so it flags a LOW severity suspect debug endpoint warning
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "BF-006"
    assert f.severity == "LOW"
    assert "debug" in f.endpoint

