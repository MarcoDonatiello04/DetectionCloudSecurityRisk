from pathlib import Path
from tree_sitter import Parser, Language
import tree_sitter_python as tspython
from src.core.broken_function_level_authorization.rules.privileged_endpoint_no_role_check import PrivilegedEndpointNoRoleCheckRule

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"

def test_privileged_endpoint_no_role_check_vulnerable():
    vuln_file = FIXTURES_DIR / "vulnerable_app" / "app.py"
    content = vuln_file.read_bytes()
    
    parser = Parser(Language(tspython.language()))
    tree = parser.parse(content)
    
    findings = PrivilegedEndpointNoRoleCheckRule.analyze_python(tree.root_node, str(vuln_file))
    
    # We expect 4 privileged endpoints without role check:
    # 1. DELETE /admin/users/<int:user_id>
    # 2. PUT /users/<int:user_id>/role (since '/users/*/role' is a privileged path)
    # 3. ANY /admin/config (as it is decorated with @app.route without role validation)
    # 4. GET /debug/token-info (as '/debug/token-info' contains '/debug/')
    assert len(findings) == 4
    
    delete_finding = next(f for f in findings if f.endpoint == "DELETE /admin/users/<int:user_id>")
    assert delete_finding.rule_id == "BF-001"
    assert delete_finding.severity == "CRITICAL"
    assert delete_finding.confidence == 0.95
    
    role_finding = next(f for f in findings if f.endpoint == "PUT /users/<int:user_id>/role")
    assert role_finding.rule_id == "BF-001"
    assert role_finding.severity == "CRITICAL"
    assert role_finding.confidence == 0.75
    
    debug_finding = next(f for f in findings if "debug" in f.endpoint)
    assert debug_finding.rule_id == "BF-001"
    assert debug_finding.severity == "CRITICAL"
    assert debug_finding.confidence == 0.95

def test_privileged_endpoint_no_role_check_secure():
    secure_file = FIXTURES_DIR / "secure_app" / "app.py"
    content = secure_file.read_bytes()
    
    parser = Parser(Language(tspython.language()))
    tree = parser.parse(content)
    
    findings = PrivilegedEndpointNoRoleCheckRule.analyze_python(tree.root_node, str(secure_file))
    
    bf001_findings = [f for f in findings if f.rule_id == "BF-001"]
    assert len(bf001_findings) == 0
