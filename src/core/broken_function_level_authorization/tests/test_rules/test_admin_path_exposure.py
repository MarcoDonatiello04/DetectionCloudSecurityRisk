from pathlib import Path
from tree_sitter import Parser, Language
import tree_sitter_python as tspython
from src.core.broken_function_level_authorization.rules.admin_path_exposure import AdminPathExposureRule

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"

def test_admin_path_exposure_vulnerable():
    vuln_file = FIXTURES_DIR / "vulnerable_app" / "app.py"
    content = vuln_file.read_bytes()
    
    parser = Parser(Language(tspython.language()))
    tree = parser.parse(content)
    
    findings = AdminPathExposureRule.analyze_python(tree.root_node, str(vuln_file))
    
    # We expect 2 admin path exposure findings:
    # 1. Blueprint /admin without global protection (list_all_users)
    # 2. export_all function on ordinary path executing bulk retrieve
    assert len(findings) == 2
    
    bp_finding = next(f for f in findings if "Blueprint" in f.missing_guard)
    assert bp_finding.rule_id == "BF-004"
    assert bp_finding.severity == "HIGH"
    assert bp_finding.confidence == 0.90
    
    bulk_finding = next(f for f in findings if "Bulk database" in f.missing_guard)
    assert bulk_finding.rule_id == "BF-004"
    assert bulk_finding.severity == "HIGH"
    assert bulk_finding.confidence == 0.70

def test_admin_path_exposure_secure():
    secure_file = FIXTURES_DIR / "secure_app" / "app.py"
    content = secure_file.read_bytes()
    
    parser = Parser(Language(tspython.language()))
    tree = parser.parse(content)
    
    findings = AdminPathExposureRule.analyze_python(tree.root_node, str(secure_file))
    
    assert len(findings) == 0
