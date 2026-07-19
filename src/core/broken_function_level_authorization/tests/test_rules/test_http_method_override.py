from pathlib import Path

import tree_sitter_python as tspython
from tree_sitter import Language, Parser

from src.core.broken_function_level_authorization.rules.http_method_override import (
    HTTPMethodOverrideRule,
)

FIXTURES_DIR = (
    Path(__file__).resolve().parent.parent.parent.parent.parent.parent
    / "test_targets"
    / "broken_function_level_authorization"
)


def test_http_method_override_vulnerable():
    vuln_file = FIXTURES_DIR / "vulnerable_app" / "app.py"
    content = vuln_file.read_bytes()

    parser = Parser(Language(tspython.language()))
    tree = parser.parse(content)

    findings = HTTPMethodOverrideRule.analyze_python(tree.root_node, str(vuln_file))

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "BF-003"
    assert f.endpoint == "ANY /admin/config"
    assert f.severity == "HIGH"
    assert f.confidence == 0.90


def test_http_method_override_secure():
    secure_file = FIXTURES_DIR / "secure_app" / "app.py"
    content = secure_file.read_bytes()

    parser = Parser(Language(tspython.language()))
    tree = parser.parse(content)

    findings = HTTPMethodOverrideRule.analyze_python(tree.root_node, str(secure_file))

    bf003_findings = [f for f in findings if f.rule_id == "BF-003"]
    assert len(bf003_findings) == 0
