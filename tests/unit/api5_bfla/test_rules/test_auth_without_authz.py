from pathlib import Path

import tree_sitter_python as tspython
from tree_sitter import Language, Parser

from src.core.api5_bfla.rules.auth_without_authz import (
    AuthWithoutAuthzRule,
)

PROJECT_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists())
FIXTURES_DIR = (
    PROJECT_ROOT
    / "data/test_targets"
    / "broken_function_level_authorization"
)


def test_auth_without_authz_vulnerable():
    vuln_file = FIXTURES_DIR / "vulnerable_app" / "app.py"
    content = vuln_file.read_bytes()

    parser = Parser(Language(tspython.language()))
    tree = parser.parse(content)

    findings = AuthWithoutAuthzRule.analyze_python(tree.root_node, str(vuln_file))

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "BF-002"
    assert f.endpoint == "PUT /users/<int:user_id>/role"
    assert f.severity == "HIGH"
    assert f.confidence == 0.80


def test_auth_without_authz_secure():
    secure_file = FIXTURES_DIR / "secure_app" / "app.py"
    content = secure_file.read_bytes()

    parser = Parser(Language(tspython.language()))
    tree = parser.parse(content)

    findings = AuthWithoutAuthzRule.analyze_python(tree.root_node, str(secure_file))

    bf002_findings = [f for f in findings if f.rule_id == "BF-002"]
    assert len(bf002_findings) == 0
