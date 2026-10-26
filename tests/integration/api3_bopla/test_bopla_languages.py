"""
BOPLA static phases on mixed-language repositories: the language is decided per file.

Regression for the single-language guess, where one JavaScript file in a Python repository
left the property inventory empty and a Go service hid the Python ones.
"""

import textwrap
from pathlib import Path

import pytest

from src.core.api3_bopla import discovery
from src.core.api3_bopla.discovery import PropertyDiscoveryEngine, collect_source_files
from src.core.api3_bopla.property_inference import PropertyAuthorizationInferenceEngine

PY_MODEL = """
class User:
    name: str
    salary: int
"""

PY_HANDLER = """
@roles_required('admin')
def get_salary(user):
    return user.salary
"""

GO_MODEL = """
package orders

type Order struct {
    ID     string `json:"id"`
    Status string `json:"status"`
}
"""

TS_MODEL = """
export interface Invoice {
  amount: number;
  paid: boolean;
}
"""


def _write(root: Path, files: dict[str, str]) -> str:
    for name, source in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(source), encoding="utf-8")
    return str(root)


def _protected(repo: str) -> set[tuple[str, str]]:
    inventory = PropertyDiscoveryEngine.discover_properties(repo)
    evidences = PropertyAuthorizationInferenceEngine.run_inference(repo, inventory)
    return {
        (e.object_name, e.property)
        for e in evidences
        if PropertyAuthorizationInferenceEngine.is_protected_property(e)
    }


def test_frontend_file_does_not_hide_python_backend(tmp_path: Path):
    repo = _write(
        tmp_path,
        {
            "models.py": PY_MODEL,
            "app.py": PY_HANDLER,
            "static/app.js": "console.log('frontend');",
        },
    )
    assert ("User", "salary") in _protected(repo)


def test_every_language_of_a_mixed_repository_is_analyzed(tmp_path: Path):
    repo = _write(
        tmp_path,
        {
            "services/users/models.py": PY_MODEL,
            "services/orders/order.go": GO_MODEL,
            "web/src/invoice.ts": TS_MODEL,
        },
    )
    inventory = PropertyDiscoveryEngine.discover_properties(repo).root
    assert {p.name for p in inventory["User"].properties} == {"name", "salary"}
    assert {p.name for p in inventory["Order"].properties} == {"id", "status"}
    assert {p.name for p in inventory["Invoice"].properties} == {"amount", "paid"}


def test_language_filter_still_restricts_the_scan(tmp_path: Path):
    repo = _write(tmp_path, {"models.py": PY_MODEL, "order.go": GO_MODEL})
    assert set(PropertyDiscoveryEngine.extract_ast_properties(repo, "go")) == {"Order"}
    assert set(PropertyDiscoveryEngine.extract_ast_properties(repo, "python")) == {"User"}


def test_unsupported_and_ignored_files_are_skipped(tmp_path: Path):
    repo = _write(
        tmp_path,
        {
            "models.py": PY_MODEL,
            "Main.java": "class Main {}",
            "node_modules/lib/index.js": "class Lib { x: 1 }",
        },
    )
    files = {(p.name, lang) for p, lang in collect_source_files(repo)}
    assert files == {("models.py", "python")}


def test_missing_grammar_falls_back_to_regex_without_installing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    repo = _write(tmp_path, {"web/invoice.ts": TS_MODEL})

    def fail_install(language: str):
        raise AssertionError(f"scan tried to install the grammar for {language}")

    discovery.get_installed_parser.cache_clear()
    monkeypatch.setattr(discovery.importlib.util, "find_spec", lambda name: None)
    monkeypatch.setattr(discovery, "get_parser_for_language", fail_install)
    try:
        inventory = PropertyDiscoveryEngine.extract_ast_properties(repo)
    finally:
        discovery.get_installed_parser.cache_clear()
    assert inventory == {"Invoice": {"amount", "paid"}}


@pytest.mark.parametrize(
    "raw,expected", [("Response", "Response"), ("Model", "Model"), ("UserDTO", "User")]
)
def test_suffix_only_class_names_are_kept(raw: str, expected: str):
    assert PropertyDiscoveryEngine.clean_object_name(raw) == expected
