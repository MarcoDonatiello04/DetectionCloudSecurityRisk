"""
Test della privilege matrix BOLA: gerarchia letta da config/bola.yaml, regole espresse
per rango (non per nome del ruolo) e degradazione esplicita dei ruoli non censiti.
"""

import logging

import pytest

from src.core.api1_bola.bola_config import reset_bola_config
from src.core.api1_bola.role_matrix import AccessControlMatrix
from src.core.config import BolaConfig, load_bola_config


@pytest.fixture(autouse=True)
def _fresh_config():
    reset_bola_config(None)
    yield
    reset_bola_config(None)


@pytest.mark.parametrize(
    ("requesting", "owner", "expected"),
    [
        ("admin", "user", "LEGITTIMO"),
        ("admin", "admin", "LEGITTIMO"),
        ("manager", "user", "LEGITTIMO"),
        ("manager", "manager", "BOLA_ORIZZONTALE"),
        ("manager", "admin", "BOLA_VERTICALE"),
        ("user", "user", "BOLA_ORIZZONTALE"),
        ("user", "manager", "BOLA_VERTICALE"),
        ("user", "admin", "BOLA_VERTICALE"),
    ],
)
def test_default_hierarchy_verdicts(requesting, owner, expected):
    assert AccessControlMatrix.validate_access_legitimacy(requesting, owner) == expected


def test_hierarchy_is_read_from_project_config():
    assert AccessControlMatrix.HIERARCHY == {"admin": 3, "manager": 2, "user": 1}
    assert load_bola_config() == BolaConfig()


def test_unknown_role_is_degraded_with_explicit_warning(caplog):
    with caplog.at_level(logging.WARNING, logger="SecurityPlatform.BOLA.AccessControlMatrix"):
        verdict = AccessControlMatrix.validate_access_legitimacy("auditor", "user")

    assert verdict == "BOLA_ORIZZONTALE"  # degradato a 'user', pari rango del proprietario
    assert any(
        "'auditor'" in r.getMessage() and "degradato a 'user'" in r.getMessage()
        for r in caplog.records
    )


def test_custom_hierarchy_from_yaml(tmp_path, caplog):
    custom = tmp_path / "bola.yaml"
    custom.write_text("roles:\n  owner: 3\n  editor: 2\n  viewer: 1\n", encoding="utf-8")
    reset_bola_config(load_bola_config(str(custom)))

    assert AccessControlMatrix.HIERARCHY == {"owner": 3, "editor": 2, "viewer": 1}
    assert AccessControlMatrix.validate_access_legitimacy("owner", "viewer") == "LEGITTIMO"
    assert AccessControlMatrix.validate_access_legitimacy("editor", "viewer") == "LEGITTIMO"
    assert AccessControlMatrix.validate_access_legitimacy("viewer", "viewer") == "BOLA_ORIZZONTALE"
    assert AccessControlMatrix.validate_access_legitimacy("viewer", "editor") == "BOLA_VERTICALE"

    with caplog.at_level(logging.WARNING):
        assert AccessControlMatrix.validate_access_legitimacy("user", "editor") == "BOLA_VERTICALE"
    assert any("degradato a 'viewer'" in r.getMessage() for r in caplog.records)


def test_invalid_roles_section_falls_back_to_default(tmp_path):
    custom = tmp_path / "bola.yaml"
    custom.write_text("roles:\n  admin: alto\n", encoding="utf-8")
    assert load_bola_config(str(custom)).role_hierarchy == BolaConfig().role_hierarchy
