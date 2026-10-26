"""
B.8: an authorization context is tied to the object the access reads, not to every object
that has a property with the same name. B.10: classes that are not API data stay out of the
inventory.
"""

import textwrap
from pathlib import Path

import pytest

from src.core.api3_bopla.discovery import PropertyDiscoveryEngine
from src.core.api3_bopla.property_inference import PropertyAuthorizationInferenceEngine as Engine

PROPS = {"User": {"role", "name"}, "Project": {"role", "title"}}


def _contexts(tmp_path: Path, source: str, props=None, name="app.py") -> dict:
    (tmp_path / name).write_text(textwrap.dedent(source), encoding="utf-8")
    return Engine.analyze_ast_authorization_contexts(str(tmp_path), None, props or PROPS)


@pytest.mark.parametrize(
    "source",
    [
        # the variable names the object
        """
        @roles_required("admin")
        def promote(user):
            user.role = "admin"
        """,
        # a local assignment from the model class
        """
        @roles_required("admin")
        def promote(uid):
            account = User.query.get(uid)
            account.role = "admin"
        """,
        # a typed parameter
        """
        @roles_required("admin")
        def promote(account: User):
            account.role = "admin"
        """,
        # self inside the model class
        """
        class User:
            role: str

            @roles_required("admin")
            def promote(self):
                self.role = "admin"
        """,
    ],
)
def test_context_bound_to_the_resolved_object(tmp_path: Path, source: str):
    contexts = _contexts(tmp_path, source)
    assert contexts["User"].get("role")
    assert not contexts["Project"].get("role")


def test_unknown_receiver_keeps_every_candidate(tmp_path: Path):
    source = """
    @roles_required("admin")
    def payload(data):
        return {"role": data["role"]}
    """
    contexts = _contexts(tmp_path, source)
    assert contexts["User"].get("role") and contexts["Project"].get("role")


def test_go_method_receiver(tmp_path: Path):
    source = """
    package m

    func (u *User) Promote() {
        if !u.IsAdmin {
            return
        }
        u.Role = "admin"
    }
    """
    contexts = _contexts(tmp_path, source, {"User": {"Role"}, "Project": {"Role"}}, "m.go")
    assert contexts["User"].get("Role") and not contexts["Project"].get("Role")


@pytest.mark.parametrize(
    "name,bases,expected",
    [
        ("Meta", "", True),
        ("UserTestCase", "", True),
        ("Color", "(Enum)", True),
        ("NotFound", "(Exception)", True),
        ("Settings", "(BaseSettings)", True),
        ("User", "(BaseModel)", False),
        ("Order", "(models.Model)", False),
    ],
)
def test_non_model_classes(name: str, bases: str, expected: bool):
    assert PropertyDiscoveryEngine.is_non_model_class(name, bases) is expected


def test_inventory_skips_non_models_and_test_files(tmp_path: Path):
    (tmp_path / "models.py").write_text(
        textwrap.dedent(
            """
            class User(models.Model):
                email = models.EmailField()

                class Meta:
                    ordering = ["email"]

            class Color(Enum):
                RED = 1
            """
        )
    )
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "fixtures.py").write_text("class Fixture:\n    value = 1\n")
    (tmp_path / "test_views.py").write_text("class Helper:\n    value = 1\n")
    assert set(PropertyDiscoveryEngine.extract_ast_properties(str(tmp_path))) == {"User"}
