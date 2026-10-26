"""
Authorization guards with early exit in the inference phase (B.2).

`if not current_user.is_admin: abort(403)` protects the statements after it. Ownership
checks and positive early returns do not, and a condition never protects its else branch.
"""

import textwrap
from pathlib import Path

import pytest

from src.core.api3_bopla.property_inference import PropertyAuthorizationInferenceEngine as Engine

PROPS = {"User": {"salary", "name"}}


def _contexts(tmp_path: Path, name: str, source: str, props=None) -> dict[str, list[str]]:
    (tmp_path / name).write_text(textwrap.dedent(source), encoding="utf-8")
    result = Engine.analyze_ast_authorization_contexts(str(tmp_path), None, props or PROPS)
    return result.get("User", {})


@pytest.mark.parametrize(
    "guard",
    [
        "if not current_user.is_admin:\n        abort(403)",
        "if not current_user.is_admin:\n        flask.abort(403)",
        'if current_user.role != "admin":\n        raise PermissionDenied()',
        'if current_user.role != "admin":\n        return {"error": "forbidden"}, 403',
        "if not has_permission(current_user, 'payroll'):\n        return None",
    ],
)
def test_python_denying_guard_protects_what_follows(tmp_path: Path, guard: str):
    source = f"""
def get_salary(user, current_user):
    {guard}
    return user.salary
"""
    contexts = _contexts(tmp_path, "app.py", source)
    assert contexts.get("salary"), contexts
    assert contexts["salary"][0].startswith("guard(")


@pytest.mark.parametrize(
    "source",
    [
        # ownership check: the owner passes it and reads every field
        """
        def get_user(user, current_user):
            if current_user.id != user.id:
                abort(403)
            return user.salary
        """,
        # positive early return: what follows is the ordinary user's path
        """
        def get_user(user, current_user):
            if current_user.is_admin:
                return full_record(user)
            return user.salary
        """,
        # the guard does not exit
        """
        def get_user(user, current_user):
            if not current_user.is_admin:
                log("not admin")
            return user.salary
        """,
        # a condition never protects its else branch
        """
        def get_user(user, current_user):
            if current_user.is_admin:
                pass
            else:
                return user.salary
        """,
        # a guard ends with its function
        """
        def admin_only(current_user):
            if not current_user.is_admin:
                abort(403)
            return "ok"

        def public(user):
            return user.salary
        """,
    ],
)
def test_python_non_guards_do_not_protect(tmp_path: Path, source: str):
    assert "salary" not in _contexts(tmp_path, "app.py", source)


def test_guard_with_else_still_protects_what_follows(tmp_path: Path):
    source = """
    def get_salary(user, current_user):
        if not current_user.is_admin:
            abort(403)
        else:
            audit(current_user)
        return user.salary
    """
    assert "salary" in _contexts(tmp_path, "app.py", source)


def test_javascript_guard(tmp_path: Path):
    source = """
    router.get('/users/:id/salary', async (req, res) => {
      if (!req.user.isAdmin) {
        return res.status(403).end();
      }
      res.json({ salary: user.salary });
    });
    """
    assert _contexts(tmp_path, "routes.js", source).get("salary")


def test_go_guard(tmp_path: Path):
    source = """
    package users

    func Salary(w http.ResponseWriter, u *User) {
        if !u.IsAdmin {
            http.Error(w, "forbidden", http.StatusForbidden)
            return
        }
        fmt.Fprint(w, u.Salary)
    }
    """
    contexts = _contexts(tmp_path, "salary.go", source, {"User": {"Salary"}})
    assert contexts.get("Salary")


def test_regex_fallback_guard_and_function_boundary(tmp_path: Path):
    # TypeScript has no installed grammar here: the regex fallback handles it
    source = """
    export async function salary(req, res) {
      if (!req.user.isAdmin) { return res.status(403).end(); }
      res.json({ value: user.salary });
    }

    export async function profile(req, res) {
      res.json({ value: user.name });
    }
    """
    contexts = _contexts(tmp_path, "users.ts", source)
    assert contexts.get("salary") == ["guard(!req.user.isAdmin)"]
    assert "name" not in contexts


def test_is_denying_guard_rules():
    guard = Engine.is_denying_guard
    assert guard("not current_user.is_admin", "abort(403)", exits=True)
    assert guard("current_user.is_admin", "return error(403)", exits=True)  # denial body
    assert not guard("current_user.is_admin", "return full(user)", exits=True)
    assert not guard("current_user.id != user.id", "abort(403)", exits=True)
    assert not guard("not current_user.is_admin", "log()", exits=False)
    assert not guard("user is None", "abort(404)", exits=True)  # not an authorization check
    # negated condition whose branch passes the request on (ASGI middleware)
    assert not guard('scope["type"] != "http"', "return await self.app(scope, r, s)", True)
    assert not guard('scope["type"] != "http"', "await self.app(scope, r, s)\nreturn", True)
    assert guard("not has_permission(current_user)", "return None", exits=True)
    assert guard("!req.user.isAdmin", "{ return; }", exits=True)


# ---------------------------------------------------------------------------
# Integration fixes: refusing branch, authentication words, decorator arguments
# ---------------------------------------------------------------------------


def test_refusing_branch_of_a_guard_is_not_protected(tmp_path: Path):
    source = """
    def comment(user, current_user):
        if current_user.role != "mechanic":
            return {"message": "unauthorized"}, 401
        return {"salary": user.salary}
    """
    contexts = _contexts(tmp_path, "app.py", source, {"User": {"salary", "message"}})
    assert "message" not in contexts
    assert contexts["salary"][0].startswith("guard(")


@pytest.mark.parametrize(
    "condition",
    [
        "current_user",  # authentication: any logged-in user
        'credentials.get("token")',
        'scope["type"] == "http"',  # ASGI scope dictionary
        "identity is not None",
    ],
)
def test_authentication_conditions_do_not_protect(tmp_path: Path, condition: str):
    source = f"""
def view(user, current_user, credentials, scope, identity):
    if {condition}:
        return user.salary
"""
    assert "salary" not in _contexts(tmp_path, "app.py", source)


@pytest.mark.parametrize(
    "expression,expected",
    [
        ("has_permission(current_user, 'payroll')", True),
        ("user_role == 'admin'", True),
        ("user.user_role_id == 3", False),
        ('"payroll:read" in token.scopes', True),
    ],
)
def test_snake_case_matches_by_last_word(expression: str, expected: bool):
    assert Engine._is_auth_expression(expression) is expected


def test_decorator_predicate_is_not_protected(tmp_path: Path):
    source = """
    @user_passes_test(lambda u: u.is_superuser)
    def payroll(user):
        return user.salary
    """
    contexts = _contexts(tmp_path, "app.py", source, {"User": {"salary", "is_superuser"}})
    assert contexts.get("salary")
    assert "is_superuser" not in contexts
