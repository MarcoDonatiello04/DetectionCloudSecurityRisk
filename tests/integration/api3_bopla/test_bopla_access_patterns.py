"""
Forms of property access recognized by the inference phase (B.7).

Besides `user.salary`, applications that work on dictionaries and object literals read and
write properties through literal string keys, `get`/`getattr`/`setattr` and destructuring:
inside an authorization context each of these forms marks the property as protected. A
string that is not a key (`print("salary")`) is never an access.
"""

import textwrap
from pathlib import Path

import pytest

from src.core.api3_bopla import access_patterns
from src.core.api3_bopla.property_inference import PropertyAuthorizationInferenceEngine as Engine

PROPS = {"User": {"salary", "name"}}


def _contexts(tmp_path: Path, name: str, source: str) -> dict[str, list[str]]:
    (tmp_path / name).write_text(textwrap.dedent(source), encoding="utf-8")
    result = Engine.analyze_ast_authorization_contexts(str(tmp_path), None, PROPS)
    return result.get("User", {})


# --- Python ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        'data["salary"] = 0',
        'value = user["salary"]',
        "value = user['salary']",
        'value = user.get("salary")',
        'value = user.get("salary", 0)',
        'value = getattr(user, "salary")',
        'setattr(user, "salary", 0)',
        'return {"salary": value}',
        'return jsonify({"id": 1, "salary": value})',
    ],
)
def test_python_dictionary_forms_inside_if(tmp_path: Path, statement: str):
    source = f"""
def get_user(user, current_user, data, value):
    if current_user.is_admin:
        {statement}
"""
    contexts = _contexts(tmp_path, "app.py", source)
    assert contexts.get("salary") == ["if(current_user.is_admin)"], contexts
    assert not contexts.get("name"), contexts


def test_python_subscript_after_guard(tmp_path: Path):
    source = """
def get_user(user, current_user):
    if not current_user.is_admin:
        abort(403)
    data = {}
    data["salary"] = user["salary"]
    return data
"""
    contexts = _contexts(tmp_path, "app.py", source)
    assert contexts.get("salary"), contexts
    assert contexts["salary"][0].startswith("guard(")


@pytest.mark.parametrize(
    "statement",
    [
        'print("salary")',
        'logger.info("salary")',
        'value = f"salary {value}"',
        "value = user[key]",
        'value = user.fetch("salary")',
        "value = getattr(user, key)",
        'value = hasattr(user, "salary")',
        "value = User(salary=value)",
    ],
)
def test_python_strings_that_are_not_accesses(tmp_path: Path, statement: str):
    source = f"""
def get_user(user, current_user, key, value):
    if current_user.is_admin:
        {statement}
"""
    assert not _contexts(tmp_path, "app.py", source).get("salary")


def test_python_dictionary_access_outside_any_context(tmp_path: Path):
    source = """
def get_user(user):
    data = {"salary": user.get("salary")}
    data["salary"] = getattr(user, "salary")
    return data
"""
    assert not _contexts(tmp_path, "app.py", source).get("salary")


# --- JavaScript -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        'data["salary"] = 0;',
        "const v = user['salary'];",
        "const v = user[`salary`];",
        "const { salary } = user;",
        "const { id, salary: s } = user;",
        "const { salary = 0, ...rest } = user;",
        "res.json({ salary: user.pay });",
        'res.json({ "salary": 1 });',
        "res.json({ id, salary });",
    ],
)
def test_javascript_forms_inside_if(tmp_path: Path, statement: str):
    source = f"""
function getUser(req, res, user, data) {{
  if (req.user.role === "admin") {{
    {statement}
  }}
}}
"""
    contexts = _contexts(tmp_path, "app.js", source)
    assert contexts.get("salary"), contexts
    assert contexts["salary"][0].startswith("if("), contexts


@pytest.mark.parametrize(
    "statement",
    [
        'console.log("salary");',
        "const v = user[key];",
        "const v = user[`salary${n}`];",
        "const v = salary;",
        'res.json({ [key]: "salary" });',
    ],
)
def test_javascript_strings_that_are_not_accesses(tmp_path: Path, statement: str):
    source = f"""
function getUser(req, res, user, key, n, salary) {{
  if (req.user.role === "admin") {{
    {statement}
  }}
}}
"""
    assert not _contexts(tmp_path, "app.js", source).get("salary")


def test_javascript_destructuring_outside_any_context(tmp_path: Path):
    source = """
function getUser(res, user) {
  const { salary } = user;
  res.json({ salary: user["salary"] });
}
"""
    assert not _contexts(tmp_path, "app.js", source).get("salary")


# --- Go -------------------------------------------------------------------------------


@pytest.mark.parametrize("statement", ['v := m["salary"]', 'm["salary"] = 0', "v := m[`salary`]"])
def test_go_map_index_inside_if(tmp_path: Path, statement: str):
    source = f"""
package main

func getUser(user User, m map[string]int) {{
\tif user.Role == "admin" {{
\t\t{statement}
\t\t_ = v
\t}}
}}
"""
    contexts = _contexts(tmp_path, "main.go", source)
    assert contexts.get("salary"), contexts


@pytest.mark.parametrize("statement", ['fmt.Println("salary")', "v := m[key]"])
def test_go_strings_that_are_not_accesses(tmp_path: Path, statement: str):
    source = f"""
package main

func getUser(user User, m map[string]int, key string) {{
\tif user.Role == "admin" {{
\t\t{statement}
\t}}
}}
"""
    assert not _contexts(tmp_path, "main.go", source).get("salary")


# --- Regex fallback (TypeScript without grammar) --------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "user.salary",
        'data["salary"] = 0',
        "data['salary'] = 0",
        'const v = user.get("salary")',
        "res.json({ salary: user.pay })",
        '{ "salary": 1 }',
        "salary: 10,",
        "const { salary } = user",
        "const { id, salary = 0, ...rest } = user",
        "const { salary: s } = user",
    ],
)
def test_regex_fallback_recognizes(line: str):
    assert access_patterns.line_mentions_property(line, "salary")


@pytest.mark.parametrize(
    "line",
    [
        'console.log("salary")',
        'logger.info("salary")',
        "const v = salary",
        "if (x) { return salary }",
        "const v = ok ? salary : 0",
        "salaryMax: 10,",
        "user.salaryMax",
    ],
)
def test_regex_fallback_ignores(line: str):
    assert not access_patterns.line_mentions_property(line, "salary")


def test_typescript_destructuring_inside_if(tmp_path: Path):
    source = """
function getUser(req: Request, res: Response, user: User) {
  if (req.user.role === "admin") {
    const { salary } = user;
    return res.json({ salary });
  }
}
"""
    contexts = _contexts(tmp_path, "app.ts", source)
    assert contexts.get("salary"), contexts
