from pathlib import Path

import pytest
import tree_sitter_javascript as tsjavascript
import tree_sitter_python as tspython
from tree_sitter import Language, Parser

from src.core.api5_bfla.detector import analyze, deduplicate_findings
from src.core.api5_bfla.models import RuleID
from src.core.api5_bfla.rules.privilege_escalation_payload import (
    PrivilegeEscalationPayloadRule,
)

PROJECT_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists())
FIXTURES_DIR = PROJECT_ROOT / "data/test_targets" / "broken_function_level_authorization"


def _py(source: str):
    tree = Parser(Language(tspython.language())).parse(source.encode())
    return PrivilegeEscalationPayloadRule.analyze_python(tree.root_node, "app.py")


def _js(source: str):
    tree = Parser(Language(tsjavascript.language())).parse(source.encode())
    return PrivilegeEscalationPayloadRule.analyze_javascript(tree.root_node, "app.js")


# ---------------------------------------------------------------------------
# Fixture ground truth
# ---------------------------------------------------------------------------


def test_bf007_fixture_vulnerable():
    vuln_file = FIXTURES_DIR / "vulnerable_app" / "app.py"
    tree = Parser(Language(tspython.language())).parse(vuln_file.read_bytes())
    findings = PrivilegeEscalationPayloadRule.analyze_python(tree.root_node, str(vuln_file))

    endpoints = {f.endpoint for f in findings}
    assert endpoints == {"POST /api/invites/new", "PUT /users/<int:user_id>/role"}
    for f in findings:
        assert f.rule_id == RuleID.BF_007.value == "BF-007"
        assert f.cwe_id == "CWE-269"
        assert f.severity == "CRITICAL"
        assert f.layer == "ast"
        assert "role" in f.missing_guard


def test_bf007_fixture_secure():
    secure_file = FIXTURES_DIR / "secure_app" / "app.py"
    tree = Parser(Language(tspython.language())).parse(secure_file.read_bytes())
    assert PrivilegeEscalationPayloadRule.analyze_python(tree.root_node, str(secure_file)) == []


def test_bf007_coexists_with_bf002_on_same_endpoint():
    """BF-007 non e esclusiva: non sostituisce ne viene sostituita da BF-002."""
    report = analyze(str(FIXTURES_DIR / "vulnerable_app"))
    on_role_endpoint = {
        f.rule_id for f in report.findings if f.endpoint == "PUT /users/<int:user_id>/role"
    }
    assert on_role_endpoint == {"BF-002", "BF-007"}


def test_dedup_keeps_non_exclusive_rule():
    vuln = FIXTURES_DIR / "vulnerable_app"
    report = analyze(str(vuln))
    again = deduplicate_findings(report.findings)
    assert sorted(f.rule_id for f in again) == sorted(f.rule_id for f in report.findings)


# ---------------------------------------------------------------------------
# Python — sink positivi
# ---------------------------------------------------------------------------

PY_VULNERABLE = {
    "direct_assignment": """
@app.post("/api/invites/new")
@login_required
def create_invite():
    invite = Invite()
    invite.role = request.json["role"]
""",
    "tainted_variable": """
@app.put("/users/<int:uid>")
def update(uid):
    data = request.get_json() or {}
    new_role = data.get("role", "user")
    user = User.query.get(uid)
    user.role = new_role
""",
    "setattr": """
@app.patch("/users/<int:uid>")
def patch(uid):
    payload = request.get_json()
    setattr(user, "is_admin", payload["is_admin"])
""",
    "update_kwarg": """
@app.put("/users/<int:uid>/perms")
def perms(uid):
    User.objects.filter(id=uid).update(permissions=request.data["permissions"])
""",
    "constructor_kwarg": """
@app.post("/api/invites/new")
def invite():
    body = request.json
    db.add(Invite(email=body["email"], role=body["role"]))
""",
    "update_dict": """
@app.put("/users/<int:uid>")
def upd(uid):
    users.update({"_id": uid}, {"role": request.json["role"]})
""",
    "sql_update": """
@app.post("/users/<int:uid>/promote")
def promote(uid):
    data = request.get_json()
    db.execute("UPDATE users SET role = %s WHERE id = %s", (data["role"], uid))
""",
    "fastapi_pydantic_body": """
@router.post("/api/invites")
def invite(body: InviteIn, db: Session = Depends(get_db)):
    invite = Invite(email=body.email)
    invite.role = body.role
""",
    "flask_route_methods": """
@app.route("/api/members", methods=["POST"])
def add_member():
    member = Member(group=request.form["group"])
""",
}


@pytest.mark.parametrize("case", sorted(PY_VULNERABLE))
def test_python_vulnerable(case):
    findings = _py(PY_VULNERABLE[case])
    assert len(findings) == 1, case
    assert findings[0].rule_id == "BF-007"


def test_python_endpoint_and_guard_metadata():
    [f] = _py(PY_VULNERABLE["direct_assignment"])
    assert f.endpoint == "POST /api/invites/new"
    assert f.found_guard == "login_required"
    assert f.line_number == 6
    assert "field: 'role'" in f.missing_guard

    [f] = _py(PY_VULNERABLE["flask_route_methods"])
    assert f.endpoint == "POST /api/members"


# ---------------------------------------------------------------------------
# Python — negativi (nessun finding atteso)
# ---------------------------------------------------------------------------

PY_SECURE = {
    "read_only_filter": """
@app.post("/api/users/search")
def search():
    payload = request.get_json()
    users = User.query.filter_by(role=payload["role"]).first()
    result = User.objects.get(role=payload["role"])
    return jsonify(users)
""",
    "comparison_only": """
@app.post("/api/check")
def check():
    if request.json["role"] == "admin":
        log.info("asked for admin")
""",
    "role_decorator": """
@app.put("/users/<int:uid>/role")
@login_required
@require_role("admin")
def set_role(uid):
    user.role = request.json["role"]
""",
    "inline_caller_check": """
@app.post("/api/invites/new")
@login_required
def invite():
    payload = request.get_json()
    requested = payload.get("role", "user")
    if requested != "user" and not current_user.is_admin:
        abort(403)
    Invite(email=payload["email"], role=requested)
""",
    "guard_call": """
@app.post("/api/invites/new")
def invite():
    check_permission(current_user, "grant_role")
    Invite(role=request.json["role"])
""",
    "literal_value": """
@app.post("/signup")
def signup():
    user = User(email=request.json["email"])
    user.role = "user"
""",
    "non_privileged_field": """
@app.put("/profile")
def profile():
    current.nickname = request.json["nickname"]
""",
    "not_a_route": """
def helper():
    user.role = request.json["role"]
""",
    "depends_is_not_body": """
@router.post("/api/invites")
def invite(current: User = Depends(get_current_user)):
    Invite(role=current.role)
""",
    "variable_reassigned": """
@app.put("/users/<int:uid>")
def upd(uid):
    role = request.json["role"]
    role = "user"
    user.role = role
""",
}


@pytest.mark.parametrize("case", sorted(PY_SECURE))
def test_python_secure(case):
    assert _py(PY_SECURE[case]) == [], case


# ---------------------------------------------------------------------------
# JavaScript / Express
# ---------------------------------------------------------------------------

JS_VULNERABLE = {
    "member_assignment": """
app.put('/users/:id/role', authenticate, async (req, res) => {
  const user = await User.findById(req.params.id);
  user.role = req.body.role;
});
""",
    "destructuring_shorthand": """
router.post('/api/invites/new', authenticated, async (req, res) => {
  const { email, role } = req.body;
  await Invite.create({ email, role });
});
""",
    "pair_value": """
app.patch('/users/:id', (req, res) => {
  const body = req.body;
  User.update({ isAdmin: body.isAdmin }, { where: { id: req.params.id } });
});
""",
    "sql_template": """
app.post('/users/:id/promote', (req, res) => {
  const r = req.body['role'];
  db.query(`UPDATE users SET role = ? WHERE id = ?`, [r, req.params.id]);
});
""",
}

JS_SECURE = {
    "role_middleware": """
app.put('/users/:id/role', authenticate, requireRole('admin'), (req, res) => {
  user.role = req.body.role;
});
""",
    "inline_caller_check": """
app.put('/users/:id/role', authenticate, (req, res) => {
  if (!req.user.isAdmin) { return res.status(403).end(); }
  user.role = req.body.role;
});
""",
    "read_only_find": """
app.post('/api/users/search', (req, res) => {
  const { role } = req.body;
  User.findAll({ where: { role } });
  User.findOne({ role: req.body.role });
});
""",
    "where_clause_only": """
app.post('/api/users/touch', (req, res) => {
  User.update({ seen: true }, { where: { role: req.body.role } });
});
""",
}


@pytest.mark.parametrize("case", sorted(JS_VULNERABLE))
def test_javascript_vulnerable(case):
    findings = _js(JS_VULNERABLE[case])
    assert len(findings) == 1, case
    assert findings[0].rule_id == "BF-007"


@pytest.mark.parametrize("case", sorted(JS_SECURE))
def test_javascript_secure(case):
    assert _js(JS_SECURE[case]) == [], case


def test_javascript_metadata():
    [f] = _js(JS_VULNERABLE["destructuring_shorthand"])
    assert f.endpoint == "POST /api/invites/new"
    assert f.found_guard == "authenticated"
