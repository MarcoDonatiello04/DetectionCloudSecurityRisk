"""
BOPLA-S01 — static mass assignment rule (src/core/api3_bopla/mass_assignment.py).

The rule reports the whole request body bound to an entity without a list of accepted
fields. An allowlist suppresses it, a denylist does not.
"""

import json
import textwrap
from pathlib import Path

import pytest

from src.core.api2_broken_auth.discovery import Config, OutputConfig
from src.core.api3_bopla.mass_assignment import scan_mass_assignment
from src.core.api3_bopla.models import PropertyEvidence
from src.core.api3_bopla.orchestrator import BOPLAOrchestrator

TWINS = Path("data/test_targets/broken_object_property_level_authorization")


def _scan(tmp_path: Path, name: str, source: str, evidences=None):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    return scan_mass_assignment(str(tmp_path), evidences)


# ---------------------------------------------------------------------------
# Python: bindings that must be reported
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "source,entity",
    [
        (
            """
            @app.patch("/users/<id>")
            def update(id):
                user = User.query.get(id)
                for k, v in request.json.items():
                    setattr(user, k, v)
            """,
            "User",
        ),
        (
            """
            def create():
                data = request.get_json()
                order = Order(**data)
            """,
            "Order",
        ),
        (
            """
            class ProfileView(APIView):
                def put(self, request, pk):
                    Profile.objects.filter(pk=pk).update(**request.data)
            """,
            "Profile",
        ),
        (
            """
            def update(user_id):
                DB["users"][user_id].update(request.json)
            """,
            "User",
        ),
        (
            """
            async def update(request):
                account = await load()
                account.__dict__.update(await request.json())
            """,
            "Account",
        ),
    ],
)
def test_python_bindings_reported(tmp_path: Path, source: str, entity: str):
    findings = _scan(tmp_path, "app.py", source)
    assert len(findings) == 1, findings
    assert findings[0].entity == entity
    assert findings[0].rule_id == "BOPLA-S01" and not findings[0].verified


def test_route_is_attached_to_the_finding(tmp_path: Path):
    findings = _scan(
        tmp_path,
        "app.py",
        """
        @app.route("/users/<id>", methods=["PUT", "PATCH"])
        def update(id):
            user = User.query.get(id)
            for k, v in request.json.items():
                setattr(user, k, v)
        """,
    )
    assert findings[0].endpoint == "PATCH|PUT /users/<id>"


def test_denylist_is_reported_as_partial_guard(tmp_path: Path):
    findings = _scan(
        tmp_path,
        "app.py",
        """
        def update_user(user, body):
            for field, value in (body or {}).items():
                if field != "id":
                    setattr(user, field, value)
        """,
    )
    assert len(findings) == 1
    assert findings[0].guard and "denylist" in findings[0].guard


# ---------------------------------------------------------------------------
# Python: allowlists and ordinary code that must NOT be reported
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "source",
    [
        # allowlist around the setattr
        """
        def update(user, body):
            for field, value in body.items():
                if field in ALLOWED:
                    setattr(user, field, value)
        """,
        # allowlist as an early continue
        """
        def update(user, body):
            for field, value in body.items():
                if field not in ALLOWED:
                    continue
                setattr(user, field, value)
        """,
        # body filtered by an allowlist comprehension
        """
        def create():
            data = {k: v for k, v in request.json.items() if k in ALLOWED}
            return User(**data)
        """,
        # iteration over a literal allowlist, not over the body
        """
        def update(user):
            for field in ("name", "email"):
                setattr(user, field, request.json[field])
        """,
        # explicit per-field assignment
        """
        def update(user):
            user.name = request.json["name"]
        """,
        # a scratch dict updated with the body is not an entity
        """
        def log(body):
            entry = {"at": now()}
            entry.update(body)
        """,
        # generic parameter names are not treated as the request body
        """
        def build(data):
            return Report(**data)
        """,
    ],
)
def test_python_safe_code_not_reported(tmp_path: Path, source: str):
    assert _scan(tmp_path, "app.py", source) == []


def test_drf_serializer_with_all_fields(tmp_path: Path):
    findings = _scan(
        tmp_path,
        "serializers.py",
        """
        class OrderSerializer(serializers.ModelSerializer):
            class Meta:
                model = Order
                fields = "__all__"

        class SafeSerializer(serializers.ModelSerializer):
            class Meta:
                model = Order
                fields = "__all__"
                read_only_fields = ["status"]
        """,
    )
    assert [f.entity for f in findings] == ["Order"]


# ---------------------------------------------------------------------------
# JavaScript / TypeScript and Go
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line,entity",
    [
        ("Object.assign(user, req.body);", "user"),
        ("const order = await Order.create(req.body);", "Order"),
        ("await User.findByIdAndUpdate(id, req.body);", "User"),
        ("await this.userRepository.save({ ...req.body });", "user"),
        ("const p = new Product(req.body);", "Product"),
    ],
)
def test_js_bindings_reported(tmp_path: Path, line: str, entity: str):
    findings = _scan(
        tmp_path, "routes.js", f"router.put('/x/:id', async (req, res) => {{\n  {line}\n}});\n"
    )
    assert len(findings) == 1, findings
    assert findings[0].entity.lower() == entity.lower()
    assert findings[0].endpoint == "PUT /x/:id"


def test_js_alias_of_the_body(tmp_path: Path):
    findings = _scan(tmp_path, "a.ts", "const data = req.body;\nawait Invoice.update(data);\n")
    assert len(findings) == 1 and findings[0].entity == "Invoice"


@pytest.mark.parametrize(
    "line",
    [
        "await User.create({ name: req.body.name });",
        "await User.update(_.pick(req.body, ['name']));",
        "const { name, email } = req.body;",
        "res.json(req.body);",
    ],
)
def test_js_safe_code_not_reported(tmp_path: Path, line: str):
    assert _scan(tmp_path, "a.js", line + "\n") == []


def test_go_decode_then_save(tmp_path: Path):
    findings = _scan(
        tmp_path,
        "handler.go",
        """
        func UpdateUser(w http.ResponseWriter, r *http.Request) {
            var user models.User
            json.NewDecoder(r.Body).Decode(&user)
            db.Save(&user)
        }

        func Login(w http.ResponseWriter, r *http.Request) {
            var creds Credentials
            json.NewDecoder(r.Body).Decode(&creds)
            check(creds)
        }
        """,
    )
    assert [(f.entity, f.language) for f in findings] == [("User", "go")]


# ---------------------------------------------------------------------------
# Severity, twins and orchestrator
# ---------------------------------------------------------------------------


def test_protected_properties_raise_severity(tmp_path: Path):
    evidence = PropertyEvidence(
        object_name="User",
        property="role",
        found_in_ast=True,
        authorization_contexts=["@roles_required('admin')"],
        confidence=0.4,
    )
    source = """
    def update(user, body):
        for k, v in body.items():
            setattr(user, k, v)
    """
    assert _scan(tmp_path, "app.py", source)[0].severity == "MEDIUM"
    finding = _scan(tmp_path, "app.py", source, [evidence])[0]
    assert finding.severity == "HIGH" and finding.properties_at_risk == ["role"]


def _run_pipeline(app_dir: Path, tmp_path: Path) -> dict:
    orchestrator = BOPLAOrchestrator(Config(output=OutputConfig(path=str(tmp_path))))
    return orchestrator.run_assessment(
        repo_path=str(app_dir),
        openapi_spec=json.loads((TWINS / "openapi.json").read_text()),
        runtime_traffic=json.loads((TWINS / "client_traffic.json").read_text()),
    )


def test_twins_static_ground_truth(tmp_path: Path):
    vulnerable = _run_pipeline(TWINS / "vulnerable_app", tmp_path)
    secure = _run_pipeline(TWINS / "secure_app", tmp_path)

    s01 = [f for f in vulnerable["static_findings"] if f["rule_id"] == "BOPLA-S01"]
    assert len(s01) == 1
    assert s01[0]["entity"] == "User"
    assert s01[0]["properties_at_risk"] == ["role", "salary"]
    assert s01[0]["severity"] == "HIGH"
    assert not [f for f in secure["static_findings"] if f["rule_id"] == "BOPLA-S01"]

    # Static findings never touch the score, which only reflects the dynamic phase
    assert vulnerable["score"] == 100 and not vulnerable["dynamic_phase_executed"]
    assert "Segnalazioni Statiche" in (tmp_path / "bopla" / "bopla_report.md").read_text()
