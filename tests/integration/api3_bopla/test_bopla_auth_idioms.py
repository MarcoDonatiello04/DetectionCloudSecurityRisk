"""
Framework authorization idioms in the inference phase (B.3, auth_idioms.py + catalog YAML).

A property read inside a function guarded by a framework authorization idiom (FastAPI
dependency, Django/DRF permission, NestJS guard, Express middleware, Go wrapper) is
protected. Authentication-only idioms and ordinary dependencies protect nothing.
"""

import ast
import textwrap
from pathlib import Path

import pytest

from src.core.api3_bopla import auth_idioms
from src.core.api3_bopla.property_inference import PropertyAuthorizationInferenceEngine as Engine

PROPS = {"User": {"salary", "name"}}


def _contexts(tmp_path: Path, name: str, source: str) -> dict[str, list[str]]:
    (tmp_path / name).write_text(textwrap.dedent(source), encoding="utf-8")
    result = Engine.analyze_ast_authorization_contexts(str(tmp_path), None, PROPS)
    return result.get("User", {})


@pytest.fixture
def missing_catalog(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(auth_idioms, "CATALOG_PATH", str(tmp_path / "missing.yaml"))


# ---------------------------------------------------------------------------
# Python: FastAPI, Django, DRF
# ---------------------------------------------------------------------------

PYTHON_PROTECTED = {
    "fastapi_depends": """
        @router.get("/users/{uid}")
        def get_user(uid: int, admin: User = Depends(require_admin)):
            return {"salary": user.salary}
        """,
    "fastapi_superuser": """
        @router.get("/users/{uid}")
        async def get_user(uid: int, current=Depends(deps.get_current_active_superuser)):
            return user.salary
        """,
    "fastapi_security_scopes": """
        @app.get("/users/{uid}")
        def get_user(me: Annotated[User, Security(get_current_user, scopes=["payroll"])]):
            return user.salary
        """,
    "fastapi_route_dependencies": """
        @router.get("/users/{uid}", dependencies=[Depends(RoleChecker(["admin"]))])
        def get_user(uid: int):
            return user.salary
        """,
    "django_user_passes_test": """
        @user_passes_test(lambda u: u.is_superuser)
        def payroll(request, uid):
            return JsonResponse({"salary": user.salary})
        """,
    "django_staff_member_required": """
        @staff_member_required
        def payroll(request, uid):
            return JsonResponse({"salary": user.salary})
        """,
    "django_permission_required": """
        @permission_required("hr.view_salary")
        def payroll(request, uid):
            return JsonResponse({"salary": user.salary})
        """,
    "django_method_decorator": """
        @method_decorator(staff_member_required, name="dispatch")
        class PayrollView(View):
            def get(self, request):
                return JsonResponse({"salary": user.salary})
        """,
    "django_permission_mixin": """
        class PayrollView(PermissionRequiredMixin, View):
            permission_required = "hr.view_salary"
            def get(self, request):
                return JsonResponse({"salary": user.salary})
        """,
    "drf_permission_classes_attribute": """
        class PayrollViewSet(viewsets.ModelViewSet):
            permission_classes = [permissions.IsAdminUser]
            def retrieve(self, request, pk=None):
                return Response({"salary": user.salary})
        """,
    "drf_permission_classes_decorator": """
        @api_view(["GET"])
        @permission_classes([IsAdminUser])
        def payroll(request):
            return Response({"salary": user.salary})
        """,
    "named_decorator": """
        @admin_only
        def payroll(request):
            return {"salary": user.salary}
        """,
}


@pytest.mark.parametrize("source", PYTHON_PROTECTED.values(), ids=PYTHON_PROTECTED.keys())
def test_python_authorization_idioms_protect(tmp_path: Path, source: str):
    contexts = _contexts(tmp_path, "views.py", source)
    assert contexts.get("salary"), contexts
    assert "name" not in contexts


PYTHON_NOT_PROTECTED = {
    "depends_get_db": """
        @router.get("/users/{uid}")
        def get_user(uid: int, db: Session = Depends(get_db)):
            return user.salary
        """,
    "depends_current_user": """
        @router.get("/users/{uid}", dependencies=[Depends(get_current_user)])
        def get_user(uid: int, me: User = Depends(get_current_user)):
            return user.salary
        """,
    "security_without_scopes": """
        @app.get("/me")
        def me(current: User = Security(get_current_user, scopes=[])):
            return user.salary
        """,
    "login_required": """
        @login_required
        def payroll(request):
            return JsonResponse({"salary": user.salary})
        """,
    "user_passes_test_active": """
        @user_passes_test(lambda u: u.is_active)
        def payroll(request):
            return JsonResponse({"salary": user.salary})
        """,
    "drf_is_authenticated": """
        class PayrollViewSet(viewsets.ModelViewSet):
            permission_classes = [IsAuthenticated]
            def retrieve(self, request, pk=None):
                return Response({"salary": user.salary})
        """,
    "drf_decorator_is_authenticated": """
        @permission_classes([IsAuthenticatedOrReadOnly])
        def payroll(request):
            return Response({"salary": user.salary})
        """,
    "login_mixin": """
        class PayrollView(LoginRequiredMixin, View):
            def get(self, request):
                return JsonResponse({"salary": user.salary})
        """,
    "property_setter_named_like_role": """
        class Account:
            @role.setter
            def role(self, value):
                self.salary = value
        """,
}


@pytest.mark.parametrize("source", PYTHON_NOT_PROTECTED.values(), ids=PYTHON_NOT_PROTECTED.keys())
def test_python_authentication_or_ordinary_idioms_do_not_protect(tmp_path: Path, source: str):
    assert _contexts(tmp_path, "views.py", source) == {}


def test_class_attribute_protects_only_its_class(tmp_path: Path):
    source = """
        class AdminView(APIView):
            permission_classes = [IsAdminUser]
            def get(self, request):
                return Response({"salary": user.salary})

        class PublicView(APIView):
            permission_classes = [AllowAny]
            def get(self, request):
                return Response({"name": user.name})
        """
    contexts = _contexts(tmp_path, "views.py", source)
    assert contexts.get("salary") == ["permission_classes = [IsAdminUser]"]
    assert "name" not in contexts


# ---------------------------------------------------------------------------
# JavaScript: NestJS decorators, Express middleware
# ---------------------------------------------------------------------------

JS_PROTECTED = {
    "nest_roles_method": """
        export class UsersController {
          @Roles('admin')
          @Get(':id')
          find(id) { return user.salary; }
        }
        """,
    "nest_guard_class_exported": """
        @Controller('users')
        @UseGuards(AuthGuard('jwt'), RolesGuard)
        export class UsersController {
          find(id) { return user.salary; }
        }
        """,
    "nest_guard_class": """
        @UseGuards(AdminGuard)
        class UsersController {
          find(id) { return user.salary; }
        }
        """,
    "express_inline_handler": """
        router.get('/users/:id', requireRole('admin'), (req, res) => {
          res.json({ salary: user.salary });
        });
        """,
    "express_named_function": """
        app.get('/users/:id', authenticate, requireAdmin, getUser);
        function getUser(req, res) { return res.json(user.salary); }
        """,
    "express_named_arrow": """
        router.put('/users/:id', checkPermissions('users:write'), controller.updateUser);
        const updateUser = async (req, res) => res.json(user.salary);
        """,
    "express_wrapper": """
        app.get('/users/:id', adminOnly(function (req, res) { res.json(user.salary); }));
        """,
}


@pytest.mark.parametrize("source", JS_PROTECTED.values(), ids=JS_PROTECTED.keys())
def test_javascript_authorization_idioms_protect(tmp_path: Path, source: str):
    contexts = _contexts(tmp_path, "routes.js", source)
    assert contexts.get("salary"), contexts


JS_NOT_PROTECTED = {
    "express_require_auth": """
        router.get('/users/:id', requireAuth, (req, res) => res.json(user.salary));
        """,
    "express_passport": """
        router.get('/users/:id', passport.authenticate('jwt'), getUser);
        function getUser(req, res) { return res.json(user.salary); }
        """,
    "nest_auth_guard_only": """
        @UseGuards(AuthGuard('jwt'))
        export class UsersController {
          find(id) { return user.salary; }
        }
        """,
    "not_a_route": """
        const value = settings.get('theme', roleDefault, () => user.salary);
        """,
    "handler_not_routed_with_middleware": """
        router.get('/users/:id', getUser);
        router.get('/admin', requireAdmin, adminPage);
        function getUser(req, res) { return res.json(user.salary); }
        """,
}


@pytest.mark.parametrize("source", JS_NOT_PROTECTED.values(), ids=JS_NOT_PROTECTED.keys())
def test_javascript_authentication_idioms_do_not_protect(tmp_path: Path, source: str):
    assert _contexts(tmp_path, "routes.js", source) == {}


# ---------------------------------------------------------------------------
# TypeScript: regex fallback (no tree-sitter grammar installed)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "@Roles(Role.Admin)",
        "@UseGuards(JwtAuthGuard, RolesGuard)",
        "router.get('/users/:id', requireRole('admin'), async (req, res) => {",
        "app.delete(`/users/:id`, auth.requireAdmin, deleteUser);",
    ],
)
def test_typescript_line_contexts(line: str):
    assert auth_idioms.line_auth_context(line) == line


@pytest.mark.parametrize(
    "line",
    [
        "@UseGuards(AuthGuard('jwt'))",
        "@Get(':id')",
        "router.get('/users/:id', requireAuth, (req, res) => res.json(user.role));",
        "const role = params.get('role');",
    ],
)
def test_typescript_line_without_authorization(line: str):
    assert auth_idioms.line_auth_context(line) is None


# ---------------------------------------------------------------------------
# Go: wrappers and middleware chains
# ---------------------------------------------------------------------------

GO_PROTECTED = {
    "wrapper_func_literal": """
        package main
        func routes() {
            r.Get("/users/{id}", RequireRole("admin", func(w http.ResponseWriter, r *http.Request) {
                x := user.salary
            }))
        }
        """,
    "wrapper_named_handler": """
        package main
        func routes() {
            mux.Handle("/users", middleware.RequireRole("admin", http.HandlerFunc(GetUser)))
        }
        func GetUser(w http.ResponseWriter, r *http.Request) { x := user.salary }
        """,
    "chi_with_chain": """
        package main
        func routes() { r.With(AdminOnly).Get("/users/{id}", h.GetUser) }
        func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) { x := user.salary }
        """,
    "gin_route_middleware": """
        package main
        func routes() { g.GET("/users/:id", middleware.RequirePermission("hr"), GetUser) }
        func GetUser(c *gin.Context) { x := user.salary }
        """,
}


@pytest.mark.parametrize("source", GO_PROTECTED.values(), ids=GO_PROTECTED.keys())
def test_go_authorization_idioms_protect(tmp_path: Path, source: str):
    contexts = _contexts(tmp_path, "routes.go", source)
    assert contexts.get("salary"), contexts


def test_go_authentication_middleware_does_not_protect(tmp_path: Path):
    source = """
        package main
        func routes() {
            r.HandleFunc("/posts", SetMiddlewareJSON(SetMiddlewareAuthentication(GetPost, db)))
        }
        func GetPost(w http.ResponseWriter, r *http.Request) { x := user.salary }
        """
    assert _contexts(tmp_path, "routes.go", source) == {}


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------


def test_missing_catalog_falls_back_to_role_decorators(tmp_path: Path, missing_catalog):
    assert auth_idioms.get_catalog() is auth_idioms.DEFAULT_CATALOG
    repo = tmp_path / "repo"
    repo.mkdir()
    legacy = _contexts(
        repo,
        "legacy.py",
        """
        @roles_required("admin")
        def payroll():
            return user.salary
        """,
    )
    assert legacy.get("salary") == ['@roles_required("admin")']
    # the new idioms are not recognized without the catalog
    (repo / "legacy.py").unlink()
    assert _contexts(repo, "views.py", PYTHON_PROTECTED["fastapi_depends"]) == {}


@pytest.mark.parametrize("content", ["just a string", "idioms: 3", "idioms:\n  - names: [x]\n"])
def test_malformed_catalog_falls_back(tmp_path: Path, content: str):
    path = tmp_path / "catalog.yaml"
    path.write_text(content, encoding="utf-8")
    assert auth_idioms.load_catalog(str(path)) is auth_idioms.DEFAULT_CATALOG


def test_disabled_idiom_is_ignored(tmp_path: Path, monkeypatch):
    path = tmp_path / "catalog.yaml"
    path.write_text(
        textwrap.dedent(
            """
            terms: {authorization: [admin]}
            idioms:
              - {kind: dependency, names: [Depends], enabled: false}
              - {kind: decorator, names: [roles_required]}
            """
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(auth_idioms, "CATALOG_PATH", str(path))
    repo = tmp_path / "repo"
    repo.mkdir()
    assert _contexts(repo, "views.py", PYTHON_PROTECTED["fastapi_depends"]) == {}


def test_project_catalog_is_loaded():
    catalog = auth_idioms.get_catalog()
    assert catalog.loaded
    assert "login_required" in catalog.authentication_names
    assert not auth_idioms.is_authorization_name("IsAuthenticated")
    assert auth_idioms.is_authorization_name("IsAdminUser")


# ---------------------------------------------------------------------------
# Static rule S02: functions reserved to a role
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "reserved"),
    [
        (PYTHON_PROTECTED["fastapi_depends"], True),
        (PYTHON_PROTECTED["drf_permission_classes_attribute"], True),
        (PYTHON_PROTECTED["django_user_passes_test"], True),
        (PYTHON_PROTECTED["django_method_decorator"], True),
        (PYTHON_NOT_PROTECTED["depends_get_db"], False),
        (PYTHON_NOT_PROTECTED["drf_is_authenticated"], False),
    ],
)
def test_reserved_python_function(source: str, reserved: bool):
    tree = ast.parse(textwrap.dedent(source))
    functions = [
        n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    assert functions
    assert all(auth_idioms.is_reserved_python_function(f, tree) is reserved for f in functions)
