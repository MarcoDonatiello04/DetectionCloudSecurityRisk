"""Layer 1 API1: estrazione di handler, parametri di path e guardie (Flask, FastAPI, Express)."""

import pathlib
import tempfile

from src.core.api1_bola.layers.layer1_ast import (
    analyze_ast,
    extract_handlers_from_file,
    path_parameters,
)


def _handlers(content: str, filename: str):
    with tempfile.TemporaryDirectory() as tmpdir:
        path = pathlib.Path(tmpdir) / filename
        path.write_text(content, encoding="utf-8")
        return extract_handlers_from_file(path)


def test_empty_directory():
    with tempfile.TemporaryDirectory() as tmpdir:
        assert analyze_ast(tmpdir) == []


def test_missing_target_path():
    assert analyze_ast("/path/that/does/not/exist") == []


def test_path_parameters_across_frameworks():
    assert path_parameters("/a/<int:order_id>/b/<name>") == [("order_id", True), ("name", False)]
    assert path_parameters("/a/{order_id}/b/{item_id:int}") == [
        ("order_id", False),
        ("item_id", True),
    ]
    assert path_parameters("/a/:orderId(\\d+)/b/:itemId") == [("orderId", True), ("itemId", False)]


def test_flask_blueprint_prefix_methods_and_guards():
    code = """
from flask import Blueprint
bp = Blueprint("orders", __name__, url_prefix="/api/v1")

@bp.route("/orders/<int:order_id>", methods=["GET", "PUT"])
@login_required
def order(order_id):
    return Order.query.get(order_id)
"""
    (h,) = _handlers(code, "app.py")
    assert h.path == "/api/v1/orders/<int:order_id>"
    assert h.http_methods == ["GET", "PUT"]
    assert h.id_params == ["order_id"] and h.numeric_id_params == ["order_id"]
    assert h.has_authentication and h.guards == ["@login_required"]
    assert [a.id_param for a in h.object_accesses] == ["order_id"]


def test_flask_add_url_rule():
    code = """
def show_invoice(invoice_id):
    return INVOICES[invoice_id]

app.add_url_rule("/invoices/<invoice_id>", view_func=show_invoice, methods=["GET"])
"""
    (h,) = _handlers(code, "app.py")
    assert (h.path, h.http_methods, h.function_name) == (
        "/invoices/<invoice_id>",
        ["GET"],
        "show_invoice",
    )
    assert h.object_accesses and not h.has_authentication


def test_fastapi_dependency_marks_authentication_and_identity():
    code = """
router = APIRouter(prefix="/api")

@router.delete("/orders/{order_id}")
async def remove(order_id: int, user: User = Depends(get_current_user)):
    await repo.delete(order_id)
"""
    (h,) = _handlers(code, "api.py")
    assert h.path == "/api/orders/{order_id}" and h.http_methods == ["DELETE"]
    assert h.has_authentication and h.numeric_id_params == ["order_id"]


def test_non_id_path_parameter_is_not_an_object_reference():
    code = """
@app.get("/files/<path:filename>")
def download(filename):
    return send_file(STORAGE[filename])
"""
    (h,) = _handlers(code, "app.py")
    assert h.id_params == [] and h.object_accesses == []


def test_express_mount_prefix_middlewares_and_named_handler():
    code = """
const router = express.Router();
async function showOrder(request, response) {
  const { orderId: oid } = request.params;
  response.json(await Order.findById(oid));
}
router.get("/orders/:orderId", verifyJWT, showOrder);
app.use("/api", router);
"""
    (h,) = _handlers(code, "server.js")
    assert h.path == "/api/orders/:orderId" and h.function_name == "showOrder"
    assert h.guards == ["verifyJWT"] and h.has_authentication
    assert [a.id_param for a in h.object_accesses] == ["orderId"]


def test_express_non_route_calls_are_ignored():
    code = """
const value = cache.get("/orders/:orderId", fallback);
map.delete("/x/:id");
"""
    assert _handlers(code, "server.js") == []
