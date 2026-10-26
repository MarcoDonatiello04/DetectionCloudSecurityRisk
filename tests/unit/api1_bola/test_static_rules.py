"""
Casi mirati per le regole statiche API1 (OA-001…OA-005).

Oltre ai casi positivi contengono varianti costruite per ingannare le euristiche
(commenti, docstring, condizioni che citano identità e ID senza legarli, pattern di
ownership meno comuni), così la precisione non poggia solo sulle fixture di ground truth.
"""

from src.core.api1_bola import detector


def _rules(content: str, filename: str = "app.py") -> set[tuple[str, str]]:
    report = detector.analyze_content(content, filename)
    return {(f.rule_id, f.http_methods[0]) for f in report.findings}


FLASK_HEADER = """
from flask import Flask, abort, jsonify, g
from flask_login import current_user, login_required
app = Flask(__name__)
"""


# --------------------------------------------------------------------- OA-001


def test_oa001_authenticated_lookup_by_id_only():
    code = (
        FLASK_HEADER
        + """
@app.get("/orders/<order_id>")
@login_required
def get_order(order_id):
    return jsonify(Order.query.get_or_404(order_id).to_dict())
"""
    )
    assert _rules(code) == {("OA-001", "GET")}


def test_oa001_comment_about_ownership_is_not_a_check():
    code = (
        FLASK_HEADER
        + """
@app.get("/orders/<order_id>")
@login_required
def get_order(order_id):
    '''Restituisce l'ordine se order.owner_id == current_user.id'''
    order = Order.query.get(order_id)  # TODO: if order.owner_id != current_user.id: abort(403)
    return jsonify(order.to_dict())
"""
    )
    assert _rules(code) == {("OA-001", "GET")}


def test_oa001_condition_mixing_identity_and_id_without_binding():
    code = (
        FLASK_HEADER
        + """
@app.get("/orders/<order_id>")
@login_required
def get_order(order_id):
    if not current_user.is_authenticated or order_id is None:
        abort(401)
    return jsonify(ORDERS[order_id])
"""
    )
    assert _rules(code) == {("OA-001", "GET")}


def test_oa001_one_finding_per_declared_method():
    code = (
        FLASK_HEADER
        + """
@app.route("/orders/<order_id>", methods=["GET", "DELETE"])
@login_required
def order(order_id):
    return jsonify(Order.query.get(order_id))
"""
    )
    report = detector.analyze_content(code)
    keys = sorted(f.correlation_key for f in report.findings)
    assert keys == ["api:DELETE:/orders/{id}", "api:GET:/orders/{id}"]


def test_fastapi_depends_user_without_scope_is_oa001():
    code = """
from fastapi import APIRouter, Depends
router = APIRouter(prefix="/api")

@router.get("/orders/{order_id}")
def read_order(order_id: str, user: User = Depends(get_current_user), db=Depends(get_db)):
    return db.get(Order, order_id)
"""
    assert _rules(code) == {("OA-001", "GET")}


# --------------------------------------------------------------------- secure variants


def test_scoped_query_is_secure():
    code = (
        FLASK_HEADER
        + """
@app.get("/orders/<order_id>")
@login_required
def get_order(order_id):
    order = Order.query.filter_by(id=order_id).filter(Order.owner_id == current_user.id).first()
    return jsonify(order.to_dict())
"""
    )
    assert _rules(code) == set()


def test_fastapi_scoped_by_injected_user_is_secure():
    code = """
from fastapi import APIRouter, Depends
router = APIRouter(prefix="/api")

@router.get("/orders/{order_id}")
def read_order(order_id: int, user: User = Depends(get_current_user), db=Depends(get_db)):
    return db.query(Order).filter(Order.id == order_id, Order.owner_id == user.id).first()
"""
    assert _rules(code) == set()


def test_identity_alias_comparison_is_secure():
    code = (
        FLASK_HEADER
        + """
@app.get("/notes/<note_id>")
@jwt_required()
def get_note(note_id):
    username = get_jwt_identity()
    note = NOTES.get(note_id)
    if note["author"] != username:
        abort(403)
    return jsonify(note)
"""
    )
    assert _rules(code) == set()


def test_ownership_helper_is_secure():
    code = (
        FLASK_HEADER
        + """
@app.put("/orders/<order_id>")
@login_required
def update_order(order_id):
    order = Order.query.get_or_404(order_id)
    check_ownership(current_user, order)
    order.update(request.json)
    return jsonify(order.to_dict())
"""
    )
    assert _rules(code) == set()


def test_loop_over_user_collection_is_secure():
    code = (
        FLASK_HEADER
        + """
@app.get("/orders/<order_id>")
@login_required
def get_order(order_id):
    order = Order.query.get_or_404(order_id)
    for owned in current_user.orders:
        if owned.id == order.id:
            return jsonify(order.to_dict())
    abort(403)
"""
    )
    assert _rules(code) == set()


def test_ownership_decorator_is_secure():
    code = (
        FLASK_HEADER
        + """
@app.get("/orders/<order_id>")
@login_required
@owner_required(Order)
def get_order(order_id):
    return jsonify(Order.query.get(order_id).to_dict())
"""
    )
    assert _rules(code) == set()


def test_privileged_role_check_is_out_of_scope():
    code = (
        FLASK_HEADER
        + """
@app.delete("/orders/<order_id>")
@login_required
def delete_order(order_id):
    if not current_user.is_admin:
        abort(403)
    db.session.delete(Order.query.get(order_id))
"""
    )
    assert _rules(code) == set()


def test_id_name_inside_string_literal_is_not_an_access():
    code = (
        FLASK_HEADER
        + """
@app.get("/orders/<order_id>/label")
@login_required
def order_label(order_id):
    return jsonify({"field": FIELD_LABELS.get("order_id"), "value": order_id})
"""
    )
    assert _rules(code) == set()


def test_route_without_object_identifier_is_ignored():
    code = (
        FLASK_HEADER
        + """
@app.get("/search/<term>")
def search(term):
    return jsonify(Order.query.filter(Order.name.contains(term)).all())
"""
    )
    assert _rules(code) == set()


# --------------------------------------------------------------------- OA-002


def test_oa002_identity_read_only_after_access():
    code = (
        FLASK_HEADER
        + """
@app.get("/invoices/<invoice_id>")
def get_invoice(invoice_id):
    invoice = INVOICES[invoice_id]
    audit.log(current_user)
    return jsonify(invoice)
"""
    )
    assert _rules(code) == {("OA-002", "GET")}


def test_before_request_auth_turns_oa002_into_oa001():
    code = (
        FLASK_HEADER
        + """
@app.before_request
def require_login():
    if not verify_token(request.headers.get("Authorization")):
        abort(401)

@app.get("/receipts/<int:receipt_id>")
def get_receipt(receipt_id):
    return jsonify(RECEIPTS.get(receipt_id))
"""
    )
    # autenticazione globale: niente OA-002 né OA-005, resta l'ownership mancante
    assert _rules(code) == {("OA-001", "GET")}


def test_express_global_auth_middleware():
    code = """
const app = require("express")();
app.use(authenticate);
app.get("/receipts/:receiptId(\\\\d+)", (req, res) => {
  res.json(receipts[Number(req.params.receiptId)]);
});
"""
    assert _rules(code, "server.js") == {("OA-001", "GET")}


# --------------------------------------------------------------------- OA-003


def test_oa003_takes_priority_over_oa001_on_same_endpoint():
    code = (
        FLASK_HEADER
        + """
@app.get("/docs/<doc_id>")
@login_required
def read_doc(doc_id):
    return jsonify(current_user.documents.filter_by(id=doc_id).first_or_404())

@app.patch("/docs/<doc_id>")
@login_required
def patch_doc(doc_id):
    doc = Document.query.get(doc_id)
    doc.title = request.json["title"]
"""
    )
    report = detector.analyze_content(code)
    assert [(f.rule_id, f.http_methods[0], f.related_rules) for f in report.findings] == [
        ("OA-003", "PATCH", ["OA-001"])
    ]


def test_oa003_admin_only_delete_is_not_inconsistent():
    code = (
        FLASK_HEADER
        + """
@app.get("/docs/<doc_id>")
@login_required
def read_doc(doc_id):
    return jsonify(current_user.documents.filter_by(id=doc_id).first_or_404())

@app.delete("/docs/<doc_id>")
@admin_required
def delete_doc(doc_id):
    db.session.delete(Document.query.get(doc_id))
"""
    )
    assert _rules(code) == set()


# --------------------------------------------------------------------- OA-004


def test_oa004_child_linked_through_parent_relationship_is_secure():
    code = (
        FLASK_HEADER
        + """
@app.get("/orders/<order_id>/items/<item_id>")
@login_required
def get_item(order_id, item_id):
    order = current_user.orders.filter_by(id=order_id).first_or_404()
    item = order.items.filter_by(id=item_id).first_or_404()
    return jsonify(item.to_dict())
"""
    )
    assert _rules(code) == set()


def test_oa004_child_linked_by_comparison_is_secure():
    code = (
        FLASK_HEADER
        + """
@app.get("/orders/<order_id>/items/<item_id>")
@login_required
def get_item(order_id, item_id):
    order = Order.query.get_or_404(order_id)
    if order.owner_id != current_user.id:
        abort(403)
    item = Item.query.get_or_404(item_id)
    if item.order_id != order.id:
        abort(404)
    return jsonify(item.to_dict())
"""
    )
    assert _rules(code) == set()


def test_oa004_reports_the_unbound_parameter():
    code = """
const router = require("express").Router();
router.delete("/orders/:orderId/items/:itemId", auth, async (req, res) => {
  const order = await Order.findOne({ _id: req.params.orderId, owner: req.user.id });
  if (!order) return res.sendStatus(404);
  await Item.deleteOne({ _id: req.params.itemId });
  res.sendStatus(204);
});
"""
    report = detector.analyze_content(code, "server.js")
    assert [(f.rule_id, f.id_parameter) for f in report.findings] == [("OA-004", "itemId")]


# --------------------------------------------------------------------- OA-005


def test_oa005_numeric_cast_in_body_counts_as_serial_id():
    code = """
const app = require("express")();
app.get("/tickets/:ticketId", (req, res) => {
  const id = parseInt(req.params.ticketId, 10);
  res.json(db.tickets.find((t) => t.id === id));
});
"""
    assert _rules(code, "server.js") == {("OA-002", "GET"), ("OA-005", "GET")}


def test_oa005_not_raised_with_auth_decorator():
    code = (
        FLASK_HEADER
        + """
@app.get("/receipts/<int:receipt_id>")
@login_required
def get_receipt(receipt_id):
    return jsonify(current_user.receipts.filter_by(id=receipt_id).first_or_404())
"""
    )
    assert _rules(code) == set()


# --------------------------------------------------------------------- funzioni di supporto

HELPER_APP = (
    FLASK_HEADER
    + """
def _load(resource_name, resource_id):
    username, _sub = extract_identity(request)
    if not username:
        return None, None, (jsonify({"error": "unauthorized"}), 401)
    bucket = DB.get(resource_name, {})
    if resource_id not in bucket:
        return None, None, (jsonify({"error": "not found"}), 404)
    return username, bucket[resource_id], None


@app.get("/projects/<id>")
def project(id):
    username, owner, error = _load("projects", id)
    if error:
        return error
    return jsonify({"id": id, "owner": owner})


@app.get("/invoices/<id>")
def invoice(id):
    username, owner, error = _load("invoices", id)
    if error:
        return error
    if username != owner and username not in ADMINS:
        abort(403)
    return jsonify({"id": id, "owner": owner})
"""
)


def test_same_file_helper_provides_identity_access_and_owner():
    report = detector.analyze_content(HELPER_APP)
    found = {(f.rule_id, f.endpoint) for f in report.findings}
    # l'identità e il lookup avvengono nell'helper: projects è autenticato ma senza
    # ownership (OA-001), invoices confronta l'owner restituito con l'identità
    assert found == {("OA-001", "/projects/<id>")}
    (finding,) = report.findings
    assert "_load(" in finding.evidence


def test_identity_extraction_call_with_object_id_is_a_plain_lookup():
    code = (
        FLASK_HEADER
        + """
@app.get("/users/<user_id>")
@login_required
def show_user(user_id):
    user = get_user(user_id)
    return jsonify(USERS[user_id])
"""
    )
    assert _rules(code) == {("OA-001", "GET")}


def test_express_helper_that_checks_ownership_is_secure():
    code = """
const router = require("express").Router();
async function loadOwnedOrder(req, orderId) {
  const order = await Order.findOne({ _id: orderId, owner: req.user.id });
  return order;
}
router.get("/orders/:orderId", auth, async (req, res) => {
  const order = await loadOwnedOrder(req, req.params.orderId);
  res.json(order);
});
"""
    assert _rules(code, "server.js") == set()
