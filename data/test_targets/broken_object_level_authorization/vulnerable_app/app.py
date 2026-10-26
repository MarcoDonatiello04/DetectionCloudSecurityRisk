"""
Fixture VULNERABILE per il rilevatore statico API1 (BOLA) — servizio Flask.

Ogni handler è etichettato con la regola attesa (ground truth in
tests/unit/api1_bola/validate_static_ground_truth.py). Gli handler marcati
"controllo negativo" sono corretti e NON devono produrre finding.
"""

from flask import Blueprint, Flask, abort, jsonify
from flask_login import current_user, login_required

from models import Document, Order, Project, Receipt, Task, User, db
from security import admin_required

app = Flask(__name__)
api = Blueprint("api", __name__, url_prefix="/api")

INVOICES = {}


# OA-001: autenticato, ma l'ordine è recuperato solo per ID
@api.route("/orders/<order_id>", methods=["GET"])
@login_required
def get_order(order_id):
    order = Order.query.get_or_404(order_id)
    return jsonify(order.to_dict())


# OA-002: nessuna guardia e nessuna identità prima dell'accesso
@api.get("/invoices/<invoice_id>")
def get_invoice(invoice_id):
    invoice = INVOICES.get(invoice_id)
    if invoice is None:
        abort(404)
    return jsonify(invoice)


# Riferimento per OA-003: la lettura del documento è filtrata sull'owner...
@api.get("/documents/<doc_id>")
@login_required
def get_document(doc_id):
    doc = Document.query.filter_by(id=doc_id, owner_id=current_user.id).first_or_404()
    return jsonify(doc.to_dict())


# OA-003: ...la cancellazione dello stesso documento no
@api.delete("/documents/<doc_id>")
@login_required
def delete_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    db.session.delete(doc)
    db.session.commit()
    return "", 204


# OA-004: il progetto è validato contro l'owner, il task no
@api.get("/projects/<project_id>/tasks/<task_id>")
@login_required
def get_task(project_id, task_id):
    project = Project.query.get_or_404(project_id)
    if project.owner_id != current_user.id:
        abort(403)
    task = Task.query.get_or_404(task_id)
    return jsonify(task.to_dict())


# OA-005 (+ OA-002): ID intero sequenziale, nessuna guardia di autenticazione
@api.get("/receipts/<int:receipt_id>")
def get_receipt(receipt_id):
    receipt = Receipt.query.get(receipt_id)
    return jsonify(receipt.to_dict())


# Controllo negativo: l'ID di path è confrontato con l'identità prima del lookup
@api.get("/profiles/<user_id>")
@login_required
def get_profile(user_id):
    if user_id != str(current_user.id):
        abort(403)
    user = User.query.get_or_404(user_id)
    return jsonify(user.to_dict())


# Controllo negativo: endpoint amministrativo (dominio API5, non BOLA)
@api.delete("/admin/users/<int:user_id>")
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return "", 204


app.register_blueprint(api)
