"""
Fixture SICURA per il rilevatore statico API1 (BOLA) — servizio Flask.

Stessi endpoint della versione vulnerabile, ciascuno con l'oggetto legato al
soggetto autenticato. Nessun handler deve produrre finding (FPR = 0%).
"""

from flask import Blueprint, Flask, abort, jsonify
from flask_login import current_user, login_required

from models import Document, Order, Project, Task, User, db
from security import admin_required

app = Flask(__name__)
api = Blueprint("api", __name__, url_prefix="/api")

INVOICES = {}


# Lookup filtrato sull'owner nella query stessa
@api.route("/orders/<order_id>", methods=["GET"])
@login_required
def get_order(order_id):
    order = Order.query.filter_by(id=order_id, owner_id=current_user.id).first_or_404()
    return jsonify(order.to_dict())


# Confronto esplicito owner/identità dopo il lookup
@api.get("/invoices/<invoice_id>")
@login_required
def get_invoice(invoice_id):
    invoice = INVOICES.get(invoice_id)
    if invoice is None or invoice["owner"] != current_user.id:
        abort(404)
    return jsonify(invoice)


@api.get("/documents/<doc_id>")
@login_required
def get_document(doc_id):
    doc = Document.query.filter_by(id=doc_id, owner_id=current_user.id).first_or_404()
    return jsonify(doc.to_dict())


# Stesso controllo anche sulla cancellazione
@api.delete("/documents/<doc_id>")
@login_required
def delete_document(doc_id):
    doc = Document.query.filter_by(id=doc_id, owner_id=current_user.id).first_or_404()
    db.session.delete(doc)
    db.session.commit()
    return "", 204


# Il task è cercato dentro il progetto già validato
@api.get("/projects/<project_id>/tasks/<task_id>")
@login_required
def get_task(project_id, task_id):
    project = Project.query.get_or_404(project_id)
    if project.owner_id != current_user.id:
        abort(403)
    task = Task.query.filter_by(id=task_id, project_id=project.id).first_or_404()
    return jsonify(task.to_dict())


# ID intero, ma endpoint autenticato e lookup sulla collezione dell'utente
@api.get("/receipts/<int:receipt_id>")
@login_required
def get_receipt(receipt_id):
    receipt = current_user.receipts.filter_by(id=receipt_id).first_or_404()
    return jsonify(receipt.to_dict())


@api.get("/profiles/<user_id>")
@login_required
def get_profile(user_id):
    if user_id != str(current_user.id):
        abort(403)
    user = User.query.get_or_404(user_id)
    return jsonify(user.to_dict())


@api.delete("/admin/users/<int:user_id>")
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return "", 204


app.register_blueprint(api)
