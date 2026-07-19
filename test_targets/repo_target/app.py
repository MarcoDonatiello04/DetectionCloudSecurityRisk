"""
Target cooperante di esempio: "Projects API".

Rappresenta una repository qualsiasi resa cooperante per i test D-AST BOLA.
Espone due risorse per oggetto, una vulnerabile e una protetta, cosi che una
scansione produca sia un verdetto VULNERABILE sia uno SAFE:

    /api/projects/{id}   VULNERABILE  nessun controllo di ownership (BOLA, API1:2023)
    /api/invoices/{id}   PROTETTA     verifica owner == richiedente (admin ammesso)

Lo stato (risorsa -> {id: owner}) e gestito dall'harness cooperante condiviso, che
fornisce anche gli endpoint /test/seed, /test/snapshot e /test/rollback su cui
l'orchestratore fa affidamento. Avvio: `python app.py` (porta 5000).
"""

from __future__ import annotations

import logging

from cooperative_harness import DB, register_harness
from flask import Flask, jsonify, request
from identity import extract_identity

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("repo_target.app")

# Username con privilegi elevati: puo accedere a risorse altrui (scenario verticale legittimo).
ADMIN_USERS = {"admin_user"}

app = Flask(__name__)
register_harness(app)


@app.get("/")
def health():
    return jsonify({"service": "repo_target Projects API", "status": "up"}), 200


def _load_resource(resource_name: str, resource_id: str):
    """Autentica il richiedente e recupera (username, owner) o una risposta di errore."""
    username, _sub = extract_identity(request)
    if not username:
        return None, None, (jsonify({"error": "Unauthorized: token mancante o invalido"}), 401)

    bucket = DB.get(resource_name, {})
    if resource_id not in bucket:
        return None, None, (jsonify({"error": "Risorsa non trovata"}), 404)

    return username, bucket[resource_id], None


@app.route("/api/projects/<id>", methods=["GET", "PUT", "PATCH", "DELETE"])
def projects(id: str):
    """VULNERABILE a BOLA: serve/modifica la risorsa senza confrontare owner e richiedente."""
    username, owner, error = _load_resource("projects", id)
    if error:
        return error

    if request.method == "DELETE":
        DB["projects"].pop(id, None)
        return jsonify({"status": "deleted", "id": id, "owner": owner, "by": username}), 200

    return jsonify(
        {
            "id": id,
            "owner": owner,
            "accessed_by": username,
            "data": f"Contenuto riservato del progetto {id}",
        }
    ), 200


@app.route("/api/invoices/<id>", methods=["GET", "PUT", "PATCH", "DELETE"])
def invoices(id: str):
    """PROTETTA: nega l'accesso se il richiedente non e il proprietario (admin ammesso)."""
    username, owner, error = _load_resource("invoices", id)
    if error:
        return error

    if username != owner and username not in ADMIN_USERS:
        logger.info("Accesso negato: %s non e proprietario della fattura %s", username, id)
        return jsonify({"error": "Forbidden: la risorsa appartiene a un altro utente"}), 403

    if request.method == "DELETE":
        DB["invoices"].pop(id, None)
        return jsonify({"status": "deleted", "id": id, "owner": owner, "by": username}), 200

    return jsonify(
        {
            "id": id,
            "owner": owner,
            "accessed_by": username,
            "data": f"Dati fatturazione riservati {id}",
        }
    ), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
