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
from urllib.parse import urlparse

import requests
from cooperative_harness import DB, register_harness
from flask import Flask, jsonify, request
from identity import extract_identity

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("repo_target.app")

# Username con privilegi elevati: puo accedere a risorse altrui (scenario verticale legittimo).
ADMIN_USERS = {"admin_user"}

# Host consentiti per l'import "sicuro" (allow-list): usato solo dalla variante protetta.
ALLOWED_IMPORT_HOSTS = {"projects.example.com", "cdn.example.com"}


def _is_allowed_host(url: str) -> bool:
    """Valida un URL contro l'allow-list di host consentiti (nega SSRF)."""
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return False
    return host in ALLOWED_IMPORT_HOSTS

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


@app.get("/api/projects")
def list_projects():
    """VULNERABILE (API4 / RC-001): ritorna la collezione con un 'limit' non limitato.

    Il parametro di paginazione arriva dall'utente e viene usato per affettare la
    lista senza alcun tetto massimo, permettendo di richiedere risorse illimitate.
    """
    username, _sub = extract_identity(request)
    if not username:
        return jsonify({"error": "Unauthorized: token mancante o invalido"}), 401

    limit = request.args.get("limit", default=1000, type=int)
    items = list(DB.get("projects", {}).items())
    page = items[:limit]  # nessun tetto massimo applicato al limit fornito dall'utente
    return jsonify({"count": len(page), "projects": [{"id": i, "owner": o} for i, o in page]}), 200


@app.post("/api/projects/<id>/import")
def import_project(id: str):
    """VULNERABILE a SSRF (API7 / SS-001) e a consumo non sicuro (API10 / UC-001).

    L'URL di import arriva dal body dell'utente e viene richiesto server-side senza
    allow-list, senza blocco degli IP interni/metadata e seguendo i redirect.
    """
    username, _sub = extract_identity(request)
    if not username:
        return jsonify({"error": "Unauthorized: token mancante o invalido"}), 401

    source_url = request.json.get("source_url")
    # SSRF (SS-001): nessuna validazione della destinazione, redirect seguiti (default).
    resp = requests.get(source_url, timeout=5)
    # Consumo non sicuro (UC-001): i dati esterni vengono usati senza validazione.
    data = resp.json()
    DB.setdefault("projects", {})[id] = data.get("owner", "unknown")
    return jsonify({"id": id, "imported_from": source_url, "owner": data.get("owner")}), 200


@app.post("/api/projects/<id>/import-safe")
def import_project_safe(id: str):
    """PROTETTA: import consentito solo verso host in allow-list, senza seguire redirect."""
    username, _sub = extract_identity(request)
    if not username:
        return jsonify({"error": "Unauthorized: token mancante o invalido"}), 401

    source_url = request.json.get("source_url")
    if _is_allowed_host(source_url):
        resp = requests.get(source_url, timeout=5, allow_redirects=False)
        return jsonify({"id": id, "imported_from": source_url, "bytes": len(resp.content)}), 200
    return jsonify({"error": "Forbidden: host di import non consentito"}), 403


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
