"""
Harness cooperante riutilizzabile per i test D-AST (BOLA / API1:2023).

Questo modulo e il "contratto" che una repository target deve esporre per
essere attaccabile dinamicamente dall'orchestratore BOLA del framework, esattamente
come gia avviene per `test_targets/bola`. Espone tre endpoint di controllo su cui
l'orchestratore fa affidamento (`src/core/api1_bola`, contratto in `config/bola_target.yaml`):

    POST      /test/seed       popola lo stato con risorse e proprietari
    GET|POST  /test/snapshot   fotografa lo stato "pulito" prima di uno scenario
    POST      /test/rollback   ripristina lo stato dopo ogni scenario

Il payload di seeding e definito da DatabaseSeeder.seed_target_application:

    { "<resource>": { "<uuid_utente>": "<owner_username>", ... }, ... }

La risposta riporta gli ID effettivamente creati (facoltativo ma raccomandato):

    { "status": "success", "ids": { "<resource>": { "<owner_username>": "<id>" } } }

L'orchestratore usa questi ID negli scenari di attacco; se `ids` manca ricade sul
vincolo storico "ID risorsa = UUID del proprietario".

Lo stato e un dizionario in memoria `DB[resource][resource_id] = owner_username`.
Una repo reale sostituisce questo store in-memory con il proprio (DB, fixture,
transazione con rollback), mantenendo la stessa semantica dei tre endpoint.
"""

from __future__ import annotations

import copy
import logging

from flask import Blueprint, jsonify, request

logger = logging.getLogger("repo_target.harness")

# Stato condiviso dell'applicazione: risorsa -> { resource_id: owner_username }.
# E lo store che gli endpoint di business leggono e che l'harness semina/ripristina.
DB: dict[str, dict[str, str]] = {}

# Snapshot profondo dello stato pulito, usato dal rollback tra gli scenari.
_SNAPSHOT: dict[str, dict[str, str]] = {}

harness_bp = Blueprint("cooperative_harness", __name__)


@harness_bp.post("/test/seed")
def seed():
    """Popola DB con il payload strutturato inviato dall'orchestratore."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Payload non valido: atteso un oggetto JSON."}), 400

    # ID effettivamente creati, per proprietario: { risorsa: { owner_username: resource_id } }.
    # Qui coincidono con le chiavi ricevute; una repo con DB reale li assegna da se
    # e li riporta qui, cosi l'orchestratore attacca gli oggetti che esistono davvero.
    created_ids: dict[str, dict[str, str]] = {}
    for resource_name, owners in payload.items():
        if not isinstance(owners, dict):
            continue
        DB.setdefault(resource_name, {})
        for resource_id, owner in owners.items():
            DB[resource_name][resource_id] = owner
            created_ids.setdefault(resource_name, {})[owner] = resource_id

    logger.info("Seeding completato. Risorse attive: %s", list(DB))
    return jsonify({"status": "success", "resources": list(DB), "ids": created_ids}), 200


@harness_bp.route("/test/snapshot", methods=["GET", "POST"])
def snapshot():
    """Salva una copia profonda dello stato corrente."""
    global _SNAPSHOT
    _SNAPSHOT = copy.deepcopy(DB)
    logger.info("Snapshot creato. Risorse clonate: %s", list(_SNAPSHOT))
    return jsonify({"status": "success", "snapshot_keys": list(_SNAPSHOT)}), 200


@harness_bp.post("/test/rollback")
def rollback():
    """Ripristina lo stato salvato dall'ultimo snapshot, mantenendo il riferimento a DB."""
    if not _SNAPSHOT:
        return jsonify({"error": "Nessuno snapshot disponibile. Eseguire prima /test/snapshot."}), 400

    DB.clear()
    for resource_name, owners in _SNAPSHOT.items():
        DB[resource_name] = copy.deepcopy(owners)

    logger.info("Rollback completato. Stato ripristinato.")
    return jsonify({"status": "success"}), 200


def register_harness(app) -> None:
    """Monta gli endpoint cooperanti su un'app Flask esistente."""
    app.register_blueprint(harness_bp)
