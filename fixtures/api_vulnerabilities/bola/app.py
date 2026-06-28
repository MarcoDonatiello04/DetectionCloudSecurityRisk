"""
Applicazione Target Flask - Backend vulnerabile a BOLA (OWASP API1:2023).
Configurata per supportare il "Context-Aware Seeding" ed estesa per
testare in sicurezza i metodi distruttivi e di scrittura (PUT/DELETE) tramite
un meccanismo di "State Snapshot & Rollback" in memoria.
"""

import os
import copy
import logging
from flask import Flask, jsonify
from seed import seed_database
from resource import get_generic_resource
from database import MOCK_DATABASE

app = Flask(__name__)

# Configurazione del logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("flask.app")

# Configurazione del server Keycloak recuperata dalle variabili d'ambiente
KEYCLOAK_SERVER_URL = os.environ.get("KEYCLOAK_SERVER_URL", "http://keycloak:8080")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "myrealm")
JWKS_URL = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs"

# Variabile globale in-memory per memorizzare lo snapshot profondo dello stato del database
_DATABASE_SNAPSHOT = {}


def database_snapshot_endpoint():
    """
    Endpoint amministrativo per eseguire il backup (copia profonda) dello stato del database.
    Supporta GET e POST.
    """
    global _DATABASE_SNAPSHOT
    try:
        _DATABASE_SNAPSHOT = copy.deepcopy(MOCK_DATABASE)
        logger.info(f"Database Snapshot creato con successo. Risorse clonate: {list(_DATABASE_SNAPSHOT.keys())}")
        return jsonify({
            "status": "success",
            "message": "Database snapshot created successfully",
            "snapshot_keys": list(_DATABASE_SNAPSHOT.keys())
        }), 200
    except Exception as e:
        logger.error(f"Errore durante la creazione dello snapshot: {e}")
        return jsonify({"error": f"Snapshot failed: {str(e)}"}), 500


def database_rollback_endpoint():
    """
    Endpoint amministrativo per eseguire il ripristino istantaneo dello stato del database.
    Sovrascrive MOCK_DATABASE con lo stato salvato in _DATABASE_SNAPSHOT.
    """
    global _DATABASE_SNAPSHOT
    try:
        if not _DATABASE_SNAPSHOT:
            logger.warning("Tentativo di rollback senza uno snapshot valido memorizzato.")
            return jsonify({"error": "No snapshot available. Take a snapshot first."}), 400
            
        # Svuota e ripopola il dizionario condiviso mantenendo lo stesso riferimento all'oggetto
        MOCK_DATABASE.clear()
        for res_name, res_data in _DATABASE_SNAPSHOT.items():
            MOCK_DATABASE[res_name] = copy.deepcopy(res_data)
            
        logger.info("Database Rollback completato con successo. Stato ripristinato.")
        return jsonify({
            "status": "success",
            "message": "Database rolled back successfully"
        }), 200
    except Exception as e:
        logger.error(f"Errore durante l'esecuzione del rollback: {e}")
        return jsonify({"error": f"Rollback failed: {str(e)}"}), 500


# Registrazione delle rotte/view functions amministrative per i test
app.add_url_rule("/test/seed", view_func=seed_database, methods=["POST"])
app.add_url_rule("/test/snapshot", view_func=database_snapshot_endpoint, methods=["GET", "POST"])
app.add_url_rule("/test/rollback", view_func=database_rollback_endpoint, methods=["POST"])

# Rotta jolly dinamica abilitata per tutti i metodi HTTP (GET, POST, PUT, PATCH, DELETE)
app.add_url_rule(
    "/api/<resource_name>/<resource_id>", 
    view_func=get_generic_resource, 
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"]
)

if __name__ == "__main__":
    # Avvio del server Flask sulla porta 5000 in ascolto su tutte le interfacce
    app.run(host="0.0.0.0", port=5000, debug=True)
