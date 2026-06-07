from flask import request, jsonify
from database import MOCK_DATABASE
import logging

logger = logging.getLogger("flask.app")

def seed_database():
    """
    Endpoint di Automated Seeding.
    Riceve un payload JSON strutturato e sovrascrive o popola il database in memoria.
    """
    global MOCK_DATABASE
    try:
        payload = request.get_json()
        if not payload or not isinstance(payload, dict):
            return jsonify({"error": "Invalid payload format. Expected JSON dictionary."}), 400
            
        # Carica i dati del seeding nel database in memoria
        for resource_name, resource_data in payload.items():
            if resource_name not in MOCK_DATABASE:
                MOCK_DATABASE[resource_name] = {}
            for res_id, owner in resource_data.items():
                MOCK_DATABASE[resource_name][res_id] = owner
                
        logger.info(f"Database popolato con successo tramite Seeding. Risorse attive: {list(MOCK_DATABASE.keys())}")
        return jsonify({"status": "success", "message": "Database seeded successfully"}), 200
    except Exception as e:
        return jsonify({"error": f"Seeding failed: {str(e)}"}), 500
