"""
Modulo Risorse BOLA per il microservizio target.
Gestisce l'accesso jolly dinamico alle risorse e implementa il comportamento
vulnerabile BOLA (Broken Object Level Authorization) per tutti i metodi HTTP
(GET, POST, PUT, DELETE).

Non verifica mai la corrispondenza tra l'owner della risorsa (memorizzato nel DB)
e l'utente richiedente estratto dal token JWT, permettendo la visualizzazione,
la modifica o l'eliminazione indiscriminata delle risorse altrui.
"""

import logging
from flask import request, jsonify
from database import MOCK_DATABASE
from extract_username import extract_username

logger = logging.getLogger("flask.app")


def get_generic_resource(resource_name, resource_id):
    """
    Endpoint dinamico vulnerabile a BOLA (OWASP API1:2023).
    Accetta GET, POST, PUT, DELETE.
    """
    # 1. Verifica dell'autenticazione (estrazione dell'utente dal JWT)
    username = extract_username(request)
    if not username:
        logger.warning("Tentativo di accesso non autenticato rifiutato.")
        return jsonify({"error": "Unauthorized: Missing or invalid token"}), 401
        
    # 2. Controllo dell'esistenza della risorsa richiesta
    if resource_name not in MOCK_DATABASE or resource_id not in MOCK_DATABASE[resource_name]:
        logger.debug(f"Risorsa '{resource_name}' con ID '{resource_id}' non trovata.")
        return jsonify({"error": f"Resource '{resource_name}' with ID '{resource_id}' not found"}), 404
        
    owner = MOCK_DATABASE[resource_name][resource_id]
    
    # -------------------------------------------------------------------------
    # VULNERABILITÀ BOLA (API1:2023)
    # -------------------------------------------------------------------------
    # NON implementiamo alcun controllo semantico per verificare se l'utente
    # corrente ('username') sia effettivamente il proprietario ('owner') della risorsa.
    # -------------------------------------------------------------------------
    
    if request.method == "GET":
        logger.info(f"BOLA READ: Utente '{username}' visualizza la risorsa '{resource_id}' di '{owner}'")
        return jsonify({
            "resource_name": resource_name,
            "resource_id": resource_id,
            "owner": owner,
            "details": f"Dati sensibili riservati per la risorsa {resource_name} (ID {resource_id})",
            "accessed_by": username,
            "status": "success"
        }), 200

    elif request.method in ("POST", "PUT", "PATCH"):
        logger.info(f"BOLA WRITE: Utente '{username}' modifica/sovrascrive la risorsa '{resource_id}' di '{owner}'")
        
        # Simula l'aggiornamento dei dettagli della risorsa
        # Per scopi di test, possiamo sovrascrivere o aggiungere dettagli in un campo fittizio
        return jsonify({
            "resource_name": resource_name,
            "resource_id": resource_id,
            "owner": owner,
            "modified_by": username,
            "status": "success",
            "message": "Resource updated successfully"
        }), 200

    elif request.method == "DELETE":
        logger.info(f"BOLA DELETE: Utente '{username}' elimina la risorsa '{resource_id}' di '{owner}'")
        
        # Rimuove effettivamente la risorsa dal database condiviso.
        # Ciò provocherà un 404 nei tentativi successivi fino a quando non verrà effettuato il rollback.
        if resource_name in MOCK_DATABASE and resource_id in MOCK_DATABASE[resource_name]:
            del MOCK_DATABASE[resource_name][resource_id]
            
        return jsonify({
            "resource_name": resource_name,
            "resource_id": resource_id,
            "owner": owner,
            "deleted_by": username,
            "status": "success",
            "message": "Resource deleted successfully"
        }), 200
