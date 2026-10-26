"""
Fixture API8 secure_app.
"""

import logging
import os

from flask import Flask, jsonify, make_response
from flask_cors import CORS
from flask_talisman import Talisman

logger = logging.getLogger(__name__)
app = Flask(__name__)

# SC-005 SECURE: secrets da environment
SECRET_KEY = os.environ.get("SECRET_KEY")
JWT_SECRET = os.environ.get("JWT_SECRET")

# SC-001 SECURE: CORS con allowlist
CORS(app, origins=["https://app.example.com", "https://admin.example.com"])

# SC-002 SECURE: debug controllato da env
if __name__ == "__main__":
    debug = os.environ.get("DEBUG", "false").lower() == "true"
    app.run(debug=debug)


# SC-003 SECURE: error handler generico
@app.errorhandler(Exception)
def handle_error(e):
    logger.error("Internal error", exc_info=True)
    return jsonify({"error": "Internal server error"}), 500


# SC-004 SECURE: security headers globali
Talisman(app, force_https=True, strict_transport_security=True)


# SC-008 SECURE: metodo esplicito su route mutante
@app.route("/api/user/delete", methods=["DELETE"])
def delete_user_secure():
    return jsonify({"status": "deleted"})


# SC-009 SECURE: cache-control no-store su endpoint privato
@app.route("/dm/user_updates.json", methods=["GET"])
def get_user_messages_secure():
    resp = make_response(jsonify({"messages": []}))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    return resp
