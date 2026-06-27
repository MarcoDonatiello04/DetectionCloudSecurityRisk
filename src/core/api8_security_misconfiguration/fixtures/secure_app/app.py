"""
Fixture API8 secure_app.
"""
import os
import logging
from flask import Flask, jsonify
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
    logger.error(f"Internal error", exc_info=True)
    return jsonify({"error": "Internal server error"}), 500

# SC-004 SECURE: security headers globali
Talisman(app, force_https=True, strict_transport_security=True)
