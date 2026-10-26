"""
Fixture API8 vulnerable_app.
Ogni sezione dimostra una specifica misconfiguration applicativa.
"""

import traceback

from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)

# SC-005: secret hardcoded
SECRET_KEY = "super-secret-key-hardcoded-123"
JWT_SECRET = "jwt-signing-secret-never-change"
STRIPE_KEY = "sk_live_abc123def456"

# SC-001: CORS wildcard
CORS(app, origins="*")

# SC-002: debug mode nel codice
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")


# SC-003: error handler verboso
@app.errorhandler(Exception)
def handle_error(e):
    return jsonify({"error": str(e), "traceback": traceback.format_exc(), "detail": repr(e)}), 500


# SC-004: nessun after_request con security headers
# (assenza rilevata a livello globale — non serve codice esplicito qui)


# SC-008: route con operazione mutante senza restrizione methods=['POST'] (default a GET)
@app.route("/api/user/delete")
def delete_user_insecure():
    return jsonify({"status": "deleted"})


# SC-009: endpoint privato/sensibile senza Cache-Control: no-store (OWASP API8 Scenario #2)
@app.route("/dm/user_updates.json")
def get_user_messages():
    return jsonify({"messages": ["secret message"]})
