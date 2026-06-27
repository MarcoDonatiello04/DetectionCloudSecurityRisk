"""
Fixture API8 vulnerable_app.
Ogni sezione dimostra una specifica misconfiguration applicativa.
"""
import traceback
from flask import Flask, jsonify
from flask_cors import CORS
from fastapi.middleware.cors import CORSMiddleware

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
    return jsonify({
        "error": str(e),
        "traceback": traceback.format_exc(),
        "detail": repr(e)
    }), 500

# SC-004: nessun after_request con security headers
# (assenza rilevata a livello globale — non serve codice esplicito qui)
