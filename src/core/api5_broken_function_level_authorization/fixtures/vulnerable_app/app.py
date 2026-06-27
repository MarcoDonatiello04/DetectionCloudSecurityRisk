"""
Fixture API5 vulnerable_app.
Ogni endpoint dimostra una specifica vulnerabilità BFLA.
"""
from flask import Flask, request, jsonify
from functools import wraps

app = Flask(__name__)

# Mock classes to make the code syntactically valid and runnable
class MockQuery:
    def get(self, user_id):
        return User()

class User:
    query = MockQuery()
    def __init__(self):
        self.role = "user"

class MockSession:
    def delete(self, obj):
        pass
    def commit(self):
        pass

class MockDB:
    session = MockSession()

db = MockDB()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated

# ── BF-001: endpoint admin senza nessuna protezione ──────────────────────────
@app.delete("/admin/users/<int:user_id>")
def delete_user(user_id: int):
    # VULNERABLE: nessun decorator di auth o role
    db.session.delete(User.query.get(user_id))
    db.session.commit()
    return jsonify({"deleted": user_id})

# ── BF-002: auth senza authz ──────────────────────────────────────────────────
@app.put("/users/<int:user_id>/role")
@login_required          # solo autenticazione — nessun role check
def update_user_role(user_id: int):
    # VULNERABLE: qualsiasi utente loggato può cambiare i ruoli
    user = User.query.get(user_id)
    user.role = request.json['role']
    db.session.commit()
    return jsonify({"updated": user_id})

# ── BF-003: route senza methods restrizione ───────────────────────────────────
@app.route("/admin/config")   # VULNERABLE: nessun methods=["GET"]
def admin_config():
    return jsonify(app.config)

from flask import Blueprint

# ── BF-004: blueprint admin senza protezione globale ─────────────────────────
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')
# VULNERABLE: nessun before_request con role check sul blueprint

@admin_bp.route("/users")
def list_all_users():
    return jsonify([u.role for u in [User(), User()]])

# ── BF-004 Pattern B: export_all su path ordinario ───────────────────────────
@app.get("/api/users/export_all")
@login_required   # solo auth — tutti gli utenti loggati possono esportare
def export_all():
    users = [User(), User()]
    return jsonify([u.role for u in users])

# ── BF-006: shadow admin function ────────────────────────────────────────────
@app.get("/debug/token-info")
def debug_token_info():
    return jsonify({"token": request.headers.get("Authorization")})

@app.post("/test/create-admin")
def create_test_admin():
    admin = User()
    admin.role = "admin"
    db.session.commit()
    return jsonify({"created": True})

