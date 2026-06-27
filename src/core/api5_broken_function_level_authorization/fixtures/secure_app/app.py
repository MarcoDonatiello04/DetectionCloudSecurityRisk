"""
Fixture API5 secure_app.
Ogni endpoint dimostra la corretta mitigazione.
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

def require_role(role):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            return f(*args, **kwargs)
        return decorated
    return decorator

# ── BF-001 SECURE ─────────────────────────────────────────────────────────────
@app.delete("/admin/users/<int:user_id>")
@login_required
@require_role("admin")
def delete_user(user_id: int):
    db.session.delete(User.query.get(user_id))
    db.session.commit()
    return jsonify({"deleted": user_id})

# ── BF-002 SECURE ─────────────────────────────────────────────────────────────
@app.put("/users/<int:user_id>/role")
@login_required
@require_role("admin")
def update_user_role(user_id: int):
    user = User.query.get(user_id)
    user.role = request.json['role']
    db.session.commit()
    return jsonify({"updated": user_id})

# ── BF-003 SECURE ─────────────────────────────────────────────────────────────
@app.route("/admin/config", methods=["GET"])
@login_required
@require_role("admin")
def admin_config():
    return jsonify(app.config)

from flask import Blueprint

# ── BF-004 SECURE (Blueprint with before_request) ────────────────────────────
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.before_request
@login_required
@require_role("admin")
def check_admin_access():
    pass

@admin_bp.route("/users")
def list_all_users():
    return jsonify([u.role for u in [User(), User()]])

# ── BF-004 Pattern B SECURE (export_all with require_role) ───────────────────
@app.get("/api/users/export_all")
@login_required
@require_role("admin")
def export_all():
    users = [User(), User()]
    return jsonify([u.role for u in users])



