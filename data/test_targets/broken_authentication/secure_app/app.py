"""
secure_app/app.py
Ground-truth target for blind security validation – SECURE version.
Identical structure to vulnerable_app/app.py but with all 5 vulnerabilities
corrected. Used to measure False Positive Rate: the scanner MUST NOT flag
any of the 5 categories as vulnerable here.

FIX-01 revision (2026-06-21): original fix was "HS256 only" (alg whitelist);
now also adds audience (aud) claim enforcement to match the updated VULN-01
in vulnerable_app (which switched from inert alg:none to missing aud check).
"""

import time
import threading
import jwt                          # PyJWT
from flask import Flask, request, jsonify, session

app = Flask(__name__)
app.secret_key = "super-secret-key-do-not-use-in-prod"

# ---------------------------------------------------------------------------
# In-memory "database"
# ---------------------------------------------------------------------------
USERS = {
    "testuser": {"password": "testpass123", "role": "user"},
    "admin":    {"password": "adminpass!",  "role": "admin"},
}
JWT_SECRET    = "jwt-secret-do-not-use-in-prod"
ALLOWED_ALGOS = ["HS256"]          # strict algorithm whitelist
EXPECTED_AUD  = "vulnerable-app"  # FIX-01: audience this service enforces

# ---------------------------------------------------------------------------
# FIX-03: In-memory rate limiter (max 5 failed attempts per IP per 60 s)
# ---------------------------------------------------------------------------
_rate_lock    = threading.Lock()
_fail_tracker: dict[str, list[float]] = {}  # ip -> [timestamps of failures]

RATE_LIMIT_MAX    = 5
RATE_LIMIT_WINDOW = 60   # seconds


def _is_rate_limited(ip: str) -> bool:
    now = time.time()
    with _rate_lock:
        timestamps = _fail_tracker.get(ip, [])
        # Keep only failures within the current window
        timestamps = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
        _fail_tracker[ip] = timestamps
        return len(timestamps) >= RATE_LIMIT_MAX


def _record_failure(ip: str) -> None:
    now = time.time()
    with _rate_lock:
        _fail_tracker.setdefault(ip, []).append(now)


# ---------------------------------------------------------------------------
# Helper: generate a JWT with a valid expiry
# ---------------------------------------------------------------------------
def generate_token(username: str, role: str) -> str:
    payload = {
        "sub":  username,
        "role": role,
        "aud":  EXPECTED_AUD,        # FIX-01: embed audience claim
        "iat":  int(time.time()),
        "exp":  int(time.time()) + 3600,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


# ---------------------------------------------------------------------------
# /api/login   – FIX-03 (rate limit) + FIX-05 (uniform error messages)
# ---------------------------------------------------------------------------
@app.route("/api/login", methods=["POST"])
def login():
    ip   = request.remote_addr or "unknown"
    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    # FIX-03: Reject if the IP has exceeded the failure threshold.
    if _is_rate_limited(ip):
        return jsonify({"error": "Too many failed attempts. Try again later."}), 429

    # FIX-05: Use the SAME error message and status code regardless of whether
    #         the user exists or the password is wrong (no user enumeration).
    GENERIC_ERROR = {"error": "Invalid credentials"}
    if username not in USERS or USERS[username]["password"] != password:
        _record_failure(ip)
        return jsonify(GENERIC_ERROR), 401

    role  = USERS[username]["role"]
    token = generate_token(username, role)

    # FIX-04: Regenerate the session ID after successful login to prevent
    #         session fixation attacks.
    session.clear()
    session["user"] = username

    return jsonify({"token": token, "username": username, "role": role}), 200


# ---------------------------------------------------------------------------
# /api/profile  – FIX-01 (alg whitelist) + FIX-02 (exp verified)
# ---------------------------------------------------------------------------
@app.route("/api/profile", methods=["GET"])
def profile():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing token"}), 401

    raw_token = auth_header.split(" ", 1)[1]

    try:
        # FIX-01: Only HS256 accepted; audience claim is verified against
        #         EXPECTED_AUD – tokens for other services are rejected.
        # FIX-02: Default options keep verify_exp=True; expired tokens are
        #         rejected with jwt.ExpiredSignatureError.
        payload = jwt.decode(
            raw_token,
            JWT_SECRET,
            algorithms=ALLOWED_ALGOS,
            audience=EXPECTED_AUD,      # FIX-01: enforce aud
            # options left at default → verify_exp=True  # FIX-02
        )
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidAudienceError:
        return jsonify({"error": "Invalid audience"}), 401
    except jwt.InvalidTokenError as exc:
        return jsonify({"error": f"Invalid token: {exc}"}), 401

    username = payload.get("sub", "")
    if username not in USERS:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "username": username,
        "role":     payload.get("role"),
        "profile":  f"Profile data for {username}",
    }), 200


# ---------------------------------------------------------------------------
# /api/admin   – cookie-session protected endpoint
# ---------------------------------------------------------------------------
@app.route("/api/admin", methods=["GET"])
def admin():
    user = session.get("user")
    if not user or USERS.get(user, {}).get("role") != "admin":
        return jsonify({"error": "Forbidden"}), 403
    return jsonify({"message": f"Welcome admin {user}"}), 200


# ---------------------------------------------------------------------------
# /api/logout
# ---------------------------------------------------------------------------
@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out"}), 200


# ---------------------------------------------------------------------------
# /api/refresh  – also validates algorithm and expiry correctly
# ---------------------------------------------------------------------------
@app.route("/api/refresh", methods=["POST"])
def refresh():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing token"}), 401

    raw_token = auth_header.split(" ", 1)[1]
    try:
        payload = jwt.decode(
            raw_token,
            JWT_SECRET,
            algorithms=ALLOWED_ALGOS,
            audience=EXPECTED_AUD,
        )
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidAudienceError:
        return jsonify({"error": "Invalid audience"}), 401
    except jwt.InvalidTokenError as exc:
        return jsonify({"error": f"Invalid token: {exc}"}), 401

    username = payload.get("sub", "")
    role     = payload.get("role", "user")
    return jsonify({"token": generate_token(username, role)}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=True)
