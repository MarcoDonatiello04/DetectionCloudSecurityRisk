"""
vulnerable_app/app.py
Ground-truth target for blind security validation.
Contains 5 deliberate authentication vulnerabilities (VULN-01 … VULN-05).
DO NOT share this file or its comments with the scanner or the agent running it
before the validation test is complete.

VULN-01 revision (2026-06-21): original alg:none approach replaced with
  "no audience verification" because PyJWT >= 2.4 rejects alg:none when a
  non-None key is supplied, making the original bug inert at runtime.
  The replacement (no aud check) is confirmed exploitable with curl.
"""

import time
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
JWT_SECRET   = "jwt-secret-do-not-use-in-prod"
EXPECTED_AUD = "vulnerable-app"   # The audience this service SHOULD enforce

# ---------------------------------------------------------------------------
# Helper: generate a (vulnerable) JWT – does NOT embed 'aud' claim
# ---------------------------------------------------------------------------
def generate_token(username: str, role: str) -> str:
    payload = {
        "sub":  username,
        "role": role,
        "iat":  int(time.time()),
        "exp":  int(time.time()) + 3600,   # 1 hour
        # Note: 'aud' claim deliberately omitted from issued tokens so that
        # the missing-aud-verification bug is naturally triggered by any token.
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


# ---------------------------------------------------------------------------
# /api/login   – VULN-03 (no rate limit) + VULN-05 (user enumeration)
# ---------------------------------------------------------------------------
@app.route("/api/login", methods=["POST"])
def login():
    data     = request.get_json(force=True, silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    # VULN-03: No rate limiting – unlimited login attempts with no throttle.
    #          An attacker can brute-force credentials without any restriction.

    if username not in USERS:
        # VULN-05: Different error message reveals that the user does not exist.
        return jsonify({"error": "User not found"}), 404

    if USERS[username]["password"] != password:
        # VULN-05: Different message (and different status) for wrong password.
        return jsonify({"error": "Invalid password"}), 401

    role  = USERS[username]["role"]
    token = generate_token(username, role)

    # VULN-04: Session fixation – session ID is NOT regenerated after login.
    #          An attacker who fixes the session ID before login retains it.
    session["user"] = username

    return jsonify({"token": token, "username": username, "role": role}), 200


# ---------------------------------------------------------------------------
# /api/profile  – VULN-01 (no aud check) + VULN-02 (exp not verified)
# ---------------------------------------------------------------------------
@app.route("/api/profile", methods=["GET"])
def profile():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing token"}), 401

    raw_token = auth_header.split(" ", 1)[1]

    try:
        # VULN-01: The 'audience' (aud) claim is never verified.
        #          A token issued for a completely different service (e.g.
        #          aud="attacker-service") is accepted as valid here.
        #          Exploit: sign any token with JWT_SECRET (or obtain one from
        #          another service sharing the same secret) and omit/forge aud.
        # VULN-02: options={"verify_exp": False} disables expiry verification.
        #          A token with exp=1 (Unix epoch 1970-01-01) is accepted.
        payload = jwt.decode(
            raw_token,
            JWT_SECRET,
            algorithms=["HS256"],           # HS256 only (alg:none correctly blocked)
            options={
                "verify_exp": False,        # VULN-02: exp never checked
                "verify_aud": False,        # VULN-01: aud never checked
            },
        )
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
# /api/admin   – cookie-session protected endpoint (demonstrates VULN-04)
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
# /api/refresh  (also vulnerable to VULN-02 / VULN-01)
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
            algorithms=["HS256"],
            options={"verify_exp": False, "verify_aud": False},
        )
    except jwt.InvalidTokenError as exc:
        return jsonify({"error": f"Invalid token: {exc}"}), 401

    username = payload.get("sub", "")
    role     = payload.get("role", "user")
    return jsonify({"token": generate_token(username, role)}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
