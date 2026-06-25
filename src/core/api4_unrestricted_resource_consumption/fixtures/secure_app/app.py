"""
Secure Flask application — fixture for API4:2023 AST layer tests.

All six endpoints are protected correctly.
No RC-* rule should fire on this file.
"""

from flask import Flask, request, jsonify, abort
import requests
import functools

app = Flask(__name__)

# RC-002 guard: Flask global upload size limit
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB

MAX_LIMIT = 100
MAX_ITEMS = 50


# ---------------------------------------------------------------------------
# Simple rate-limit decorator (in-memory, for fixture purposes only)
# ---------------------------------------------------------------------------
_call_counts: dict = {}

def rate_limit(max_calls: int = 5, period: int = 3600, per: str = "user"):
    """Minimal in-process rate limiter (fixture only)."""
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def heavy_operation(item):
    pass


def send_sms(phone: str, message: str):
    pass


def generate_otp() -> str:
    return "123456"


# ---------------------------------------------------------------------------
# RC-001 SECURE — Pagination with explicit cap via min()
# ---------------------------------------------------------------------------
@app.get("/users")
def list_users():
    limit = request.args.get("limit", 10, type=int)
    limit = min(limit, MAX_LIMIT)          # ← cap applied
    data = list(range(1000))
    return jsonify(data[:limit])


# ---------------------------------------------------------------------------
# RC-002 SECURE — Upload with MAX_CONTENT_LENGTH set at app level
# (Flask will reject oversized requests automatically)
# ---------------------------------------------------------------------------
@app.post("/upload")
def upload_file():
    if request.content_length and request.content_length > app.config["MAX_CONTENT_LENGTH"]:
        abort(413)
    file = request.files["file"]
    file.save(f"/tmp/safe_{file.filename}")
    return "ok"


# ---------------------------------------------------------------------------
# RC-003 SECURE — HTTP call with explicit timeout
# ---------------------------------------------------------------------------
@app.post("/notify")
def notify():
    payload = {"to": "+1234567890", "body": "Your code"}
    requests.post(
        "https://api.sms-provider.com/send",
        json=payload,
        timeout=5.0,                       # ← timeout present
    )
    return "sent"


# ---------------------------------------------------------------------------
# RC-004 — Not applicable (Flask, no GraphQL server here)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# RC-005 SECURE — Loop with len() guard before iteration
# ---------------------------------------------------------------------------
@app.post("/batch-process")
def batch():
    items = request.json["items"]
    if len(items) > MAX_ITEMS:             # ← guard applied
        abort(400)
    for item in items:
        heavy_operation(item)
    return "done"


# ---------------------------------------------------------------------------
# RC-006 SECURE — Rate-limit decorator on paid-service endpoint
# ---------------------------------------------------------------------------
from twilio.rest import Client as TwilioClient

ACCOUNT_SID = "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
AUTH_TOKEN = "your_auth_token"
TWILIO_FROM = "+1234567890"
twilio = TwilioClient(ACCOUNT_SID, AUTH_TOKEN)

@app.post("/forgot-password")
@rate_limit(max_calls=3, period=3600, per="user")   # ← throttle present
def forgot_password():
    phone = request.json["phone"]
    twilio.messages.create(to=phone, from_=TWILIO_FROM, body=generate_otp())
    return "sent"


if __name__ == "__main__":
    app.run(debug=True)
