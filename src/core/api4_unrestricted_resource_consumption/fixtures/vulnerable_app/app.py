"""
Vulnerable Flask application — fixture for API4:2023 AST layer tests.

Each endpoint deliberately contains one of the six RC-* vulnerabilities.
Comments mark which rule should fire and why.
"""

from flask import Flask, request, jsonify
import requests

app = Flask(__name__)


def heavy_operation(item):
    """Simulate expensive processing."""
    pass


def send_sms(phone: str, message: str):
    """Simulated paid SMS function (triggers RC-006)."""
    pass


def generate_otp() -> str:
    return "123456"


# ---------------------------------------------------------------------------
# RC-001 — Unbounded Pagination
# limit is read from query string and passed directly to .limit() without min()
# ---------------------------------------------------------------------------
@app.get("/users")
def list_users():
    limit = request.args.get("limit", 10, type=int)  # no cap applied
    # In real code: return db.query(User).limit(limit).all()
    # Simulated:
    data = list(range(1000))
    return jsonify(data[:limit])


# ---------------------------------------------------------------------------
# RC-002 — Upload Without Size Check
# Accesses request.files without checking content_length or MAX_CONTENT_LENGTH
# ---------------------------------------------------------------------------
@app.post("/upload")
def upload_file():
    file = request.files["file"]           # no size check before this
    file.save(f"/tmp/{file.filename}")
    return "ok"


# ---------------------------------------------------------------------------
# RC-003 — HTTP Call Without Timeout
# requests.post() with no timeout= kwarg — worker can block indefinitely
# URL contains 'sms' → confidence 0.95
# ---------------------------------------------------------------------------
@app.post("/notify")
def notify():
    payload = {"to": "+1234567890", "body": "Your code"}
    requests.post("https://api.sms-provider.com/send", json=payload)  # no timeout
    return "sent"


# ---------------------------------------------------------------------------
# RC-004 — GraphQL not applicable in Flask directly.
# Dedicated GraphQL fixture handled in tests/fixtures/graphql_vulnerable.py
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# RC-005 — Loop on User-Controlled Array
# items comes from request.json; no len() check before the loop
# ---------------------------------------------------------------------------
@app.post("/batch-process")
def batch():
    items = request.json["items"]          # tainted — size unknown
    for item in items:                     # no len(items) > MAX check
        heavy_operation(item)
    return "done"


# ---------------------------------------------------------------------------
# RC-006 — Paid-Service Call Without Rate Throttle
# twilio client call with no rate limiting
# ---------------------------------------------------------------------------
from twilio.rest import Client as TwilioClient

ACCOUNT_SID = "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
AUTH_TOKEN = "your_auth_token"
TWILIO_FROM = "+1234567890"
twilio = TwilioClient(ACCOUNT_SID, AUTH_TOKEN)

@app.post("/forgot-password")
def forgot_password():
    phone = request.json["phone"]
    twilio.messages.create(to=phone, from_=TWILIO_FROM, body=generate_otp())
    return "sent"


if __name__ == "__main__":
    app.run(debug=True)
