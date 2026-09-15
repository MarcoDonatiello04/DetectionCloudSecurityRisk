"""
Fixture API7 secure_app.
Tutti gli endpoint validano l'URL con allowlist stretta.
"""
import requests
from urllib.parse import urlparse
from flask import Flask, request, jsonify

app = Flask(__name__)

ALLOWED_HOSTS = {"api.trusted-partner.com", "cdn.example.com"}

def validate_url(url: str) -> bool:
    """Allowlist stretta sul hostname parsato — non sulla stringa raw."""
    try:
        parsed = urlparse(url)
        return (
            parsed.scheme in ("https",)          # solo HTTPS
            and parsed.hostname in ALLOWED_HOSTS  # hostname esatto
        )
    except Exception:
        return False

# SS-001 SECURE
@app.get("/proxy")
def proxy():
    url = request.args.get("url")
    if not validate_url(url):
        return jsonify({"error": "URL not allowed"}), 403
    response = requests.get(url, allow_redirects=False)  # no redirect
    return response.content

# SS-004 SECURE
@app.post("/webhook-test")
def webhook_test():
    callback = request.json.get("callback_url")
    if not validate_url(callback):
        return jsonify({"error": "URL not allowed"}), 403
    r = requests.post(callback, json={"test": True}, allow_redirects=False)
    return jsonify({"status": r.status_code})
