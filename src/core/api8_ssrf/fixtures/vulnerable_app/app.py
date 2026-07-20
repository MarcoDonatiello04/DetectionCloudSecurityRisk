"""
Fixture API7 vulnerable_app.
Ogni endpoint dimostra un pattern SSRF distinto.
"""
import requests
import urllib.request
from flask import Flask, request, jsonify

app = Flask(__name__)

# SS-001: URL da query param passato direttamente a requests.get
@app.get("/proxy")
def proxy():
    url = request.args.get("url")           # TAINT SOURCE
    response = requests.get(url)            # TAINT SINK — SSRF diretto
    return response.content

# SS-002: URL da body passato a urllib
@app.post("/fetch")
def fetch():
    url = request.json.get("target")        # TAINT SOURCE
    content = urllib.request.urlopen(url)   # TAINT SINK
    return content.read()

# SS-003 è JavaScript — vedere vulnerable_app/server.js

# SS-004: allow_redirects=True con URL da input
@app.post("/webhook-test")
def webhook_test():
    callback = request.json.get("callback_url")   # TAINT SOURCE
    # VULNERABLE: allow_redirects=True permette bypass
    # di allowlist via redirect da host autorizzato a host interno
    r = requests.post(callback, json={"test": True}, allow_redirects=True)
    return jsonify({"status": r.status_code})

# SS-005: accesso diretto a cloud metadata endpoint
@app.get("/debug/instance-info")
def instance_info():
    # VULNERABLE: accesso all'instance metadata service
    # Permette a un attacker di rubare le credenziali IAM dell'istanza
    response = requests.get(
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        timeout=2
    )
    return response.json()

# SS-005: validazione insufficiente (blocklist invece di allowlist)
@app.get("/fetch-resource")
def fetch_resource():
    url = request.args.get("resource_url")
    # VULNERABLE: blocklist bypassabile con encoding o redirect
    if "169.254" in url or "localhost" in url:
        return jsonify({"error": "not allowed"}), 403
    response = requests.get(url)            # ancora SSRF
    return response.content
