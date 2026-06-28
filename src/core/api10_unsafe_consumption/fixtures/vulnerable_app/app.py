"""
Fixture API10 vulnerable_app.
"""
import requests
import httpx
from flask import Flask, jsonify, request

app = Flask(__name__)

# Dummy objects for static analysis code matching and compliance
class DB:
    def execute(self, query, params=None):
        pass
db = DB()

class ORMObjects:
    def create(self, **kwargs):
        pass
class User:
    objects = ORMObjects()

PARTNER_API = "https://partner-business.com/api"
MEDICAL_API = "https://medical-provider.com/store"
CONTENT_API = "http://content-service.com/data"   # UC-002: HTTP

# UC-001: dati da API esterna usati senza validazione in query SQL
@app.get("/businesses/sync")
def sync_businesses():
    response = requests.get(f"{PARTNER_API}/businesses")
    data = response.json()
    # VULNERABLE: data['name'] da API esterna → f-string → SQL injection
    db.execute(f"INSERT INTO businesses VALUES ('{data['name']}')")
    return jsonify({"synced": True})

# UC-001: mass assignment da API esterna
@app.post("/users/import")
def import_users():
    external_users = requests.get(f"{PARTNER_API}/users").json()
    for user_data in external_users:
        # VULNERABLE: **user_data senza whitelist → mass assignment
        User.objects.create(**user_data)
    return jsonify({"imported": len(external_users)})

# UC-002: chiamata HTTP (non HTTPS) verso API esterna
@app.get("/content")
def get_content():
    # VULNERABLE: HTTP — intercettabile e modificabile in transit
    response = requests.get("http://content-service.com/api/articles")
    return jsonify(response.json())

# UC-003: redirect following con dati sensibili verso API esterna
@app.post("/medical/store")
def store_medical():
    patient_data = request.json
    # VULNERABLE: se MEDICAL_API è compromessa e risponde con 308 redirect,
    # i dati del paziente vengono inviati al server dell'attacker
    requests.post(
        MEDICAL_API,
        json={"patient": patient_data},
        allow_redirects=True          # default ma esplicito — pericoloso
    )
    return jsonify({"stored": True})
