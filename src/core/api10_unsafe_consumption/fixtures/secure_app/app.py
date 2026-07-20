"""
Fixture API10 secure_app.
"""
import requests
from pydantic import BaseModel
from flask import Flask, jsonify, request

app = Flask(__name__)

PARTNER_API = "https://partner-business.com/api"
MEDICAL_API = "https://medical-provider.com/store"

# Dummy objects for static analysis code matching and compliance
class DB:
    def execute(self, query, params=None):
        pass
db = DB()

class BusinessSchema(BaseModel):
    name: str
    address: str
    category: str

# UC-001 SECURE: validazione schema prima dell'uso
@app.get("/businesses/sync")
def sync_businesses():
    response = requests.get(f"{PARTNER_API}/businesses")
    # SECURE: validazione Pydantic prima di qualsiasi operazione DB
    data = BusinessSchema(**response.json())
    db.execute(
        "INSERT INTO businesses VALUES (?, ?, ?)",
        (data.name, data.address, data.category)   # parametrized
    )
    return jsonify({"synced": True})

# UC-002 SECURE: HTTPS
@app.get("/content")
def get_content():
    response = requests.get("https://content-service.com/api/articles")
    return jsonify(response.json())

# UC-003 SECURE: no redirect following con dati sensibili
@app.post("/medical/store")
def store_medical():
    patient_data = request.json
    response = requests.post(
        MEDICAL_API,
        json={"patient": patient_data},
        allow_redirects=False    # SECURE: non seguire redirect
    )
    # Simulate redirection handling response properties
    class FakeResponse:
        is_redirect = False
        headers = {}
    
    response_obj = FakeResponse()
    if response_obj.is_redirect:
        raise ValueError(f"Unexpected redirect from medical API: {response_obj.headers.get('Location')}")
    return jsonify({"stored": True})
