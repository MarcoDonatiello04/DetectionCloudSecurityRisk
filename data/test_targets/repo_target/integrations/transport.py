"""Client verso servizi esterni — casi per UC-002 (CWE-319, canale in chiaro).

Etichette: VULNERABILE = dati verso una terza parte su http; SICURO = no.
"""

import os

import httpx
import requests

SHIPPING_API = "http://api.shipfast.example/v1"
PAYMENTS_API = "https://api.payments-partner.example/v2"
WEATHER_URL = os.environ.get("WEATHER_URL", "http://api.weather-partner.example/v2")


# VULNERABILE — URL letterale in chiaro verso l'ERP di un partner.
def fetch_legacy_orders():
    return requests.get("http://erp.legacy-partner.example/api/orders", timeout=10).json()


# VULNERABILE — base URL in chiaro in una costante di modulo.
def track_parcel(tracking_code):
    return requests.get(f"{SHIPPING_API}/tracking/{tracking_code}", timeout=10).json()


# SICURO — https.
def list_payouts():
    return requests.get(f"{PAYMENTS_API}/payouts", timeout=10).json()


# SICURO — http solo verso un servizio locale di sviluppo.
def local_dev_healthcheck():
    return requests.get("http://localhost:9000/health", timeout=2).status_code == 200


# VULNERABILE — il default in chiaro è nel fallback della variabile d'ambiente.
def forecast(city):
    return requests.get(f"{WEATHER_URL}/forecast", params={"city": city}, timeout=10).json()


# VULNERABILE — il canale in chiaro è nel base_url del client, non nella singola chiamata.
def latest_fx_snapshot():
    with httpx.Client(base_url="http://fx.partner-rates.example", timeout=10) as client:
        return client.get("/latest").json()


# SICURO — l'URI http:// è il namespace SOAP usato come chiave di dizionario: nessuna
# richiesta di rete.
def soap_envelope_prefix(namespace_prefixes):
    return namespace_prefixes.get("http://schemas.xmlsoap.org/soap/envelope/", "soap")
