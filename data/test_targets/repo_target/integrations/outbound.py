"""Invio di dati a partner esterni — casi per UC-003 (CWE-601, redirect seguiti alla cieca).

Un 307/308 del partner compromesso fa ripartire il corpo verso un host arbitrario.
Etichette: VULNERABILE = dati sensibili esposti a un redirect seguito; SICURO = no.
"""

import httpx
import requests

KYC_API = "https://kyc.identity-partner.example/v1/checks"
CRM_API = "https://crm.partner-suite.example/api"
STATUS_API = "https://status.partner-suite.example/summary"
HEALTH_RECORDS_API = "https://records.health-partner.example/v1/patients"
TELEMETRY_API = "https://telemetry.vendor-metrics.example/ingest"


# VULNERABILE — POST di dati personali: requests segue i redirect di default.
def submit_kyc_check(user_profile):
    return requests.post(KYC_API, json=user_profile, timeout=10).json()


# VULNERABILE — PUT dei dati cliente verso il CRM, redirect seguiti.
def push_crm_contact(customer_info):
    return requests.put(f"{CRM_API}/contacts", data=customer_info, timeout=10).status_code


# SICURO — redirect disabilitati esplicitamente.
def submit_kyc_check_strict(user_profile):
    response = requests.post(KYC_API, json=user_profile, allow_redirects=False, timeout=10)
    if response.is_redirect:
        raise RuntimeError("redirect inatteso dal provider KYC")
    return response.json()


# SICURO — GET di una pagina di stato pubblica, nessun dato inviato.
def partner_status():
    return requests.get(STATUS_API, timeout=5).json()


# VULNERABILE — stessa esposizione, ma tramite una requests.Session.
def sync_contact(session: requests.Session, contact_details):
    return session.post(f"{CRM_API}/sync", json=contact_details, timeout=10).status_code


# VULNERABILE — httpx non segue i redirect di default, qui vengono riattivati.
def export_patient_record(patient_record):
    return httpx.post(
        HEALTH_RECORDS_API, json=patient_record, follow_redirects=True, timeout=10
    ).status_code


# SICURO — solo contatori aggregati e anonimi (versione, richieste servite).
def send_usage_metrics(usage_data):
    return requests.post(TELEMETRY_API, json=usage_data, timeout=5).status_code
