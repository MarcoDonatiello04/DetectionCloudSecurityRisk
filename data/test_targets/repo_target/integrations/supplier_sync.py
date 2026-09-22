"""Sincronizzazione dei dati dei fornitori — casi per UC-001 (CWE-20).

Il dato arriva da un'API di terze parti e finisce in un punto pericoloso (query
SQL costruita a stringa, costruttore di modello da dizionario non filtrato).
Etichette: VULNERABILE = il difetto c'è; SICURO = il difetto non c'è.
"""

import logging

import jsonschema
import requests
from pydantic import BaseModel

logger = logging.getLogger(__name__)

SUPPLIER_API = "https://api.supplier-hub.example/v1"
FX_API = "https://fx.partner-rates.example/latest"

SKU_SCHEMA = {
    "type": "object",
    "properties": {"sku": {"type": "string", "pattern": "^[A-Z0-9-]{1,32}$"}},
    "required": ["sku"],
    "additionalProperties": False,
}


class Supplier:
    """Modello ORM semplificato: accetta qualunque campo (is_admin, credit_limit, ...)."""

    def __init__(self, **fields):
        self.__dict__.update(fields)


class QuoteSchema(BaseModel):
    amount: float
    currency: str


# VULNERABILE — tasso di cambio del partner interpolato nella query.
def sync_exchange_rates(cursor):
    rates = requests.get(FX_API, timeout=10).json()
    cursor.execute(f"UPDATE currencies SET rate = {rates['eur']} WHERE code = 'EUR'")


# VULNERABILE — mass assignment: il payload del partner diventa un modello senza whitelist.
def import_supplier(supplier_id):
    supplier_payload = requests.get(f"{SUPPLIER_API}/suppliers/{supplier_id}", timeout=10).json()
    return Supplier(**supplier_payload)


# SICURO — schema Pydantic e query parametrizzata.
def sync_supplier_quote(cursor, supplier_id):
    raw_quote = requests.get(f"{SUPPLIER_API}/quotes/{supplier_id}", timeout=10).json()
    quote = QuoteSchema.model_validate(raw_quote)
    cursor.execute(
        "INSERT INTO quotes (supplier, amount, currency) VALUES (?, ?, ?)",
        (supplier_id, quote.amount, quote.currency),
    )


# SICURO — nessuna validazione, ma la query è parametrizzata: niente iniezione.
def record_supplier_rating(cursor, supplier_id):
    rating_doc = requests.get(f"{SUPPLIER_API}/ratings/{supplier_id}", timeout=10).json()
    cursor.execute(
        "UPDATE suppliers SET rating = ? WHERE id = ?", (rating_doc["score"], supplier_id)
    )


def _fetch_catalog(supplier_id):
    return requests.get(f"{SUPPLIER_API}/catalog/{supplier_id}", timeout=10).json()


# VULNERABILE — il JSON arriva da un helper: il flusso attraversa una chiamata di funzione.
def refresh_catalog(cursor, supplier_id):
    catalog = _fetch_catalog(supplier_id)
    cursor.execute(f"DELETE FROM catalog WHERE supplier_code = '{catalog['supplier_code']}'")


class OrderMirror:
    def __init__(self, db):
        self.db = db

    # VULNERABILE — stessa iniezione, ma la connessione è un attributo (self.db).
    def mirror_order(self, order_id):
        order_doc = requests.get(f"{SUPPLIER_API}/orders/{order_id}", timeout=10).json()
        self.db.execute(f"INSERT INTO orders (reference) VALUES ('{order_doc['reference']}')")


# VULNERABILE — len() usato solo per il log non valida nulla.
def import_shipment_status(cursor, shipment_id):
    shipment = requests.get(f"{SUPPLIER_API}/shipments/{shipment_id}", timeout=10).json()
    received_fields = len(shipment)
    logger.info("shipment %s: %d campi ricevuti", shipment_id, received_fields)
    cursor.execute(f"UPDATE shipments SET status = '{shipment['status']}' WHERE id = %s", (shipment_id,))


# SICURO — int() rifiuta qualunque valore non numerico prima della query.
def sync_stock_level(cursor, sku):
    stock = requests.get(f"{SUPPLIER_API}/stock/{sku}", timeout=10).json()
    cursor.execute(f"UPDATE stock SET qty = {int(stock['quantity'])} WHERE sku = %s", (sku,))


# SICURO — JSON Schema con pattern restrittivo validato prima dell'uso.
def register_sku(cursor):
    sku_doc = requests.get(f"{SUPPLIER_API}/skus/next", timeout=10).json()
    jsonschema.validate(instance=sku_doc, schema=SKU_SCHEMA)
    cursor.execute(f"INSERT INTO skus (code) VALUES ('{sku_doc['sku']}')")
