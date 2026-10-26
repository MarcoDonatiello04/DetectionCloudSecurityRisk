"""
Applicazione gemella VULNERABILE per la validazione del modulo BOPLA (OWASP API3:2023).

Non usa un framework web: espone `handle(method, path, headers, body)` e viene interrogata
nello stesso processo dei test, che instradano le richieste HTTP del tester dinamico verso
questa funzione. Lo stato e' in memoria e si ripristina con `reset()`.

Difetti presenti (identici per struttura alla variante sicura, che li corregge):
  - GET /api/users/{id} restituisce l'intero oggetto, compresi `salary` e `role`
    (esposizione di proprieta' riservate, API3 in lettura);
  - PUT /api/users/{id} assegna al modello ogni campo ricevuto (mass assignment,
    API3 in scrittura), anche `salary` e `role` che solo l'amministratore puo' cambiare.
"""

import base64
import json


def roles_required(*roles):
    """Ammette la chiamata solo se il chiamante ha uno dei ruoli indicati."""

    def wrap(fn):
        def inner(current_user, *args, **kwargs):
            if current_user.role not in roles:
                return 403, {"error": "forbidden"}
            return fn(current_user, *args, **kwargs)

        return inner

    return wrap


class UserDTO:
    id: str
    name: str
    email: str
    salary: int
    role: str

    def __init__(self, id, name, email, salary, role):
        self.id = id
        self.name = name
        self.email = email
        self.salary = salary
        self.role = role


DB: dict[str, UserDTO] = {}


def reset():
    DB.clear()
    DB["alice"] = UserDTO("alice", "Alice", "alice@example.com", 3000, "user")
    DB["admin"] = UserDTO("admin", "Admin", "admin@example.com", 9000, "admin")


def _current_user(headers):
    header = headers.get("Authorization", "")
    parts = header.split(" ")[-1].split(".")
    if len(parts) < 2:
        return None
    try:
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except Exception:
        return None
    return DB.get(payload.get("sub"))


def to_public(user):
    return {"id": user.id, "name": user.name, "email": user.email}


def get_user(current_user, user_id):
    user = DB.get(user_id)
    if user is None:
        return 404, {"error": "not found"}
    if current_user.id != user.id and current_user.role != "admin":
        return 403, {"error": "forbidden"}
    # Difetto: l'oggetto viene serializzato per intero, campi riservati compresi.
    return 200, dict(vars(user))


def update_user(current_user, user_id, body):
    user = DB.get(user_id)
    if user is None:
        return 404, {"error": "not found"}
    if current_user.id != user.id and current_user.role != "admin":
        return 403, {"error": "forbidden"}
    # Difetto: ogni campo ricevuto viene assegnato al modello (mass assignment).
    for field, value in (body or {}).items():
        if field != "id":
            setattr(user, field, value)
    return 200, to_public(user)


@roles_required("admin")
def update_compensation(current_user, user_id, body):
    user = DB[user_id]
    user.salary = body.get("salary", user.salary)
    user.role = body.get("role", user.role)
    return 200, to_public(user)


def handle(method, path, headers, body=None):
    current_user = _current_user(headers or {})
    if current_user is None:
        return 401, {"error": "unauthenticated"}
    parts = [p for p in path.split("?")[0].split("/") if p]
    if parts[:2] == ["api", "users"] and len(parts) == 3:
        if method == "GET":
            return get_user(current_user, parts[2])
        if method in ("PUT", "PATCH"):
            return update_user(current_user, parts[2], body)
    if parts[:3] == ["api", "admin", "users"] and len(parts) == 5 and method == "POST":
        return update_compensation(current_user, parts[3], body or {})
    return 404, {"error": "not found"}


reset()
