# Ground-Truth Target — README

Questo repository contiene due applicazioni Flask identiche nella struttura,
da usare come **target di validazione cieca** per uno scanner di Broken
Authentication (OWASP API2:2023).

| App | Porta | Stato |
|-----|-------|-------|
| `vulnerable_app/` | **5001** | 5 vulnerabilità deliberate |
| `secure_app/` | **5002** | Tutte e 5 corrette |

---

## Prerequisiti

- Python ≥ 3.10
- pip

---

## Installazione

### vulnerable_app

```bash
cd vulnerable_app
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### secure_app

```bash
cd secure_app
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

> Le dipendenze sono identiche (`flask`, `pyjwt`, `werkzeug`). Puoi
> condividere un unico virtualenv installando i requisiti di entrambe le
> cartelle se preferisci.

---

## Avvio

In due terminali separati:

```bash
# Terminale 1 – app vulnerabile su porta 5001
cd vulnerable_app && python app.py

# Terminale 2 – app sicura su porta 5002
cd secure_app && python app.py
```

---

## Utenti di test pre-registrati

Entrambe le app condividono gli stessi utenti (definiti in memoria):

| Username | Password | Ruolo |
|----------|----------|-------|
| `testuser` | `testpass123` | user |
| `admin` | `adminpass!` | admin |

### Esempio di autenticazione con curl

```bash
# Login – ottieni il token JWT
TOKEN=$(curl -s -X POST http://localhost:5001/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass123"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Accesso all'endpoint protetto
curl -H "Authorization: Bearer $TOKEN" http://localhost:5001/api/profile
```

---

## Struttura del progetto

```
tests/ground_truth/
├── vulnerable_app/
│   ├── app.py           # 5 vulnerabilità marchiate VULN-01…VULN-05
│   ├── requirements.txt
│   └── openapi.yaml
├── secure_app/
│   ├── app.py           # Stessa struttura, tutti i fix applicati
│   ├── requirements.txt
│   └── openapi.yaml
├── answer_key.md        # ⚠️  NON esporre allo scanner prima del test
└── README.md
```

---

## Istruzioni per il validatore

1. Avvia entrambe le app.
2. Fornisci allo scanner **solo** gli URL e le credenziali di test.
3. Esegui lo scanner su `http://localhost:5001` (vulnerabile) e poi su
   `http://localhost:5002` (sicura).
4. Al termine, confronta i risultati con `answer_key.md` per calcolare
   TPR e FPR.

> **`answer_key.md` non è referenziato da nessun file dentro le due
> cartelle delle app.** È intenzionalmente fuori da entrambe le directory.
