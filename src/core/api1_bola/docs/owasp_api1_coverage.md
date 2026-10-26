# OWASP API1:2023 — Broken Object Level Authorization: copertura statica

> [!NOTE]
> *Questa tassonomia è una scomposizione interna ispirata a OWASP API1:2023 e a CWE-639,
> non una griglia ufficiale OWASP.* Descrive solo il livello **statico** del modulo
> (`detector.py`, `layers/`, `rules/`); il livello dinamico (`dynamic_orchestrator.py` e
> componenti collegati) resta il riferimento per la conferma empirica.

## Metodologia

- **Effective Coverage = YES** solo se il detector produce il finding corretto, sull'endpoint
  e sul metodo attesi, contro la fixture corrispondente, e nessun finding sulla fixture sicura.
- Il confronto è per tupla `(file, regola, metodo, path normalizzato)`: la regola giusta
  sull'endpoint sbagliato conta come FP + FN.
- Ogni YES è coperto da un test automatico (`tests/unit/api1_bola/test_static_*.py`).

## Confine statico / dinamico

| Aspetto di BOLA | Livello statico | Livello dinamico |
| :--- | :---: | :---: |
| Nessun legame tra l'oggetto e il soggetto autenticato (lookup per solo ID) | ✅ OA-001 / OA-002 | ✅ |
| Legame presente su un metodo e assente su un altro della stessa risorsa | ✅ OA-003 | ✅ |
| ID figlio non agganciato al genitore validato (path annidati) | ✅ OA-004 | ✅ |
| ID sequenziali enumerabili senza guardia di autenticazione | ✅ OA-005 | parziale |
| Contratto che dichiara `security` ma codice senza ownership (punto cieco Spectral) | ✅ Layer 3 | ✅ |
| **Correttezza semantica** di un legame presente (campo sbagliato, confronto invertito, owner falsificabile dal body) | ❌ | ✅ |
| Ownership verificata in moduli importati, middleware di altri file, decorator custom senza nome parlante | ❌ | ✅ |

Il livello statico riconosce la **presenza** di un legame oggetto → chiamante, non la sua
correttezza: `filter_by(owner_id=current_user.id)` è accettato anche se `owner_id` non è
il campo giusto. È il residuo che, nella partizione della tesi, rende API1 una categoria
ibrida.

---

## Coverage Table

| Rule ID | CWE | Categoria | Implementato | Fixture TP (Flask / Express) | Fixture TN | Effective Coverage |
|---------|-----|-----------|:---:|:---:|:---:|:---:|
| OA-001 | CWE-639 | missing_ownership_filter | ✅ | ✅ / ✅ | ✅ | **YES** |
| OA-002 | CWE-639 | direct_object_reference_no_check | ✅ | ✅ / ✅ | ✅ | **YES** |
| OA-003 | CWE-639 | inconsistent_authz_across_methods | ✅ | ✅ / ✅ | ✅ | **YES** |
| OA-004 | CWE-639 | unvalidated_nested_object_reference | ✅ | ✅ / ✅ | ✅ | **YES** |
| OA-005 | CWE-639 | serial_id_no_authz_decorator | ✅ | ✅ / ✅ | ✅ | **YES** |
| Layer 3 | — | contract_status (`security_declared` / `security_missing` / `not_documented`) | ✅ | ✅ | — | **YES** |

Severità e confidenza di partenza: OA-001 HIGH 0.75, OA-002 HIGH 0.70, OA-003 HIGH 0.85,
OA-004 HIGH 0.70, OA-005 MEDIUM 0.60. Il Layer 3 aggiunge +0.10 quando il contratto dichiara
`security` (il codice smentisce una garanzia promessa). La conferma runtime, tramite il `RiskCorrelationEngine`,
eleva la severità (HIGH → CRITICAL, MEDIUM → HIGH) e porta la confidenza a 1.0.

Priorità in deduplicazione (stesso file, metodo e path): OA-003 > OA-004 > OA-001 > OA-002;
le regole assorbite restano in `related_rules`. OA-005 non compete (misura la predicibilità
dell'ID, non chi può accedere).

---

## Registro di validazione

| Data | Fixture | TP | FN | FP | TPR | Precision | Note |
|------|---------|:---:|:---:|:---:|:---:|:---:|------|
| 2026-09-27 | vulnerable_app + secure_app (Flask + Express) | 12 | 0 | 0 | 100.0% | 100.0% | 32 handler; 2 controlli negativi per servizio anche nell'app vulnerabile |
| 2026-09-27 | `repo_target` (fuori campione) | 4 | 0 | 0 | — | — | etichette del target, vedi sotto |

Output di `validate_static_ground_truth.py` (2026-09-27):

```
======================================================================
Fixture: vulnerable_app  (handler analizzati: 16)
  [TP] ('app.py', 'OA-001', 'GET', '/api/orders/{id}')
  [TP] ('app.py', 'OA-002', 'GET', '/api/invoices/{id}')
  [TP] ('app.py', 'OA-002', 'GET', '/api/receipts/{id}')
  [TP] ('app.py', 'OA-003', 'DELETE', '/api/documents/{id}')
  [TP] ('app.py', 'OA-004', 'GET', '/api/projects/{id}/tasks/{id}')
  [TP] ('app.py', 'OA-005', 'GET', '/api/receipts/{id}')
  [TP] ('server.js', 'OA-001', 'GET', '/api/orders/{id}')
  [TP] ('server.js', 'OA-002', 'GET', '/api/invoices/{id}')
  [TP] ('server.js', 'OA-002', 'GET', '/api/receipts/{id}')
  [TP] ('server.js', 'OA-003', 'PUT', '/api/documents/{id}')
  [TP] ('server.js', 'OA-004', 'GET', '/api/projects/{id}/tasks/{id}')
  [TP] ('server.js', 'OA-005', 'GET', '/api/receipts/{id}')

======================================================================
Fixture: secure_app  (handler analizzati: 16)
  [TN] Secure app clean — correct

======================================================================
TP=12 FN=0 FP=0 TN=1
TPR=100.0%  Precision=100.0%  FP su app sicura=0
```

Layer 3 sulla fixture vulnerabile (`openapi.yaml`): `security_declared` 4,
`security_missing` 6, `not_documented` 2. I 4 `security_declared` (OA-001 su
`GET /api/orders/{id}`, OA-003 su `DELETE`/`PUT /api/documents/{id}`, in entrambi i servizi)
sono operazioni su cui la regola Spectral `owasp-api1-object-level-security` **passa**.

---

## Validazione fuori campione

Le fixture sono scritte dallo stesso autore delle regole (rischio di circolarità). Per questo
il detector è stato eseguito anche su target del repository che non sono stati scritti per
questo modulo.

### `data/test_targets/repo_target`

Etichette dichiarate nel docstring del target: `/api/projects/{id}` VULNERABILE (nessun
controllo di ownership), `/api/invoices/{id}` PROTETTA (owner == richiedente, admin ammesso).

```
### data/test_targets/repo_target  handlers=9 with_id=4 access=3 ownership=1  findings=5
  OA-001 GET    /api/projects/<id>  /app.py:69  | username, owner, error = _load_resource("projects", id)
  OA-001 PUT    /api/projects/<id>  /app.py:69  | username, owner, error = _load_resource("projects", id)
  OA-001 PATCH  /api/projects/<id>  /app.py:69  | username, owner, error = _load_resource("projects", id)
  OA-001 DELETE /api/projects/<id>  /app.py:69  | username, owner, error = _load_resource("projects", id)
  OA-001 POST   /api/projects/<id>/import  /app.py:120  | DB.setdefault("projects", {})[id] = data.get("owner", "unknown")
```

- `projects` (4 metodi): TP, concorda con il verdetto runtime atteso.
- `invoices`: nessun finding, concorda con l'etichetta PROTETTA.
- `POST /api/projects/{id}/import`: non etichettato per API1. Qualunque utente autenticato
  sovrascrive l'owner del progetto `id`: è una scrittura BOLA plausibile, da confermare a runtime.

La prima esecuzione (prima dell'analisi delle funzioni di supporto) segnalava anche `invoices`
come OA-002, perché identità e lookup stanno nell'helper `_load_resource()`. Il caso ha portato
al riassunto di un livello delle funzioni dello stesso file (`summarize_helper`), coperto da
`test_same_file_helper_provides_identity_access_and_owner`.

### Altri target

| Target | Handler | Con ID | Finding | Lettura |
| :--- | :---: | :---: | :---: | :--- |
| `broken_function_level_authorization` (fixture API5) | 14 | 4 | 3 | `DELETE /admin/users/<int:user_id>` senza alcuna guardia (OA-002 + OA-005) e `PUT /users/<int:user_id>/role` solo autenticato (OA-001): sovrapposizione attesa con BF-001/BF-002. App sicura: 0 finding |
| `bola` (target dinamico) | 3 | 0 | 0 | rotta catch-all `/<path:path>`: gli ID esistono solo a runtime, fuori portata statica |
| `crapi_repo` | 8 | 0 | 0 | **copertura statica nulla**, vedi limiti |

---

## Limiti noti

1. **crAPI non è coperto dal livello statico.** I casi BOLA di crAPI stanno in servizi Java
   (identity), Go (community) e Django (workshop, class-based view con
   `request.GET["report_id"]`). Il Layer 1 legge solo Flask/FastAPI ed Express, e solo ID nel
   path. Su crAPI la rilevazione di API1 resta interamente dinamica.
2. **ID in query string e nel body** non sono modellati come riferimenti a oggetti.
3. **Analisi intra-file**, con un solo livello di funzioni di supporto. Helper importati da
   altri moduli, middleware definiti altrove e repository/service layer non sono visibili:
   un controllo di ownership lì dentro produce un falso positivo (OA-001/OA-002).
4. **Vocabolario per nome.** Identità (`current_user`, `req.user`, `get_jwt_identity()`,
   `extract_identity(...)`), helper di ownership (`check_ownership`, `authorize`, `isOwner`) e
   campi owner (`owner_id`, `userId`, `author`, …) sono riconosciuti per convenzione di nome.
   Un helper `authorize(...)` viene accettato senza verificarne il contenuto.
5. **Endpoint con ruolo privilegiato esclusi.** Un handler protetto da `admin_required`,
   `is_admin` e simili è considerato di dominio API5; BOLA orizzontale tra amministratori non
   è modellato.
6. **Diramazioni per metodo.** In un handler Flask multi-metodo con
   `if request.method == ...`, il controllo in un solo ramo copre tutti i metodi.
7. **Router annidati Express** (`router.use("/x", subRouter)` a più livelli) e
   `router.route(path).get(...)` non sono risolti.

---

## Eseguire la validazione

```bash
# Dal root del progetto:
PYTHONPATH=. .venv/bin/python tests/unit/api1_bola/validate_static_ground_truth.py
.venv/bin/python -m pytest tests/unit/api1_bola -k static
```

Uso programmatico:

```python
from src.core.api1_bola import detector

report = detector.analyze("path/al/target", openapi_spec=detector.load_spec("openapi.yaml"))
findings = detector.to_domain_findings(report)   # Finding di dominio, chiave api:METODO:path
```
