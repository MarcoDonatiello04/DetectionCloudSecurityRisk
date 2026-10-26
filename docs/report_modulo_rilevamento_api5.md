# Report Strutturato: Modulo di Rilevamento API5:2023 (BFLA)

Il modulo [`src/core/api5_bfla`](../src/core/api5_bfla) è il componente della piattaforma dedicato all'analisi statica e contrattuale delle vulnerabilità riconducibili a **OWASP API5:2023 — Broken Function Level Authorization (BFLA)**. Copre le CWE-285, CWE-862, CWE-650, CWE-284, CWE-276 e, con l'estensione in corso, CWE-269.

> **Stato al 2026-09-25** — 7 regole implementate: BF-001→BF-006 validate, più BF-007 aggiunta nella Fase 1 del piano di estensione. La suite `tests/unit/api5_bfla` conta **61 test verdi** e la ground truth dà **TPR 100% / FPR 0%**. BF-007 resta marcata come *proposta* nel registro di copertura fino alla Fase 6 del piano (§7).

---

## 1. Obiettivo ed Ambito di Analisi

Il BOLA (API1) chiede *"questo utente può accedere a **questo oggetto**?"*. Il BFLA chiede invece *"questo utente può invocare **questa funzione**?"*. Il modulo intercetta gli endpoint che espongono funzionalità privilegiate (amministrative, distruttive, di debug o di gestione dei ruoli) senza un controllo di autorizzazione proporzionato alla funzione. Gli scenari principali sono:
* **Accesso anonimo a funzioni amministrative**: rotte `/admin`, `/internal`, `/management` prive di qualunque guardia.
* **Autenticazione scambiata per autorizzazione**: un `@login_required` davanti a un'operazione distruttiva, che lascia agire qualsiasi utente loggato.
* **Aggiramento tramite verbo HTTP**: rotte privilegiate che accettano ogni metodo, oppure header `X-HTTP-Method-Override` non filtrati.
* **Funzioni ombra**: endpoint di debug, test o seed rimasti in produzione e assenti dal contratto OpenAPI.
* **Politica permissiva di default**: framework configurati in *allow-by-default* (DRF senza `DEFAULT_PERMISSION_CLASSES`, FastAPI o Express senza dipendenze/middleware globali).
* **Escalation di privilegio via payload** *(BF-007)*: il chiamante si auto-assegna un ruolo inviando `{"role": "admin"}` nel body.

---

## 2. Architettura dei Componenti

Il modulo usa un motore a **tre layer indipendenti**, i cui risultati convergono in un unico punto di deduplicazione:

| Layer | Tecnica | Input | Regole |
| :--- | :--- | :--- | :--- |
| **1 — AST** | Parsing sintattico con **tree-sitter** (Python, JavaScript/TypeScript) | Sorgenti `.py`, `.js`, `.ts`, `.jsx`, `.tsx`, `.mjs`, `.cjs` | BF-001, BF-002, BF-003, BF-004, BF-006, BF-007 |
| **2 — Config** | `ast` standard di Python ed euristiche testuali | `settings.py`, `app.py`, `main.py`, `app.js`, `server.js`, `index.js`, … | BF-005 |
| **3 — OpenAPI** | Analisi contrattuale e correlazione con il Layer 1 | Specifica OpenAPI 3.x / Swagger 2.0 già parsata | BF-001, BF-003, BF-004, BF-006 |

```
src/core/api5_bfla/
├── detector.py                  # Entry point analyze(): orchestra i layer, deduplica, riepiloga
├── models.py                    # RuleID (enum), FunctionAuthzFinding, FunctionAuthzReport
├── layers/
│   ├── layer1_ast.py            # Parsing tree-sitter, dispatch delle regole, estrazione endpoint
│   ├── layer2_config.py         # Discovery dei file di configurazione → BF-005
│   └── layer3_openapi.py        # Analisi della spec, correlazione AST↔spec, arricchimento x-security-analysis
├── rules/
│   ├── privileged_endpoint_no_role_check.py   # BF-001 + helper condivisi (is_privileged_path, has_inline_role_check)
│   ├── auth_without_authz.py                  # BF-002
│   ├── http_method_override.py                # BF-003
│   ├── admin_path_exposure.py                 # BF-004
│   ├── missing_deny_by_default.py             # BF-005
│   ├── shadow_admin_function.py               # BF-006
│   └── privilege_escalation_payload.py        # BF-007
└── docs/
    └── owasp_api5_coverage.md   # Registro formale di copertura e validazione
```

### Ruolo dei Moduli Principali

* [`detector.py`](../src/core/api5_bfla/detector.py): la funzione [`analyze(target_path, openapi_spec=None, enrich_spec=False)`](../src/core/api5_bfla/detector.py#L98) esegue sempre i Layer 1 e 2. Esegue il Layer 3 solo se riceve una specifica, alla quale passa anche i finding AST e gli endpoint scoperti per la correlazione. Deduplica i finding e costruisce `coverage_signals` (categoria → regole) e `summary` (conteggi per severità, categoria e layer).
* [`models.py`](../src/core/api5_bfla/models.py): [`RuleID`](../src/core/api5_bfla/models.py#L5) è un enum `str` con gli identificativi univoci. [`FunctionAuthzFinding`](../src/core/api5_bfla/models.py#L18) ha i campi `rule_id`, `cwe_id`, `category`, `severity`, `file_path`, `line_number`, `endpoint`, `http_methods`, `required_role`, `found_guard`, `missing_guard`, `evidence`, `confidence` e `layer`.
* [`layer1_ast.py`](../src/core/api5_bfla/layers/layer1_ast.py): percorre il target saltando `node_modules`, `.venv`, `dist` e le altre directory di build, oltre ai file binari, vuoti o sopra 1 MB. Su ogni file esegue la catena di regole del linguaggio; se una regola fallisce registra un *warning* e le altre proseguono. Estrae poi l'inventario degli endpoint, compresi i prefissi dei Blueprint Flask. Deduplica per `(rule_id, file, riga)` e ordina per severità e confidenza.
* [`layer3_openapi.py`](../src/core/api5_bfla/layers/layer3_openapi.py): oltre alle regole contrattuali produce due **segnali di correlazione**. BF-003 è marcata `layer="ast+openapi"` quando la spec dichiara un'operazione che il codice non restringe per metodo. BF-006 scatta per ogni endpoint presente nel codice ma assente dalla spec, se il path è di tipo *shadow*. Con `enrich_spec=True` scrive i finding nella specifica sotto l'estensione `x-security-analysis.api5_findings`.

### Helper condivisi

Le regole AST condividono tre primitive definite in [`privileged_endpoint_no_role_check.py`](../src/core/api5_bfla/rules/privileged_endpoint_no_role_check.py):
* [`is_privileged_path()`](../src/core/api5_bfla/rules/privileged_endpoint_no_role_check.py#L54): normalizza i parametri di path (`<int:id>`, `{id}`, `:id` → `*`) e confronta il risultato con `PRIVILEGED_PATH_PATTERNS` (`/admin`, `/internal`, `/management`, `/debug`, `/config`, `/users/*/role`, `/users/*/promote`, `/export`, …). Considera privilegiate anche le operazioni `DELETE`/`PUT` su collezione, cioè quelle il cui ultimo segmento non è un identificativo.
* [`has_inline_role_check()`](../src/core/api5_bfla/rules/privileged_endpoint_no_role_check.py#L76): riconosce un controllo di ruolo nel corpo dell'handler (`is_admin`, `is_staff`, `has_role`, `check_permission`, `role ==`, `… in … role`).
* `ROLE_CHECK_DECORATORS` / `AUTH_ONLY_DECORATORS`: tengono distinti i decorator e middleware di **autorizzazione** (`require_role`, `admin_required`, `IsAdminUser`, `permission_classes`, …) da quelli di sola **autenticazione** (`login_required`, `jwt_required`, `IsAuthenticated`, …). Su questa distinzione si regge BF-002.

---

## 3. Matrice delle Regole di Rilevamento

| Regola | CWE | Severità | Categoria | Layer | Linguaggi / Target | Descrizione Operativa |
| :--- | :--- | :---: | :--- | :--- | :--- | :--- |
| **BF-001** | CWE-285 | CRITICAL | `privileged_endpoint_no_role_check` | AST, OpenAPI | Flask, FastAPI, Express, OpenAPI | Endpoint su path privilegiato senza decorator/middleware di ruolo né controllo inline. Nella spec: operazione privilegiata senza `security` (né locale né globale). |
| **BF-002** | CWE-862 | HIGH | `auth_without_authz` | AST | Flask, FastAPI, Express | Handler con operazione sensibile (`delete`, `set_role`, `role =`, `refund`, `stripe.Charge`, …) protetto **solo** da autenticazione. |
| **BF-003** | CWE-650 | HIGH | `http_method_override` | AST, AST+OpenAPI | Flask, Express, OpenAPI | `@app.route` su path privilegiato senza `methods=[…]`, `router.all()` su path privilegiato, uso di `X-HTTP-Method-Override` senza whitelist. |
| **BF-004** | CWE-284 | HIGH | `admin_path_exposure` | AST, OpenAPI | Flask Blueprint, Express, OpenAPI | (A) Blueprint con prefisso `/admin`/`/internal` senza `before_request` di ruolo; (B) funzione *bulk* (`export_all`, `.all()`, `find_all(`) su path ordinario senza ruolo; (C) path admin nella spec senza `security`. |
| **BF-005** | CWE-276 | MEDIUM | `missing_deny_by_default` | Config | Django REST Framework, FastAPI, Express | `REST_FRAMEWORK` senza `DEFAULT_PERMISSION_CLASSES` o con `AllowAny`; `FastAPI()` senza `dependencies=`; app Express senza `app.use(auth…)` prima dei router. |
| **BF-006** | CWE-285 | HIGH / MEDIUM / LOW | `shadow_admin_function` | AST, OpenAPI | Flask, Express, OpenAPI | Path `/debug/`, `/test/`, `/dev/`, `/seed/`, `/backdoor/`, … senza ruolo (HIGH, MEDIUM se autenticati ma senza ruolo); gli stessi path protetti restano segnalati come residui da rimuovere (LOW); funzioni `seed_`, `create_admin`, `bypass_` senza ruolo; endpoint shadow presenti nel codice ma assenti dalla spec. |
| **BF-007** *(proposta)* | CWE-269 | CRITICAL | `privilege_escalation_via_payload` | AST | Flask, FastAPI, DRF `@api_view`, Express | Campo di privilegio letto dal payload e **assegnato** a un oggetto/modello senza verificare che il *chiamante* possa concedere quel privilegio. Dettaglio in §4.4. |

### Confidenza per regola

| Regola | Confidenza | Condizione |
| :--- | :---: | :--- |
| BF-001 | 0.95 / 0.75 | 0.95 su path esplicitamente amministrativi; 0.75 quando il privilegio deriva solo da `DELETE`/`PUT` su collezione |
| BF-002 | 0.80 | Autenticazione presente, autorizzazione assente |
| BF-003 | 0.90 / 0.85 | 0.90 per rotta senza restrizione di metodo o correlata alla spec; 0.85 per `X-HTTP-Method-Override` |
| BF-004 | 0.90 / 0.70 | 0.90 per Blueprint o spec admin; 0.70 per il pattern *bulk* su path ordinario (euristico) |
| BF-005 | 0.95 / 0.75 / 0.65 | Rispettivamente DRF, Express, FastAPI (decrescente con l'affidabilità del parsing) |
| BF-006 | 0.95 / 0.90 / 0.75 / 0.50 | Shadow da correlazione spec / path shadow non protetto / residuo protetto / solo nome della funzione |
| BF-007 | 0.90 | Flusso diretto payload → assegnazione, senza guardia sul chiamante |

---

## 4. Dettagli di Funzionamento del Motore di Analisi

### 4.1. Riconoscimento delle rotte

Il Layer 1 lavora sull'albero sintattico concreto prodotto da tree-sitter, non su regex applicate al testo del file. Questo lo rende robusto ai commenti, alla formattazione e ai decorator impilati:
* **Python**: `decorated_definition` → decorator `app.|bp.|router.{route,get,post,put,patch,delete}`. Il path è il primo argomento stringa; i metodi vengono dal verbo del decorator o dalla keyword `methods=[…]`. I prefissi dei `Blueprint(url_prefix=…)` si risolvono tramite l'assegnazione della variabile del blueprint.
* **JavaScript/Express**: `call_expression` `app|router.<verbo>(path, …middleware, handler)`. Il primo argomento è il path, l'ultimo è l'handler, quelli intermedi sono i middleware su cui si cercano le guardie di ruolo.

### 4.2. Deduplicazione cross-layer

Lo stesso endpoint può essere segnalato da più regole (ad esempio BF-001 e BF-002 su `PUT /users/<id>/role`) e da più layer (AST e OpenAPI). [`deduplicate_findings()`](../src/core/api5_bfla/detector.py#L58) raggruppa i finding **per path** e ne conserva uno solo, scelto secondo `RULE_PRIORITY`:

```
BF-006 > BF-004 > BF-003 > BF-002 > BF-001 > BF-005
```

A parità di priorità vince il finding AST, che ha una riga di codice concreta, rispetto a quello OpenAPI. Due eccezioni:
* I finding senza endpoint (BF-005 e le viste DRF senza path) sono sempre conservati.
* Le regole in [`NON_EXCLUSIVE_RULES`](../src/core/api5_bfla/detector.py#L55) (oggi solo BF-007) **non competono** per il path e si affiancano al finding vincente, perché misurano una dimensione diversa (§4.4).

### 4.3. Autenticazione vs. autorizzazione

La distinzione centrale del modulo è tra *"chi sei"* e *"cosa puoi fare"*. Un endpoint con `@login_required` e nessun controllo di ruolo:
* su path privilegiato → **BF-001** (CRITICAL). Se il corpo contiene anche un'operazione sensibile, la deduplicazione lo riporta come **BF-002**, più specifica;
* su path ordinario con operazione distruttiva → **BF-002**;
* su path ordinario con operazione *bulk* → **BF-004** pattern B.

### 4.4. BF-007 — Taint leggero payload → assegnazione

[`privilege_escalation_payload.py`](../src/core/api5_bfla/rules/privilege_escalation_payload.py) è la prima regola del modulo che segue un **flusso di dati** invece di cercare la sola presenza di un segnale. L'analisi è intra-procedurale e visita il corpo dell'handler in ordine di sorgente:

* **Sorgenti (payload)**:
  * Python: `request.json`, `request.get_json()`, `request.form`, `request.data`, `request.values`, `request.POST`, e i parametri FastAPI tipizzati con un modello (Pydantic/DTO). Sono esclusi i parametri con default `Depends(`, `Security(`, `Query(`, …
  * Express: `req.body`, anche tramite destrutturazione (`const { role } = req.body`).
* **Campi di privilegio** (configurabili in `PRIVILEGE_FIELDS`): `role`, `is_admin`, `is_staff`, `permissions`, `group`, `scope`, `admin`, `privilege` e gli alias camelCase `isAdmin`, `isStaff`.
* **Propagazione**: `data = request.get_json() or {}` rende `data` una variabile-payload; `new_role = data.get("role")` rende `new_role` contaminata. Se la variabile viene riassegnata a un letterale, la contaminazione decade.
* **Sink (assegnazioni)**:
  * assegnazione diretta `obj.role = …` / `obj["role"] = …`;
  * `setattr(obj, "is_admin", …)`;
  * keyword argument su chiamate e costruttori (`.update(role=…)`, `Invite(role=…)`, `.create(role=…)`);
  * dizionari o oggetti letterali passati a `update`/`create`;
  * SQL `UPDATE … SET role = …` con parametri contaminati, anche in template string JS.
* **Esclusioni (falsi positivi)**: gli argomenti di chiamate di sola lettura (`filter`, `filter_by`, `where`, `find*`, `count`, …), i criteri keyword dei lookup (`.get(role=…)`, `get_or_404`) e le clausole `where:` di Sequelize. Un campo usato solo per filtrare non è un'assegnazione.
* **Guardia sul chiamante**: la regola viene soppressa da un decorator o middleware di ruolo. La sopprime anche una condizione `if`/`elif`/`assert` che interroga il privilegio del **chiamante** (`current_user.is_admin`, `req.user.role`, `g.user.permissions`, …), oppure una chiamata `check_permission(`/`has_role(`/`can_grant(`. Un'autenticazione generica **non** basta.

BF-007 è *non esclusiva* (§4.2). Sull'endpoint `PUT /users/<id>/role` del fixture vulnerabile coesiste con BF-002: BF-002 segnala che la funzione è invocabile da qualsiasi utente autenticato, BF-007 che il valore assegnato è scelto dal chiamante.

---

## 5. Validazione Ground Truth e Risultati

La validazione in cieco è eseguibile con [`tests/unit/api5_bfla/validate_ground_truth.py`](../tests/unit/api5_bfla/validate_ground_truth.py) (`--crapi <path>` opzionale) ed è verificata in CI da `test_ground_truth.py`. I fixture si trovano in [`data/test_targets/broken_function_level_authorization`](../data/test_targets/broken_function_level_authorization).

### 5.1. Fixture sintetici

| Regola | Endpoint vulnerabile (`vulnerable_app`) | Mitigazione (`secure_app`) |
| :--- | :--- | :--- |
| BF-001 | `DELETE /admin/users/<id>` senza guardie | `@login_required` + `@require_role("admin")` |
| BF-002 | `PUT /users/<id>/role` con solo `@login_required` | Aggiunta di `@require_role("admin")` |
| BF-003 | `@app.route("/admin/config")` senza `methods` | `methods=["GET"]` + ruolo |
| BF-004 | Blueprint `/admin` senza `before_request`; `GET /api/users/export_all` con sola auth | `before_request` con ruolo; `@require_role` sull'export |
| BF-005 | `settings.py` senza `DEFAULT_PERMISSION_CLASSES` | `IsAuthenticated` come default |
| BF-006 | `GET /debug/token-info`, `POST /test/create-admin` | Endpoint rimossi |
| BF-007 | `POST /api/invites/new` con `role=payload.get("role")` e sola auth | Verifica `current_user.is_admin` se il ruolo richiesto ≠ `user`; `POST /api/users/search` usa `role` solo come filtro |

### 5.2. Risultati

| Data | Target | TP | TN | FP | FN | TPR | FPR | Stato |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| 2026-06-26 | vulnerable_app & secure_app (BF-001→006) | 6 | 1 | 0 | 0 | 100.0% | 0.0% | Superato ✅ |
| 2026-09-25 | vulnerable_app & secure_app (BF-001→007) | 7 | 1 | 0 | 0 | 100.0% | 0.0% | Superato ✅ |

Suite `pytest tests/unit/api5_bfla`: **61 test, tutti verdi**. Di questi, 33 sono dedicati a BF-007:
* 9 casi vulnerabili Python e 4 JavaScript, uno per ogni tipo di sink;
* 10 casi sicuri Python e 4 JavaScript (filtro di sola lettura, confronto, decorator di ruolo, guardia inline, letterale, campo non privilegiato, funzione non-rotta, `Depends`, riassegnazione, clausola `where`);
* i test di coesistenza con BF-002 e di invarianza della deduplicazione.

Dopo l'aggiunta di BF-007 i sei finding preesistenti su `vulnerable_app` sono identici a quelli della baseline.

### 5.3. Verifica su repository reale (`repo_target`)

`analyze("data/test_targets/repo_target", openapi.yaml)` restituisce **3 finding BF-006 (HIGH, 0.90)** sugli endpoint del [`cooperative_harness.py`](../data/test_targets/repo_target/cooperative_harness.py):

| Finding riportato | Metodo reale | Riga |
| :--- | :--- | :---: |
| `GET /test/seed` | `POST` | 49 |
| `GET /test/snapshot` | `GET` / `POST` | 72 |
| `GET /test/rollback` | `POST` | 81 |

Sono **veri positivi tecnici**: endpoint che modificano lo stato senza autenticazione né ruolo. Sono però **intenzionali**, perché costituiscono il contratto cooperante che l'orchestratore BOLA usa per seed, snapshot e rollback. Non compaiono falsi positivi sugli endpoint applicativi (`/api/invoices/{id}` con verifica owner/admin). L'analisi rivela anche un difetto di reporting: BF-006 riporta sempre `GET` come metodo (§6, punto 5).

---

## 6. Limiti Noti e Possibili Estensioni

1. **Controlli di ruolo "cosmetici"**: `has_inline_role_check` è un match testuale. Un `logger.info(f"role: {user.role}")`, o un `if` che non interrompe il flusso, sopprime BF-001/002/004 come se fosse una guardia reale. Anche la guardia di BF-007 verifica la condizione ma non il ramo. → *Fase 4 (Guard Validity Engine)*.
2. **Schemi di sola autenticazione nella spec**: nel Layer 3 qualunque `security` non vuoto (anche solo `bearerAuth`) sopprime BF-001, benché dichiari autenticazione e non autorizzazione di funzione. → *Fase 5 (BF-011, granularità degli scope OAuth2)*.
3. **Viste class-based**: le regole AST visitano funzioni decorate e chiamate Express. Le `APIView`/`ViewSet` Django, i controller NestJS e i router class-based non sono coperti. → *Fase 3 (BF-010)*.
4. **Autorizzazione orizzontale tra gruppi/tenant**: un utente del gruppo X che invoca funzioni del gruppo Y (`/orgs/{org_id}/…` senza confronto con `current_user.org_id`) non viene rilevato. → *Fase 2 (BF-008)*.
5. **Metodo HTTP in BF-004/BF-006**: sul ramo AST Python i finding riportano sempre `GET`, indipendentemente dal verbo reale del decorator (§5.3). L'endpoint resta corretto e la chiave di deduplicazione (solo path) non ne risente, ma il metodo mostrato in dashboard può essere errato.
6. **Analisi intra-procedurale**: BF-007 non segue il payload attraverso funzioni helper, service layer o serializer (DRF `serializer.save()`). Il mass assignment generico (`user.update(**request.json)`) è volutamente lasciato ad API3/BOPLA.
7. **Allowlist di ruoli assegnabili**: `if role not in ("user", "viewer"): abort(400)` è sicuro nella pratica, ma BF-007 lo segnala perché non verifica il chiamante. È un possibile falso positivo su endpoint di self-signup.
8. **Nessuna conferma runtime**: il modulo è puramente statico. A differenza del BOLA, non esiste un tester dinamico che invochi le funzioni privilegiate con il token di un utente a basso privilegio per ottenere la prova empirica sfruttata dal motore di correlazione.

---

## 7. Piano di Estensione in Corso

| Fase | Contenuto | Regola | CWE | Severità | Stato |
| :---: | :--- | :--- | :--- | :---: | :--- |
| 1 | Privilege Escalation via Payload | BF-007 | CWE-269 | CRITICAL | ✅ Completata (fixture + 33 test, TPR/FPR invariati) |
| 2 | Autorizzazione orizzontale/gerarchica insufficiente | BF-008 | CWE-863 | HIGH | ⏳ In attesa di conferma |
| 3 | Controller amministrativi non protetti (supporto `ClassDef`) | BF-010 | CWE-285 | HIGH | ⏳ |
| 4 | Guard Validity Engine su `has_inline_role_check` | — | — | — | ⏳ |
| 5 | Verifica granulare degli scope OAuth2 (Layer 3) | BF-011 | CWE-285 | HIGH | ⏳ |
| 6 | Integrazione: `RuleID`, nuova priorità di dedup, registro di copertura | — | — | — | ⏳ |

Priorità di deduplicazione prevista a fine piano, con BF-007 e verosimilmente BF-008 come regole non esclusive:

```
BF-007 > BF-006 > BF-010 > BF-004 > BF-003 > BF-002 > BF-008 > BF-001 > BF-011 > BF-005
```
