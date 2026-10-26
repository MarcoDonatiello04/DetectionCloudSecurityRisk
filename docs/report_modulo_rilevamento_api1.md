# Report Strutturato: Modulo di Rilevamento API1:2023 (BOLA)

Il modulo [`src/core/api1_bola`](../src/core/api1_bola) è il componente della piattaforma dedicato a **OWASP API1:2023 — Broken Object Level Authorization (BOLA)**, classificata come CWE-639 (*Authorization Bypass Through User-Controlled Key*). È l'unico modulo della piattaforma con due livelli completi: un livello **dinamico** (D-AST), che attacca il bersaglio in esecuzione e ne osserva le risposte, e un livello **statico**, che legge codice sorgente e contratto OpenAPI senza eseguire nulla.

> **Stato al 2026-09-27** — Livello dinamico: pipeline Discovery → Seeding → Attack con tre scenari di tampering, asserzioni differenziali e privilege matrix configurabile. Livello statico (nuovo): 5 regole OA-001→OA-005 su Flask, FastAPI ed Express, più l'incrocio con il contratto OpenAPI. La suite `tests/unit/api1_bola` conta **118 test verdi** (68 del livello dinamico, 50 del livello statico). Ground truth statica: **12 TP, 0 FN, 0 FP, app sicura pulita**; su `repo_target`, fuori campione, i verdetti statici concordano con le etichette del target. Nella stessa data è stato corretto un difetto del motore di correlazione, che trattava come conferma anche gli attacchi bloccati (§6.1).

---

## 1. Obiettivo ed Ambito di Analisi

Il BOLA chiede *"questo utente può accedere a **questo oggetto**?"*. Il BFLA (API5) chiede invece *"questo utente può invocare **questa funzione**?"*. Un endpoint BOLA è di solito autenticato e perfettamente legittimo come funzione: il difetto sta nel fatto che l'oggetto viene selezionato dall'ID inviato dal client senza verificare che appartenga al chiamante. Gli scenari coperti sono:
* **Lookup per solo ID**: `Order.query.get(order_id)` in un handler autenticato, senza filtro sull'owner.
* **Riferimento diretto senza identità**: l'ID arriva all'accesso all'oggetto in un handler privo di qualsiasi contesto di identità.
* **Incoerenza tra metodi**: la lettura della risorsa è filtrata sull'owner, la modifica o la cancellazione no.
* **Riferimenti annidati**: in `/projects/{id}/tasks/{task_id}` il progetto viene validato, il task no.
* **ID enumerabili**: interi sequenziali esposti senza guardia di autenticazione.
* **BOLA orizzontale e verticale a runtime**: un utente pari grado, o di rango inferiore, ottiene l'oggetto di un altro utente.

La categoria è **ibrida**. La componente strutturale (manca un legame tra oggetto e chiamante) è osservabile nel codice. La correttezza di un legame presente (campo giusto, confronto nel verso giusto, owner non falsificabile) dipende invece dal modello di dominio e si accerta solo eseguendo l'attacco. Per questo il modulo tiene entrambi i livelli e li collega tramite la stessa chiave di correlazione (§4.7).

---

## 2. Architettura dei Componenti

| Livello | Tecnica | Input | Output |
| :--- | :--- | :--- | :--- |
| **Statico — Layer 1 (AST)** | Parsing con **tree-sitter** (Python, JavaScript/TypeScript) + analisi del corpo degli handler | Sorgenti `.py`, `.js`, `.ts`, `.jsx`, `.tsx`, `.mjs`, `.cjs` | Finding OA-001→OA-005 |
| **Statico — Layer 3 (OpenAPI)** | Incrocio contratto ↔ finding AST | Specifica OpenAPI 3.x / Swagger 2.0 | Stato del contratto su ogni finding |
| **Statico — Spectral** *(esterno al modulo)* | Regola `owasp-api1-object-level-security` | Specifica OpenAPI | Operazioni su `{id}` senza `security` |
| **Dinamico (D-AST)** | Differential testing con tre identità reali, via proxy OWASP ZAP | Bersaglio in esecuzione, contratto cooperante, inventario endpoint, traffico catturato | Verdetto per endpoint/metodo/scenario |

```
src/core/api1_bola/
├── detector.py                      # [statico] Entry point analyze(): Layer 1 + Layer 3, dedup, report, to_domain_findings()
├── models.py                        # [statico] RuleID, RouteHandler, ObjectAccess, OwnershipCheck, ObjectAuthzFinding/Report
├── layers/
│   ├── layer1_ast.py                # [statico] Estrazione handler (Flask/FastAPI/Express), guardie, helper del file, regole
│   ├── ownership_facts.py           # [statico] Fatti di ownership dal corpo dell'handler (accessi, identità, legami)
│   └── layer3_openapi.py            # [statico] Stato del contratto: security_declared / security_missing / not_documented
├── rules/
│   ├── _common.py                   # Costruzione dei finding e chiave di correlazione
│   ├── missing_ownership_filter.py              # OA-001
│   ├── direct_object_reference_no_check.py      # OA-002
│   ├── inconsistent_authz_across_methods.py     # OA-003
│   ├── unvalidated_nested_object_reference.py   # OA-004
│   └── serial_id_no_authz_decorator.py          # OA-005
├── dynamic_orchestrator.py          # [dinamico] DynamicOrchestrator + ZapController: Discovery → Seeding → Attack
├── attack_vector.py                 # [dinamico] ContextAwareAttackGenerator: tre scenari di tampering + chiamata anonima
├── assertion_engine.py              # [dinamico] APIAssertionEngine: quattro asserzioni differenziali
├── role_matrix.py                   # [dinamico] AccessControlMatrix: gerarchia dei ruoli da config/bola.yaml
├── state_manager.py                 # [dinamico] APIStateEngine: snapshot/rollback tramite l'harness del bersaglio
├── target_config.py                 # [dinamico] Contratto cooperante (config/bola_target.yaml)
├── bola_config.py                   # [dinamico] Accesso condiviso a config/bola.yaml
├── discovery/
│   ├── object_discovery.py          # [dinamico] ObjectReferenceDiscoveryEngine: ID in path/query/body del traffico
│   └── ownership_inference.py       # [dinamico] OwnershipInferenceEngine: identità e risorse possedute dal traffico
└── docs/
    └── owasp_api1_coverage.md       # Registro formale di copertura e validazione del livello statico
```

Componenti esterni al modulo che partecipano al rilevamento: [`identity_context.py`](../src/core/identity_context.py) (`IdentityManager`, `DatabaseSeeder`), la regola Spectral in [`spectral-owasp.yaml`](../config/scanner_configs/spectral-owasp.yaml#L10) con la mappatura in [`spectral_adapter.py`](../src/infrastructure/adapters/spectral_adapter.py#L182), e il [`RiskCorrelationEngine`](../src/application/correlation/engine.py).

### 2.1. Ruolo dei moduli del livello statico

* [`detector.py`](../src/core/api1_bola/detector.py): [`analyze(target_path, openapi_spec=None, enrich_spec=False)`](../src/core/api1_bola/detector.py#L128) esegue sempre il Layer 1 e, se riceve una specifica, il Layer 3. Deduplica per handler e metodo e costruisce `coverage_signals` e `summary` (conteggi per severità, regola, layer, stato del contratto e handler; `spectral_blind_spot` conta i finding su operazioni che dichiarano `security`). [`to_domain_findings()`](../src/core/api1_bola/detector.py#L173) converte il report nel `Finding` di dominio con sorgente `STATIC_ANALYZER`, categoria `AUTHORIZATION`, `owasp_api_category="API1:2023"`, natura `EXPOSURE` e un ID deterministico calcolato sul path relativo al target.
* [`models.py`](../src/core/api1_bola/models.py): [`RuleID`](../src/core/api1_bola/models.py#L19) elenca OA-001→OA-005. [`RouteHandler`](../src/core/api1_bola/models.py#L66) è la rappresentazione intermedia di un handler: path, metodi, parametri ID (e quali sono numerici), guardie, accessi agli oggetti ([`ObjectAccess`](../src/core/api1_bola/models.py#L44)), controlli di ownership ([`OwnershipCheck`](../src/core/api1_bola/models.py#L56)), parametri validati e parametri legati. [`ObjectAuthzFinding`](../src/core/api1_bola/models.py#L113) riprende i campi di `FunctionAuthzFinding` di API5 e aggiunge `id_parameter`, `correlation_key`, `contract_status` e `related_rules`.
* [`layer1_ast.py`](../src/core/api1_bola/layers/layer1_ast.py): percorre il target saltando `node_modules`, `.venv`, `dist` e le altre directory di build, oltre ai file binari, vuoti o sopra 1 MB. Estrae gli handler, classifica le guardie e riassume le funzioni di supporto dello stesso file. Poi esegue le regole sull'insieme di tutti gli handler, perché OA-003 confronta handler diversi della stessa risorsa.
* [`ownership_facts.py`](../src/core/api1_bola/layers/ownership_facts.py): legge il corpo dell'handler istruzione per istruzione e produce i fatti su cui ragionano le regole (§4.2).
* [`layer3_openapi.py`](../src/core/api1_bola/layers/layer3_openapi.py): per ogni finding AST cerca l'operazione corrispondente nel contratto e ne registra lo stato (§4.4).

### 2.2. Ruolo dei moduli del livello dinamico

* [`dynamic_orchestrator.py`](../src/core/api1_bola/dynamic_orchestrator.py): [`DynamicOrchestrator.run_dast_pipeline()`](../src/core/api1_bola/dynamic_orchestrator.py#L732) riceve l'inventario degli endpoint e lo divide in dinamici (con `{id}`) e statici. Ottiene le identità, esegue il seeding e affida gli attacchi a [`ZapController.run_differential_scan()`](../src/core/api1_bola/dynamic_orchestrator.py#L323). Infine converte ogni esito in un `Finding` `RUNTIME_VALIDATOR`: `dynamic-bola-exploited` (HIGH) se vulnerabile, `dynamic-test-secure` (INFO) se sicuro. La cancellazione è un `threading.Event` per istanza, quindi due scansioni concorrenti non interferiscono.
* [`attack_vector.py`](../src/core/api1_bola/attack_vector.py): [`execute_tampering()`](../src/core/api1_bola/attack_vector.py#L202) esegue i tre scenari di §3.2 per ogni endpoint e metodo. Per ciascuno invia tre richieste attraverso ZAP: il proprietario, l'attaccante con il proprio token sulla risorsa della vittima, e un anonimo. Sostituisce gli ID nel path (l'ultimo `{id}` è l'oggetto bersaglio, i precedenti ricevono l'UUID del proprietario), nella query e nel body.
* [`assertion_engine.py`](../src/core/api1_bola/assertion_engine.py): [`evaluate_bola_assertion()`](../src/core/api1_bola/assertion_engine.py#L121) decide se l'attacco è riuscito (§4.6).
* [`role_matrix.py`](../src/core/api1_bola/role_matrix.py): [`AccessControlMatrix.validate_access_legitimacy()`](../src/core/api1_bola/role_matrix.py#L85) confronta i ranghi dei ruoli letti da `config/bola.yaml`. Il rango massimo ha accesso legittimo a tutto; a pari rango l'accesso è BOLA orizzontale; da rango inferiore a superiore è BOLA verticale; da rango superiore a inferiore è legittimo. Un ruolo non censito viene degradato al rango minimo, con un warning.
* [`state_manager.py`](../src/core/api1_bola/state_manager.py): chiama gli endpoint `/test/snapshot` e `/test/rollback` dell'harness cooperante prima e dopo ogni metodo che può mutare lo stato (POST, PUT, PATCH, DELETE).
* [`target_config.py`](../src/core/api1_bola/target_config.py): carica [`config/bola_target.yaml`](../config/bola_target.yaml), che raccoglie URL del bersaglio, host interno per ZAP, endpoint dell'harness, identity provider (`keycloak`, `static_tokens` o `traffic`) e le tre identità `victim`, `peer`, `privileged`. Le credenziali arrivano solo da variabili d'ambiente (ADR-003).
* [`object_discovery.py`](../src/core/api1_bola/discovery/object_discovery.py) e [`ownership_inference.py`](../src/core/api1_bola/discovery/ownership_inference.py): in Assessment Mode ricavano dal traffico catturato gli ID presenti in path, query e body, e costruiscono la mappa *identità → risorse possedute* decodificando i JWT (senza verificarne la firma, trattandosi di traffico osservato).

---

## 3. Matrice delle Regole di Rilevamento

### 3.1. Regole statiche

| Regola | CWE | Severità | Confidenza | Categoria | Linguaggi | Descrizione Operativa |
| :--- | :--- | :---: | :---: | :--- | :--- | :--- |
| **OA-001** | CWE-639 | HIGH | 0.75 | `missing_ownership_filter` | Flask, FastAPI, Express | Handler autenticato (guardia o identità letta prima dell'accesso) che recupera o modifica l'oggetto usando solo l'ID del client, senza filtro, confronto, helper o decorator di ownership. |
| **OA-002** | CWE-639 | HIGH | 0.70 | `direct_object_reference_no_check` | Flask, FastAPI, Express | Come OA-001, ma senza alcun contesto di identità prima dell'accesso: nessuna guardia di autenticazione e nessuna lettura dell'identità. |
| **OA-003** | CWE-639 | HIGH | 0.85 | `inconsistent_authz_across_methods` | Flask, FastAPI, Express | Stessa risorsa (path normalizzato e linguaggio): almeno un metodo lega l'oggetto al chiamante, un altro no. Segnale più forte di OA-001, perché il codice dimostra che l'ownership era un requisito noto. |
| **OA-004** | CWE-639 | HIGH | 0.70 | `unvalidated_nested_object_reference` | Flask, FastAPI, Express | Path con due o più ID: un ID è validato contro l'owner, un altro è usato per accedere a un oggetto senza essere legato né al chiamante né all'oggetto validato. |
| **OA-005** | CWE-639 | MEDIUM | 0.60 | `serial_id_no_authz_decorator` | Flask, FastAPI, Express | ID intero (`<int:id>`, `id: int`, `:id(\d+)`, o convertito con `int()`/`parseInt()`/`Number()`) usato per accedere a un oggetto in un handler senza guardia di autenticazione. Misura la predicibilità dell'ID: non compete in deduplicazione. |
| *Spectral* `owasp-api1-object-level-security` | — | error | — | contratto | OpenAPI | Operazioni `get`/`put`/`patch`/`delete` su path con `{…}` prive di requisito `security`. Mappata su `AUTHORIZATION` con chiave `api:METODO:path`. |

Il Layer 3 aggiunge **+0.10** di confidenza (tetto 0.95) quando il contratto dichiara `security` per l'operazione: il codice smentisce una garanzia che il contratto promette.

### 3.2. Scenari dinamici

| Scenario | Proprietario della risorsa | Attaccante | Esito atteso su un endpoint sicuro |
| :--- | :--- | :--- | :--- |
| **BOLA Orizzontale** | victim (`user`) | peer (`user`) | Bloccato |
| **BOLA Verticale** | privileged (`admin`) | victim (`user`) | Bloccato |
| **Privilegio Legittimo** | victim (`user`) | privileged (`admin`) | Consentito (SAFE per la privilege matrix) |
| **Broken Auth** (per ciascuno dei tre) | come sopra | anonimo | Bloccato; `200`/`204` all'anonimo è segnalato come vulnerabile |

---

## 4. Dettagli di Funzionamento del Motore di Analisi

### 4.1. Estrazione degli handler (Layer 1)

Il riconoscimento avviene sull'albero sintattico di tree-sitter, non su regex applicate al file:
* **Flask/FastAPI**: `decorated_definition` con decorator `X.route(...)`, `X.api_route(...)` o `X.get/post/put/patch/delete(...)`, più le registrazioni `app.add_url_rule(path, view_func=f, methods=[…])`. I prefissi vengono da `Blueprint(url_prefix=…)`, `APIRouter(prefix=…)` e `register_blueprint(bp, url_prefix=…)`. Le dipendenze FastAPI `Depends(get_current_user)` nei parametri, o `dependencies=[…]` sul router o sulla rotta, contano come autenticazione; il parametro iniettato diventa una variabile d'identità.
* **Express**: `call_expression` `X.<verbo>(path, …middleware, handler)`. L'handler può essere inline o una funzione nominata dello stesso file. I prefissi di montaggio vengono da `app.use("/api", router)`. Il nome del parametro request (`req`, `request`, …) è letto dalla firma.
* **Parametri ID**: un parametro di path è un riferimento a un oggetto se è tipizzato come intero o se il suo nome supera la stessa euristica usata a runtime da `ObjectReferenceDiscoveryEngine.is_id_field` (`id`, `*_id`, `*Id`, `uuid`, `guid`, più `pk` e `slug`). `/files/<path:filename>` o `/search/<term>` non vengono analizzati.
* **Guardie**: i decorator e i middleware vengono classificati come autenticazione (`login_required`, `jwt_required`, `authenticate`, `verifyJWT`, …), ownership (`owner_required`, `object_permission`, `isOwner`, `checkOwnership`, …) o ruolo privilegiato (`admin_required`, `requireAdmin`, `roles_required("admin")`, …). Un `@app.before_request` che impone l'autenticazione, o un `app.use(authenticate)`, autentica tutte le rotte del file.

### 4.2. Fatti di ownership (Layer 1)

[`ownership_facts.py`](../src/core/api1_bola/layers/ownership_facts.py) rimuove commenti e docstring e ricompone le istruzioni su più righe (chiamate e oggetti letterali passati come argomento). Poi legge il corpo in ordine:
* **Accesso a un oggetto**: una chiamata di lettura o scrittura (`get`, `get_or_404`, `filter_by`, `find_one`, `execute`, `delete`, `findById`, `findOne`, `findByIdAndUpdate`, …) o un subscript (`ORDERS[order_id]`) che contiene un ID di path, direttamente o tramite alias (`oid = int(order_id)`, `const { orderId } = req.params`). I nomi dentro i letterali stringa non contano.
* **Identità del chiamante**: `current_user`, `g.user`, `request.user`, `get_jwt_identity()`, `session["user_id"]`, `req.user`, `req.auth`, `res.locals.user`, le funzioni il cui nome indica l'estrazione dell'identità (`extract_identity(request)`, `getCurrentUser(req)`) purché non ricevano un ID di path, e le variabili derivate (`username = get_jwt_identity()`, `for owned in current_user.orders`).
* **Legame oggetto → chiamante** (un `OwnershipCheck`):
  * *query filtrata*: l'identità compare tra gli argomenti della catena di accesso o nel ricevitore (`filter_by(id=order_id, owner_id=current_user.id)`, `current_user.orders.filter_by(id=…)`, `findOne({ _id: …, owner: req.user.id })`);
  * *confronto*: una clausola di confronto che contiene l'identità e, tolta l'identità, un campo owner, l'ID o l'oggetto (`order.owner_id != current_user.id`, `user_id != str(current_user.id)`). Le condizioni composte vengono spezzate su `and`/`or`/`&&`/`||`, così `not current_user.is_authenticated or order_id is None` non conta come legame;
  * *helper*: `check_ownership(…)`, `authorize(…)`, `has_object_permission(…)`, `isOwner(…)`, …;
  * *decorator*: guardia di ownership sull'handler.
* **Legami tra ID** (path annidati): un ID è *legato* se il suo accesso cita un ID o un oggetto già validato (`filter_by(id=task_id, project_id=project.id)`, `order.items.get(item_id)`) o se un confronto lo aggancia a esso (`item.order_id != order.id`). La propagazione prosegue fino a punto fisso.
* **Funzioni di supporto dello stesso file** (un livello): ogni funzione che non è un handler viene riassunta trattando i suoi parametri come possibili ID. Il riassunto registra quali parametri usa per accedere a oggetti, quali lega al chiamante, se legge l'identità e che ruolo hanno i valori restituiti. Alla chiamata `username, owner, err = _load_resource("projects", id)` l'handler eredita l'accesso guidato da `id`, la lettura dell'identità, `username` come identità e `owner` come oggetto.

### 4.3. Deduplicazione

Più regole possono colpire lo stesso handler sullo stesso metodo (OA-003 e OA-001 sulla `DELETE` non protetta). [`deduplicate_findings()`](../src/core/api1_bola/detector.py#L53) raggruppa per **file + chiave di correlazione** e tiene la regola con priorità più alta:

```
OA-003 > OA-004 > OA-001 > OA-002          (OA-005 non esclusiva)
```

Le regole assorbite restano in `related_rules`. Il file entra nella chiave perché due servizi della stessa repository possono esporre lo stesso path (nelle fixture, Flask ed Express): sono implementazioni distinte, non duplicati. Ogni finding riguarda un solo metodo, perché la chiave `api:METODO:path` è per metodo.

### 4.4. Layer 3 e punto cieco della regola Spectral

[`analyze_openapi()`](../src/core/api1_bola/layers/layer3_openapi.py#L104) indicizza le operazioni per metodo e path normalizzato (con un confronto per suffisso che tollera `servers`/basePath diversi) e calcola il `security` effettivo: quello dell'operazione, altrimenti quello globale. `[]` e `[{}]` (autenticazione opzionale) non contano come requisito. Ogni finding AST riceve uno stato:

| `contract_status` | Significato | Rapporto con Spectral |
| :--- | :--- | :--- |
| `security_declared` | Il contratto richiede autenticazione, il codice non lega l'oggetto al chiamante | **Punto cieco**: la regola Spectral passa. Confidenza +0.10 |
| `security_missing` | Anche il contratto è scoperto | Si somma al finding Spectral sulla stessa chiave |
| `not_documented` | L'handler non compare nel contratto | Possibile shadow endpoint; neppure il runner dinamico lo attacca (§5.3) |

Con `enrich_spec=True` i finding vengono scritti nella specifica sotto `x-security-analysis.api1_findings`.

### 4.5. Pipeline dinamica: Discovery → Seeding → Attack

1. **Discovery**: gli endpoint arrivano dall'inventario della pipeline (Semgrep/Spectral) o, con [`run_bola_repo_target.py`](../entrypoints/runners/run_bola_repo_target.py), dalla specifica OpenAPI del bersaglio. Vengono normalizzati su `{id}` e raggruppati per path; nei path annidati l'oggetto bersaglio è l'ultimo `{id}`. Il traffico catturato, se presente, aggiunge endpoint e riferimenti a oggetti.
2. **Identità e seeding**, in due modalità:
   * *Lab Mode* (provider `keycloak` o `static_tokens`): `IdentityManager` ottiene i token delle tre identità. `DatabaseSeeder` popola il bersaglio tramite `/test/seed`; gli ID restituiti dall'harness hanno la precedenza sull'UUID dell'identità. Snapshot e rollback sono attivi.
   * *Assessment Mode* (provider `traffic` o flag esplicito): identità, ruoli e ID posseduti sono inferiti dal traffico. Non c'è seeding né rollback, quindi PUT/PATCH/DELETE vengono esclusi salvo `allow_mutations`.
3. **Attack**: per ogni endpoint vengono esercitati i metodi dichiarati dall'inventario, oppure tutti e cinque con `--all-methods`. Per i metodi che possono mutare lo stato si fa snapshot prima e rollback dopo. Su ogni esito vulnerabile ZAP lancia uno scan attivo sull'URL.

### 4.6. Asserzioni differenziali

[`APIAssertionEngine`](../src/core/api1_bola/assertion_engine.py#L29) confronta la risposta del proprietario con quella dell'attaccante tramite quattro asserzioni:
* **status**: `401`/`403` → bloccato;
* **keyword**: una risposta `2xx` che contiene `access denied`, `forbidden`, `non autorizzato`, `error_code`, … è un blocco mascherato; ogni risposta non-`2xx` è considerata bloccata;
* **somiglianza strutturale**: i body JSON sono uguali dopo aver rimosso i campi volatili dichiarati in `config/bola.yaml` (`accessed_by`, `timestamp`, `updated_at`, …), non per lunghezza in byte;
* **riferimento alla vittima**: il body `2xx` dell'attaccante contiene l'ID della risorsa della vittima.

L'attacco ha successo tecnico se non è bloccato né da status né da keyword e almeno una delle ultime due asserzioni è vera. Il verdetto finale arriva dalla privilege matrix: successo tecnico con accesso legittimo → SAFE; successo tra pari → BOLA ORIZZONTALE; successo verso rango superiore → BOLA VERTICALE.

### 4.7. Correlazione statico–dinamico

Il finding statico (OA-00x), il finding Spectral API1 e i finding runtime usano la stessa chiave `api:METODO:<path normalizzato>`. Il test [`test_runtime_confirmation_elevates_static_finding`](../tests/unit/api1_bola/test_static_detector.py) verifica che, dato un OA-001 su `GET /api/orders/<order_id>` e una conferma runtime su `GET /api/orders/101`, il `RiskCorrelationEngine` unisca i due in un'unica voce: resta l'OA-001, portato a **CRITICAL** con confidenza 1.0 e con il finding runtime tra i `related_findings`. Se invece il runtime attesta che l'attacco è stato bloccato (`dynamic-test-secure`), l'esito è una **smentita**: la severità resta invariata, la confidenza viene dimezzata, non viene allegata `runtime_evidence` e il dettaglio finisce in `raw_data["runtime_refutations"]`. Una conferma sulla stessa chiave prevale sempre, in qualunque ordine arrivino gli esiti (§6.1).

---

## 5. Validazione e Risultati

La validazione statica è eseguibile con [`tests/unit/api1_bola/validate_static_ground_truth.py`](../tests/unit/api1_bola/validate_static_ground_truth.py) ed è verificata da `test_static_ground_truth.py`. Le fixture si trovano in [`data/test_targets/broken_object_level_authorization`](../data/test_targets/broken_object_level_authorization). Il registro formale è [`owasp_api1_coverage.md`](../src/core/api1_bola/docs/owasp_api1_coverage.md).

### 5.1. Fixture sintetici

Ogni caso esiste sia nel servizio Flask (`app.py`) sia in quello Express (`server.js`); ogni app ha anche il proprio `openapi.yaml`.

| Regola | Endpoint vulnerabile (`vulnerable_app`) | Mitigazione (`secure_app`) |
| :--- | :--- | :--- |
| OA-001 | `GET /api/orders/{id}` autenticato, lookup per solo ID | Query filtrata su `owner_id = current_user.id` / `owner: req.user.id` |
| OA-002 | `GET /api/invoices/{id}` senza guardia | Guardia di autenticazione + confronto owner (Flask) / filtro nella `find` (Express) |
| OA-003 | `GET /api/documents/{id}` filtrato, `DELETE` (Flask) / `PUT` (Express) no | Stesso filtro su tutti i metodi |
| OA-004 | `GET /api/projects/{id}/tasks/{id}`: progetto validato, task cercato per solo ID | Task cercato dentro il progetto validato |
| OA-005 | `GET /api/receipts/{int}` senza guardia (anche OA-002) | Guardia + lookup sulla collezione dell'utente |
| *controllo negativo* | `GET /api/profiles/{id}` con confronto ID ↔ identità | identico |
| *controllo negativo* | `DELETE /api/admin/users/{int}` con guardia admin (dominio API5) | identico |

### 5.2. Risultati

| Data | Target | TP | FN | FP | TN | TPR | Precision | Stato |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| 2026-09-27 | vulnerable_app & secure_app (OA-001→005, Flask + Express) | 12 | 0 | 0 | 1 | 100.0% | 100.0% | Superato ✅ |

Il confronto è per tupla `(file, regola, metodo, path)`: un finding con la regola giusta sull'endpoint sbagliato conta come FP + FN. Layer 3 sulla fixture vulnerabile: 4 `security_declared`, 6 `security_missing`, 2 `not_documented`. I 4 `security_declared` (OA-001 sugli ordini, OA-003 sui documenti, in entrambi i servizi) sono operazioni su cui la regola Spectral passa.

Suite `pytest tests/unit/api1_bola`: **118 test, tutti verdi**.

| Gruppo | Test | Contenuto |
| :--- | :---: | :--- |
| Livello dinamico | 68 | `test_dynamic_orchestrator` (13), `test_role_matrix` (12), `test_target_config` (12), `test_identity_context` (9), `test_bola` (8), `test_attack_vector` (6), `test_assessment_mode_e2e` (3), `test_target_reachability` (3), `test_object_discovery` (1), `test_ownership_inference` (1). ZAP e le chiamate HTTP sono simulati. |
| Livello statico | 50 | `test_static_rules` (27): casi positivi e varianti costruite per ingannare le euristiche (commenti e docstring, condizioni che citano identità e ID senza legarli, loop sulla collezione dell'utente, helper, ruolo privilegiato, nomi dentro stringhe); `test_static_layer1` (9); `test_static_layer3` (6); `test_static_detector` (6), inclusa la correlazione con il runtime; `test_static_ground_truth` (2). |

Per controllare che i test abbiano presa sul codice sono state applicate sette mutazioni mirate, una alla volta: rimozione della pulizia dei commenti, della divisione delle clausole, dei legami tra ID, dello scoping sul ricevitore, dell'identità derivata dai loop, del mascheramento delle stringhe e dei riassunti delle funzioni di supporto. Ciascuna fa fallire almeno un test. Quella sul mascheramento delle stringhe, alla prima prova, non ne faceva fallire nessuno: è stato aggiunto `test_id_name_inside_string_literal_is_not_an_access`.

### 5.3. Verifica fuori campione (`repo_target`)

Fixture e regole hanno lo stesso autore, quindi il 100% sulle fixture non basta. [`repo_target`](../data/test_targets/repo_target/app.py) non è stato scritto per il livello statico e dichiara nel docstring le proprie etichette: `/api/projects/{id}` VULNERABILE, `/api/invoices/{id}` PROTETTA (owner == richiedente, admin ammesso).

| Endpoint | Etichetta | Livello statico | Esito |
| :--- | :--- | :--- | :---: |
| `GET/PUT/PATCH/DELETE /api/projects/{id}` | VULNERABILE | OA-001 su ciascun metodo, evidenza `_load_resource("projects", id)` (riga 69) | TP ✅ |
| `GET/PUT/PATCH/DELETE /api/invoices/{id}` | PROTETTA | nessun finding | TN ✅ |
| `POST /api/projects/{id}/import` | non etichettato per API1 | OA-001 (riga 120): qualunque utente autenticato sovrascrive l'owner del progetto `id` | da confermare |

Il Layer 3 classifica `GET`, `PUT`, `DELETE` e l'import come `security_missing` (il contratto del target non dichiara `security`), quindi si sommano alla regola Spectral. `PATCH /api/projects/{id}` risulta invece `not_documented`: la specifica non lo dichiara, e il runner dinamico, che costruisce l'inventario dalla specifica, non lo attacca. È un metodo vulnerabile che solo il livello statico raggiunge.

La prima esecuzione segnalava anche `invoices` (come OA-002). Identità e lookup stanno infatti nell'helper `_load_resource()`, che l'analisi limitata al corpo dell'handler non vedeva. Il caso ha portato ai riassunti delle funzioni dello stesso file (§4.2). `POST /api/projects/{id}/import` compare nel contratto del target ma solo con il metodo `post`, che l'orchestratore esercita; va quindi verificato con una scansione dinamica prima di etichettarlo.

### 5.4. Altri target

| Target | Handler | Con ID | Finding | Lettura |
| :--- | :---: | :---: | :---: | :--- |
| `broken_function_level_authorization` (fixture API5) | 14 | 4 | 3 | `DELETE /admin/users/<int>` senza guardie (OA-002 + OA-005) e `PUT /users/<int>/role` solo autenticato (OA-001): sovrapposizione attesa con BF-001/BF-002. App sicura: 0 finding |
| `bola` (target del livello dinamico) | 3 | 0 | 0 | Rotta catch-all `/<path:path>`: gli ID esistono solo a runtime, fuori portata statica |
| `crapi_repo` | 8 | 0 | 0 | **Nessuna copertura statica** (§6.2) |

---

## 6. Limiti Noti e Possibili Estensioni

### 6.1. Difetto corretto: un esito runtime SAFE elevava il finding statico

**Il problema.** `RiskCorrelationEngine.correlate()` trattava **ogni** finding runtime con la stessa chiave come una conferma: portava la severità da HIGH a CRITICAL e la confidenza a 1.0, senza guardare l'esito. Il livello dinamico, però, produce per ogni endpoint testato anche finding `dynamic-test-secure` (severità INFO): gli attacchi bloccati e, sempre, lo scenario *Privilegio Legittimo*. Il percorso della CLI ([`main.py`, riga 204](../src/presentation/cli/main.py#L204)) passa tutti i finding dinamici al motore senza filtrarli. Un falso positivo statico, smentito dall'attacco, usciva quindi dalla pipeline come CRITICAL con confidenza massima e con `runtime_evidence` allegata, che nel catalogo della CLI significa "VULNERABLE". Lo stesso accadeva al finding Spectral API1, che usa la stessa chiave.

**La correzione (2026-09-27)**, in [`engine.py`](../src/application/correlation/engine.py#L98):
* i finding runtime vengono divisi in **conferme** e **smentite**; sono smentite gli esiti `RUNTIME_VALIDATOR` con regola in `RUNTIME_REFUTATION_RULES` (oggi `dynamic-test-secure`);
* le conferme seguono il percorso di prima, senza modifiche;
* le smentite vengono applicate dopo tutte le conferme, da [`_apply_refutation()`](../src/application/correlation/engine.py#L163). Su una voce statica mai confermata: severità invariata, confidenza moltiplicata per `REFUTED_CONFIDENCE_FACTOR` (0.5, una sola volta), `raw_data["runtime_refuted"] = True`, dettagli in `raw_data["runtime_refutations"]`, nessuna `runtime_evidence`. Se la chiave ha anche una conferma, o la voce è già runtime, la smentita viene solo collegata in `related_findings`. Senza voce corrispondente, l'esito sicuro resta una voce a sé, come prima.

Stesso input prima e dopo: un OA-001 su `GET /api/orders/<order_id>` (HIGH, 0.75) e un finding `dynamic-test-secure` su `GET /api/orders/1` (INFO, "Endpoint Sicuro (403)"). Output reale di `correlate()`, come `(rule_id, severity, confidence, nature, runtime_refuted, runtime_evidence)`:

```
prima:  [('OA-001', 'CRITICAL', 1.0, <FindingNature.EXPOSURE: 'EXPOSURE'>)]
dopo:   [('OA-001', 'HIGH', 0.38, <FindingNature.EXPOSURE: 'EXPOSURE'>, True, None)]
```

Regressione coperta da [`tests/unit/test_correlation_refutation.py`](../tests/unit/test_correlation_refutation.py) (6 test): smentita semplice; conferma che prevale sulla smentita in entrambi gli ordini; più smentite che riducono la confidenza una sola volta; esito sicuro senza voce statica; esito sicuro che non eleva una vulnerabilità runtime. I test preesistenti sulla correlazione (`test_clean_arch`, `test_finding_nature`, `test_risk_scoring`, `test_spectral_adapter`) restano verdi senza modifiche.

**Resta da fare**: il catalogo per endpoint della CLI ([`main.py`, righe 295–335](../src/presentation/cli/main.py#L295)) non legge ancora `runtime_refuted`. Un finding statico smentito vi compare come `POTENTIAL` invece che `SAFE`.

### 6.2. Livello statico

1. **crAPI non è coperto**. I casi BOLA di crAPI stanno in servizi Java (identity), Go (community) e Django (workshop, class-based view che legge `request.GET["report_id"]`). Il Layer 1 legge solo Flask, FastAPI ed Express, e solo ID nel path. Su crAPI API1 resta interamente dinamica.
2. **ID in query string e nel body** non sono modellati come riferimenti a oggetti; lo sono solo a runtime (`ObjectReferenceDiscoveryEngine`).
3. **Analisi limitata al file**, con un livello di funzioni di supporto. Helper importati da altri moduli, middleware definiti altrove e service/repository layer non sono visibili: un controllo di ownership lì dentro produce un falso positivo OA-001/OA-002.
4. **Vocabolario per convenzione di nome**: identità, helper di ownership (`authorize(…)` è accettato senza verificarne il contenuto) e campi owner (`owner_id`, `userId`, `author`, `created_by`, …).
5. **Presenza, non correttezza**: `filter_by(owner_id=current_user.id)` è accettato anche se `owner_id` non è il campo che esprime davvero l'appartenenza. È il residuo che solo il runtime accerta.
6. **Ruolo privilegiato come esclusione**: un handler con guardia admin è considerato di dominio API5; il BOLA orizzontale tra amministratori non è modellato.
7. **Diramazioni per metodo**: in un handler Flask multi-metodo con `if request.method == …`, un controllo in un solo ramo copre tutti i metodi.
8. **Router Express annidati** a più livelli e `router.route(path).get(…)` non sono risolti.
9. **Non ancora integrato nei runner**: `detector.analyze()` non è registrato in `run_unified_core_scanners.py`, `server.py` e `run_all_validations.py`, quindi i finding OA-00x non arrivano ancora alla dashboard né al motore di correlazione della pipeline.

### 6.3. Livello dinamico

1. **Target cooperante richiesto**: in Lab Mode servono gli endpoint `/test/seed`, `/test/snapshot` e `/test/rollback`. In Assessment Mode il test dipende dalla qualità del traffico catturato e i metodi mutanti sono esclusi di default.
2. **Durata**: con snapshot/rollback reali una scansione dura decine di minuti. Con i soli metodi dichiarati il tempo scende di 3–5 volte rispetto a `--all-methods`.
3. **Assunzioni sul formato delle risposte**: il confronto strutturale presume body JSON (in alternativa ricade sull'uguaglianza testuale). Le keyword di blocco sono una lista fissa, in italiano e inglese.
4. **Copertura legata all'inventario**: il runner su repository attacca solo le operazioni dichiarate nella specifica. Gli endpoint e i metodi trovati dal livello statico come `not_documented` non vengono esercitati (su `repo_target`: `PATCH /api/projects/{id}`, §5.3).
5. **Broken Auth come effetto collaterale**: la chiamata anonima marca vulnerabile ogni `200`/`204`, anche su endpoint pubblici per design, e produce un finding `AUTHENTICATION` sulla stessa chiave della risorsa.

### 6.4. Estensioni proposte, in ordine di impatto

| Priorità | Estensione | Motivo |
| :---: | :--- | :--- |
| 1 | Registrazione del detector statico nei runner e nella dashboard | Oggi i finding OA-00x restano fuori dalla pipeline |
| 2 | Lettura di `runtime_refuted` nel catalogo per endpoint della CLI (§6.1) | Un rischio smentito deve comparire come SAFE, non come POTENTIAL |
| 3 | ID in query string (`request.args`, `request.GET`, `req.query`) | Primo passo verso crAPI (`report_id`) |
| 4 | Viste class-based Django/DRF (`urls.py` + `APIView`) | Coprirebbe il servizio workshop di crAPI; stessa esigenza di BF-010 in API5 |
| 5 | Inventario dinamico arricchito dagli endpoint `not_documented` del livello statico | Farebbe attaccare anche gli shadow endpoint |
| 6 | Esperimento statico vs dinamico su `repo_target` e crAPI | Misura della concordanza (conferme / smentite) per la tesi, ora che il motore le distingue |

---

## 7. Come Eseguire

```bash
# Livello statico: validazione sulle fixture
PYTHONPATH=. .venv/bin/python tests/unit/api1_bola/validate_static_ground_truth.py

# Tutti i test del modulo (statico + dinamico)
.venv/bin/python -m pytest tests/unit/api1_bola

# Livello dinamico su repository cooperante (target attivo, identity provider, ZAP)
make bola-repo-target
```

```python
from src.core.api1_bola import detector

report = detector.analyze("data/test_targets/repo_target",
                          openapi_spec=detector.load_spec("data/test_targets/repo_target/openapi.yaml"))
findings = detector.to_domain_findings(report)   # Finding di dominio, chiave api:METODO:path
```
