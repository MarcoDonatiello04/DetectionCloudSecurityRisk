# Report: Modulo di Rilevamento API3:2023 (Broken Object Property Level Authorization)

Riepilogo completo del modulo [`src/core/api3_bopla`](../src/core/api3_bopla), verificato sul
codice e con esecuzioni reali al **26/09/2026**. Sostituisce il report del 25/09 e il report
intermedio `report_api3_implementazione_e_limiti_statici.md`, che documentava i singoli
interventi del 26/09 (la loro storia è riassunta in Parte C).

- **Parte A**: come funziona il modulo oggi.
- **Parte B**: limiti che restano, statici e dinamici.
- **Parte C**: cronologia degli interventi e risultati sui bersagli.

---

# PARTE A — Implementazione

## A.1 Cosa rileva

La *Broken Object Property Level Authorization* riguarda la singola **proprietà** di un oggetto
che l'utente può legittimamente raggiungere. Le direzioni sono due:

- **lettura** (*excessive data exposure*, CWE-213): una proprietà riservata, come `salary`,
  viene restituita a chi non dovrebbe vederla;
- **scrittura** (*mass assignment*, CWE-915): una proprietà interna, come `role`, viene
  accettata in scrittura da chi non dovrebbe modificarla.

**Vincolo metodologico** (tesi, Cap. 3). Al modulo non si dice **quali** proprietà sono
protette. Il modulo deve dedurlo da solo, e poi verificarlo sul sistema in esecuzione con
identità diverse. Gli è invece consentito imparare **come** le applicazioni esprimono un
controllo: decoratori, dipendenze, guardie, dichiarazioni del contratto. La categoria è
**ibrida**: statica per inventario, inferenza e regole, dinamica per la conferma.

## A.2 Struttura

```
src/core/api3_bopla/                    (~4.900 righe)
├── orchestrator.py      pipeline, punteggio, report JSON/Markdown, vista per la dashboard
├── discovery.py         Fase 1 — inventario (codice, contratto, traffico), nomi canonici
├── contract.py          lettura del contratto OpenAPI ($ref, composizioni, readOnly/writeOnly)
├── property_inference.py Fase 2 — contesti autorizzativi, guardie, legame con l'oggetto, confidenza
├── access_patterns.py   forme in cui il codice accede a una proprietà
├── auth_idioms.py       idiomi di autorizzazione dei framework (catalogo YAML)
├── mass_assignment.py   Fase 2b — regola BOPLA-S01
├── static_rules.py      Fase 2b — regole BOPLA-S02..S04 + correlazione con la fase dinamica
├── dynamic_tester.py    Fase 3 — prove T01–T07
├── detector.py          adattatore verso il modello di dominio (IVulnerabilityDetector)
└── models.py            modelli Pydantic
config/scanner_configs/bopla-auth-idioms.yaml   catalogo degli idiomi di autorizzazione
```

Test: `tests/integration/api3_bopla/`, 14 file, **274 test verdi** (suite completa del
progetto: 857).

## A.3 Fase 1 — Inventario delle proprietà

L'inventario associa a ogni oggetto le sue proprietà e registra in quali **fonti** ciascuna
compare.

| Fonte | Cosa legge |
| --- | --- |
| **Codice** | classi Python, classi/interfacce/tipi JS e TS, struct Go (tag `json`). Il linguaggio è deciso **per file**, quindi le repository miste sono analizzate in tutte le loro parti. tree-sitter se la grammatica è installata, altrimenti regex: la scansione non installa pacchetti. Sono esclusi i file e le classi di test, gli enum, le eccezioni e le classi `Meta`/`Config` |
| **Contratto OpenAPI** | schemi dei componenti e schemi inline. I `$ref` sono risolti per operazione, e l'operazione è associata allo **schema** che la descrive, non solo al nome del percorso. `allOf` viene unito, `oneOf`/`anyOf` danno oggetti distinti. Le proprietà annidate hanno percorso puntato (`address.city`) |
| **Traffico osservato** | chiavi dei corpi JSON di richieste e risposte, con percorso puntato per gli oggetti annidati (`manager.salary`), associate all'operazione del contratto quando c'è (`/me` → `User`) |

I nomi degli oggetti sono resi **canonici**: PascalCase, separatori rimossi, singolare con regole
e tabelle di irregolari. Così `apply_coupon`, `ApplyCoupon` e `/apply-coupons` sono lo stesso
oggetto. Vengono tolti anche i suffissi di trasporto (`UserDTO`, `UserEntity` → `User`).

## A.4 Fase 2 — Inferenza dell'autorizzazione

Una proprietà è **protetta** se ha almeno un **contesto autorizzativo** e confidenza ≥ 0,4.
La confidenza premia la presenza nelle fonti e nelle operazioni. I contesti autorizzativi
possono essere di cinque tipi:

1. **Idiomi dei framework**, dal catalogo YAML:
   - decoratori di ruolo o permesso;
   - FastAPI `Depends(...)` e `Security(scopes=…)`;
   - Django `user_passes_test`, `permission_required` e mixin;
   - DRF `permission_classes`;
   - NestJS `@Roles` e `@UseGuards`;
   - middleware Express nella rotta;
   - wrapper e catene di middleware in Go.
   Il catalogo distingue l'**autorizzazione** (ruoli, permessi, scope) dall'**autenticazione**
   (`login_required`, `IsAuthenticated`, `requireAuth`), che non conta.
2. **Corpo di un `if`** la cui condizione riguarda l'autorizzazione. La condizione vale solo per
   il suo ramo, non per `elif`/`else`.
3. **Guardia a uscita anticipata**: `if not user.is_admin: abort(403)` rende riservato ciò che
   segue. Vale solo se la guardia **rifiuta** davvero la richiesta, cioè risponde 401/403, oppure
   ha la condizione negata e un ramo che contiene soltanto l'uscita. Sono esclusi i controlli di
   sola proprietà (`current_user.id != user.id`, che lasciano passare il proprietario) e le
   uscite positive (`if is_admin: return completo`). Il ramo di rifiuto non è un contesto.
4. **Contratto**: `readOnly` riserva la scrittura, `writeOnly` la lettura. La protezione ha
   quindi una **direzione**, rispettata da tutte le regole e le prove.
5. Le **parole chiave delle condizioni** sono solo di autorizzazione: ruolo, admin, staff,
   superuser, permesso, scope al plurale, rbac, acl. Il camelCase è scomposto (`isAdmin`).
   Lo snake_case conta per l'ultima parola (`has_permission` sì, `user_role_id` no).

Il riconoscimento degli **accessi** a una proprietà copre:
- l'attributo `user.salary`;
- la chiave `user["salary"]`, `.get("salary")`, `getattr`/`setattr`;
- le chiavi dei dizionari e degli oggetti letterali;
- la destrutturazione JS;
- le mappe Go.

Il contesto va all'**oggetto** dell'accesso, ricavato dal ricevitore: il nome della variabile,
un'assegnazione locale (`account = User.query.get(...)`), un parametro tipizzato, `self`/`this`
o il ricevitore di un metodo Go. Solo se il ricevitore non basta, il contesto va a tutti gli
oggetti che hanno quella proprietà.

## A.5 Fase 2b — Regole statiche

Le regole producono segnalazioni **da verificare**. Non toccano il punteggio, ma sono ciò che il
modulo mostra quando la fase dinamica non può girare.

| Regola | Direzione | Cosa segnala | Severità |
| --- | --- | --- | --- |
| **BOPLA-S01** mass assignment | scrittura | corpo della richiesta legato per intero a un'entità senza lista dei campi ammessi: `setattr` in un ciclo sulle chiavi, `Entità(**corpo)`, `.create/.update(**corpo)`, `archivio[k].update(corpo)`, serializer DRF `fields="__all__"`, `Object.assign(x, req.body)`, `Model.create(req.body)`, `Decode(&x)` + salvataggio in Go. Un'allowlist sopprime la segnalazione; una denylist no, ed è riportata come protezione parziale | MEDIUM, HIGH se l'entità ha proprietà protette in scrittura |
| **BOPLA-S02** esposizione | lettura | entità con proprietà protette serializzata **per intero** nella risposta (`vars(x)`, `to_dict()`, `model_dump()`, `res.json(x)`) fuori da un contesto autorizzativo | HIGH |
| **BOPLA-S03** contratto incoerente | entrambe | `readOnly` accettato dallo schema di richiesta di un'altra operazione, o `writeOnly` restituito in una risposta | MEDIUM |
| **BOPLA-S04** non documentata | entrambe | proprietà protetta osservata nel traffico ma assente dal contratto | LOW |

## A.6 Fasi 3 e 4 — Verifica dinamica, correlazione e punteggio

Servono una **matrice di identità** (utente ordinario e amministratore) e il bersaglio in
esecuzione. Le prove sono sette:

| Prova | Direzione | Condizione di vulnerabilità |
| --- | --- | --- |
| T01 | lettura | la proprietà protetta compare nella risposta all'utente |
| T02 / T03 / T04 / T05 | scrittura | il valore marcatore scritto dall'utente risulta **persistito** (riletto con l'identità più privilegiata) |
| T06 | lettura | l'utente riceve la stessa proprietà protetta dell'amministratore |
| T07 | scrittura | la scrittura dell'utente persiste dove solo l'amministratore dovrebbe riuscire |

**Correlazione.** Una segnalazione statica diventa:
- **confermata** (CRITICAL, confidenza 1) se una prova della stessa direzione dimostra
  vulnerabile una delle sue proprietà sulla stessa entità;
- **non confermata** se quelle proprietà sono state provate e hanno retto;
- **da verificare** negli altri casi.

**Punteggio.** Parte da 100 e perde 15 punti per ogni categoria di prova confermata.
`dynamic_phase_executed` è vero solo se almeno una prova ha ricevuto una risposta dal server:
con identità disponibili ma bersaglio irraggiungibile, il punteggio pieno non passa per
"verificato".

## A.7 Integrazione nella piattaforma

| Punto d'ingresso | Cosa mostra |
| --- | --- |
| Dashboard (`server.py`) e `run_unified_core_scanners.py` | nessuna identità, quindi solo le fasi statiche. `to_dashboard_items` mostra e conta le segnalazioni statiche con il loro stato, più le prove confermate quando ci sono |
| `run_bopla_scan.py`, `run_all_security_tests.py` | identità da Keycloak se raggiungibile. Riepilogo con prove, segnalazioni statiche e stato della fase dinamica |
| `Api3BoplaDetector` | traduce prove confermate e segnalazioni statiche in `Finding` del dominio. Sorgente `RUNTIME_VALIDATOR` o `STATIC_ANALYZER` (nuovo valore), CWE, categoria OWASP, posizione nel codice, chiave di correlazione `api:METODO:/percorso` |

---

# PARTE B — Limiti residui

## B.1 Statici

1. **Chiavi senza ricevitore.** Una chiave di dizionario o un oggetto letterale
   (`{"key": …}`) non dice a quale oggetto appartiene. Il contesto va quindi a tutti gli
   oggetti con quella proprietà. Su crAPI restano così `key`/`label` di un menu costruito
   sotto un controllo di ruolo, e `comment` distribuito su più oggetti.
2. **Nomi da percorso e da classe non sempre coincidono.** Il suffisso `Request` viene tolto dai
   nomi di classe: il modello Django `ServiceRequest` diventa `Service`, mentre il percorso
   `/service_requests` dà `ServiceRequest`.
3. **Java non analizzato.** È escluso il servizio identity di crAPI, e le annotazioni Spring
   (`@PreAuthorize`, `@Secured`) sono nel catalogo ma non vengono mai lette.
4. **Idiomi non supportati**:
   - middleware applicati a un gruppo di rotte (`router.use`, `r.Use`, `APIRouter(dependencies=…)`);
   - handler definiti in un file diverso da quello della rotta (è il caso del Go di crAPI);
   - guard NestJS con nome generico;
   - `get_permissions()` dinamici di DRF.
5. **TypeScript passa dalle regex**, perché `tree-sitter-typescript` non è installato: i
   contesti durano poche righe, e la chiave `salary:` riconosce anche le annotazioni di tipo.
6. **Il mass assignment esplicito non è una regola.** `order.status = request_data["status"]`,
   il caso noto di crAPI, si vede solo se `status` risulta protetta.
7. **La confidenza mescola documentazione e protezione.** Un decoratore esplicito vale quanto un
   `if` generico. La repository viene letta più volte (inventario, contesti, occorrenze).
8. **Contratto.** Gli involucri (`{"data": {…}}`) diventano proprietà puntate; `security` e
   gli scope per operazione non sono usati. La `repo_target` resta vuota, perché il suo contratto
   non dichiara schemi e il codice non ha classi di modello.

## B.2 Dinamici (fuori dal perimetro del lavoro statico)

- Nella piattaforma integrata la matrice di identità non viene passata: la fase dinamica gira
  solo dai runner dedicati.
- La ricerca delle chiavi in T01/T06 non distingue il livello: un `salary` di primo livello
  combacia anche con `manager.salary`.
- Il punteggio conta le categorie di prova, non le proprietà colpite.

---

# PARTE C — Interventi e risultati

## C.1 Interventi (25–26/09/2026)

| # | Limite | Intervento |
| --- | --- | --- |
| 25/09 | falsi positivi di T01/T06, conferme sul codice di stato | protezione = contesto + soglia; T06 invertito; scritture confermate solo se il valore persiste; app gemelle BOPLA |
| 1 | un solo linguaggio per repository | linguaggio per file, niente installazioni durante la scansione |
| 2 | mass assignment non cercato nel codice | BOPLA-S01 |
| 3 | le fasi statiche non producevano segnalazioni | BOPLA-S02..S04, correlazione con la fase dinamica, dashboard |
| 4 | guardie a uscita anticipata ignorate | guardie che rifiutano; `elif`/`else` non ereditano la condizione; camelCase |
| 5 | accessi solo come attributo | chiavi, `get`, `getattr`, dizionari, destrutturazione, mappe Go |
| 6 | contratto letto in parte, nomi fragili, annidamento appiattito | `contract.py`, direzione di `readOnly`/`writeOnly`, nomi canonici, percorsi puntati |
| 7 | idiomi dei framework invisibili | catalogo YAML autorizzazione/autenticazione |
| integrazione | rumore emerso misurando crAPI | ramo di rifiuto non protetto, parole chiave solo di autorizzazione, predicato del decoratore non protetto, direzione in S01/S02 |
| 8 | contesto legato al nome, non all'oggetto | risoluzione del ricevitore (variabile, assegnazione, parametro tipizzato, `self`, ricevitore Go) |
| 10 (parte) | classi non-modello nell'inventario | esclusi test, enum, eccezioni, `Meta`/`Config` |
| verifica finale | adattatore di dominio non funzionante; "fase dinamica eseguita" con bersaglio irraggiungibile | `Api3BoplaDetector` produce `Finding`; fase dinamica solo con risposte reali; T07 non registra prove senza risposta |

## C.2 Risultati sui bersagli

| Bersaglio | Oggetti | Proprietà | Protette | Segnalazioni statiche |
| --- | --- | --- | --- | --- |
| Gemella vulnerabile | 1 | 5 | `salary`, `role` | S01 + S02 (HIGH), S04 (LOW); con la fase dinamica **tutte confermate** |
| Gemella sicura | 1 | 5 | `salary`, `role` | solo S04; con la fase dinamica **non confermata** |
| `repo_target` | 1 | 2 | 0 | 0 |
| crAPI (repository + contratto) | 142 | 805 | 22 | 0 |
| Progetto intero (come lo analizza la dashboard, ~8 s) | 219 | 1.736 | 112 | 2 (S01, S02 sulla gemella vulnerabile) |

Andamento su crAPI:

| Momento | Oggetti | Proprietà protette | Nota |
| --- | --- | --- | --- |
| iniziale | 44 | 0 | analizzata solo la parte Go |
| dopo il punto 1 | 156 | 2 | 2 falsi positivi |
| dopo il punto 4 | 156 | 7 | — |
| dopo i punti 5–7 | 152 | 53 | per lo più rumore |
| dopo l'integrazione | 152 | 25 | — |
| finale | 142 | 22 | — |

Le 22 proprietà protette finali su crAPI hanno queste origini:
- **11 `id` `readOnly`** dichiarati dal contratto, protetti solo in scrittura;
- **8 dalla guardia di ruolo dei meccanici** (`if user.role != MECH: return 401`), che è un
  controllo autentico; `comment` è però distribuita su più oggetti (limite B.1.1);
- **3 chiavi di un menu** sotto un controllo di ruolo vero (limite B.1.1).

Le segnalazioni statiche su crAPI restano 0, ed è corretto: il suo mass assignment noto è
esplicito, campo per campo, e non un legame in blocco (B.1.6).
