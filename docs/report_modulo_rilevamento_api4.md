# Report: Modulo di Rilevamento API4:2023 (Unrestricted Resource Consumption)

Il documento ha due parti:

- **Parte A**: riepilogo tecnico di come è implementato il modulo
  [`src/core/api4_resource_consumption`](../src/core/api4_resource_consumption), verificato sul
  codice al 25/09/2026.
- **Parte B**: un prompt pronto da usare per riscrivere e aggiornare la sezione
  *Rilevamento dell'Unrestricted Resource Consumption* (`\label{sec:rilevamento-resource}`) del
  Capitolo 3 della tesi (`~/Desktop/MarcoDonatiello_Tesi/capitoli/capitolo3.tex`).

---

# PARTE A — Riepilogo dell'implementazione

## A.1 Obiettivo e ambito

Il modulo cerca le **difese mancanti** contro il consumo incontrollato di risorse (OWASP API4:2023),
cioè i punti in cui una richiesta può consumare memoria, CPU, banda, tempo o denaro senza alcun tetto:

- paginazione senza valore massimo;
- caricamenti di file senza limite di dimensione;
- chiamate di rete in uscita senza timeout;
- server GraphQL senza limiti di profondità o complessità;
- cicli su collezioni inviate dall'utente, senza controllo della lunghezza;
- chiamate a servizi a pagamento (SMS, email, pagamenti, LLM) senza limiti di frequenza;
- container, proxy e server applicativi senza limiti di memoria, di dimensione del corpo o di timeout;
- contratti OpenAPI che non dichiarano nessuno di questi vincoli.

CWE di riferimento: **CWE-400** (Uncontrolled Resource Consumption), **CWE-770** (Allocation of
Resources Without Limits or Throttling), **CWE-799** (Improper Control of Interaction Frequency).

Il modulo è **interamente statico**: non ha una fase dinamica. L'assenza di un limite è una
proprietà strutturale, che si legge sugli artefatti di progetto senza interrogare il sistema in
esecuzione.

## A.2 Struttura del modulo

```
src/core/api4_resource_consumption/
├── __init__.py              # esporta analyze, ResourceConsumptionFinding, ResourceConsumptionReport
├── detector.py              # entry point analyze(): esegue i tre livelli e costruisce il report
├── models.py                # dataclass ResourceConsumptionFinding / ResourceConsumptionReport
├── layers/
│   ├── layer1_ast.py        # Livello 1 — codice sorgente (tree-sitter, Python + JS/TS)
│   ├── layer2_config.py     # Livello 2 — file di configurazione (YAML, ast, regex)
│   └── layer3_openapi.py    # Livello 3 — contratto OpenAPI (visita del dizionario) + arricchimento
├── rules/                   # le sei regole del livello AST, una per file
│   ├── pagination.py        # RC-001
│   ├── upload.py            # RC-002
│   ├── timeout.py           # RC-003
│   ├── graphql_batching.py  # RC-004
│   ├── loop_bounds.py       # RC-005
│   └── third_party_cost.py  # RC-006
└── docs/owasp_api4_coverage.md   # registro di copertura e cicli di validazione
```

Dimensione: circa 3.900 righe di codice. Test in `tests/unit/api4_resource_consumption/`
(**176 test, tutti verdi, nessuno saltato**).

## A.3 Modello dati

[`models.py`](../src/core/api4_resource_consumption/models.py): ogni segnalazione
(`ResourceConsumptionFinding`) ha la stessa forma, qualunque sia il livello che l'ha prodotta:

| Campo | Significato |
| --- | --- |
| `rule_id`, `cwe_id`, `category` | regola (RC-001…RC-013), debolezza CWE, categoria del difetto |
| `severity` | `HIGH` / `MEDIUM` / `LOW` |
| `file_path`, `line_number` | posizione (per il contratto: `openapi_spec`, riga assente) |
| `endpoint`, `parameter` | rotta e parametro coinvolti, quando identificabili |
| `evidence` | frammento testuale che ha fatto scattare la regola |
| `missing_guard` | **la difesa che ci si aspettava di trovare** (il campo che caratterizza il modulo) |
| `confidence` | grado di fiducia 0–1 |
| `layer` | `ast` / `config` / `openapi` |

`ResourceConsumptionReport` aggiunge:

- `coverage_signals`: per ogni categoria, quali regole sono scattate;
- `summary`: conteggi per severità, per categoria e per livello.

## A.4 Flusso di esecuzione

[`detector.analyze(target_path, openapi_spec=None, enrich_spec=False)`](../src/core/api4_resource_consumption/detector.py):

1. **Livello 1 (sempre)**: `analyze_ast(target_path)`.
2. **Livello 2 (sempre)**: `analyze_configs(target_path)`.
3. **Livello 3 (solo se è stata passata una specifica)**: `analyze_openapi(spec, enrich_spec)`.
   Senza specifica il livello viene saltato senza errori.
4. Le segnalazioni vengono concatenate e il report calcola `coverage_signals` e `summary`.

Politica di robustezza: *skip-and-continue*. Un file illeggibile, binario, più grande di 1 MB o
sintatticamente rotto viene saltato con un warning. Anche il fallimento di una singola regola viene
registrato nel log senza bloccare le altre. Tree-sitter analizza comunque la parte recuperabile
dell'albero anche in presenza di errori di sintassi.

## A.5 Le tredici regole

| Livello | Regola | CWE | Cosa cerca | Severità / confidenza tipiche |
| --- | --- | --- | --- | --- |
| AST | **RC-001** Paginazione illimitata | 400 | parametro `limit`/`page_size`/`per_page`/`count`/`size`/`offset`/`take`/`skip` letto dalla richiesta e passato a `.limit()`, a uno slicing `[:x]` ecc. senza `min`/`max`/`clamp` o un `if` di confronto; FastAPI `Query(...)` senza `le=`; Express `req.query.limit` | HIGH 0.8–0.9; MEDIUM 0.6 per i casi indiretti |
| AST | **RC-002** Upload senza limite | 770 | Flask `request.files` senza `MAX_CONTENT_LENGTH`; FastAPI `UploadFile` senza controllo di `size`; Multer senza `limits.fileSize` | HIGH 0.8–0.9 |
| AST | **RC-003** Chiamata HTTP senza timeout | 400 | `requests`, `httpx`, `urllib`, `axios`, `fetch`, `got` senza `timeout` (né context manager `asyncio.timeout`/`anyio.fail_after`) | HIGH; confidenza alzata a 0.95 se l'URL o la funzione rimandano a un servizio a pagamento (twilio, stripe, sendgrid…); esclude il codice lato client (fix del falso positivo su `userSaga.ts`) |
| AST | **RC-004** GraphQL senza limiti | 799 | `strawberry.Schema`, `graphene.Schema`, Ariadne, `ApolloServer`, `GraphQLServer` senza depth/cost limiter o `validationRules` | HIGH 0.85 |
| AST | **RC-005** Ciclo su input utente | 400 | modello di taint semplificato e intra-procedurale: sorgente `request.json`/`req.body` → ciclo senza un controllo `len(...)`/`.length`/`MAX_ITEMS` che lo preceda. **Esteso**: `for`, `while`, comprensioni Python (list/dict/set/generator), `for` indicizzato JS, `while` JS, `forEach`/`map`/`filter`/`reduce`/`flatMap` | HIGH 0.75 |
| AST | **RC-006** Servizio a pagamento senza freno | 799 | chiamata a un SDK a pagamento (twilio, sendgrid, stripe, boto3.ses/sns, openai, anthropic…) in un handler senza decoratore di rate limiting né contatore Redis. **Vincolo anti-falsi positivi**: la chiamata deve essere riconducibile a un import dell'SDK | HIGH 0.85; MEDIUM 0.7 |
| Config | **RC-007** Container senza limite di memoria | 770 | servizi in `docker-compose.yml` senza `mem_limit`/`deploy.resources.limits` | MEDIUM 0.9 |
| Config | **RC-008** Corpo della richiesta illimitato | 770 | `client_max_body_size` assente (HIGH) o > 50 MB (MEDIUM) in `nginx.conf`; `MAX_CONTENT_LENGTH`/`DATA_UPLOAD_MAX_MEMORY_SIZE` assenti in `.env` o `settings.py` (letti con `ast` della libreria standard) | HIGH 0.9 / MEDIUM 0.7–0.75 |
| Config | **RC-009** Timeout di richiesta mancante | 400 | timeout del proxy assenti in nginx; gunicorn `timeout = 0` (**HIGH 0.98**: il controllo è disattivato); timeout non dichiarato (LOW 0.5, vale il default); `Procfile` | graduata |
| OpenAPI | **RC-010** Parametro di paginazione senza `maximum` | 400 | parametri di paginazione senza `maximum` (HIGH 0.9); `maximum` > 1000 (LOW 0.6) | |
| OpenAPI | **RC-011** Upload senza `maxLength`/`maxItems` | 770 | corpi `multipart/form-data` o `application/octet-stream` senza vincoli di dimensione | HIGH 0.9 / MEDIUM 0.75–0.8 |
| OpenAPI | **RC-012** Endpoint costoso non protetto | 770 | percorso, `operationId`, `summary` o `description` contengono come parola intera una parola chiave "costosa": le parole di *azione* (export, download, transcode, predict…) valgono con ogni metodo, quelle di *risorsa* (sms, otp, email, report, payment, invoice, ai, ml…) solo quando l'operazione avvia un lavoro: POST, PUT/PATCH su una collezione (`PUT /sms`) o un verbo di innesco nel percorso/`operationId`/`summary` (`/invoices/{id}/send`, `resendOtp`). Se il nome è neutro, valgono i **segnali strutturali** del contratto: campi della richiesta (telefono + messaggio, destinatario + oggetto, `amount` + `currency`, `cvc`/`cvv`, `prompt`, `max_tokens`/`temperature`; HIGH 0.8) o una risposta `202 Accepted` o con contenuto generato (PDF, CSV, archivi, fogli di calcolo, binari, audio/video; MEDIUM 0.7). In ogni caso l'operazione non ha `security`, un'estensione `x-rate-limit`/`x-throttle` o una menzione di throttling | HIGH 0.85 |
| OpenAPI | **RC-013** Array nel payload senza `maxItems` *(nuova)* | 400 | corpo JSON che è un array, o che ha proprietà di tipo array, senza `maxItems`; severità HIGH se il percorso contiene batch/bulk/multi/import/items, altrimenti MEDIUM | 0.8–0.85 |

**Arricchimento del contratto** (`enrich_spec=True`): per ogni operazione con segnalazioni il modulo
aggiunge un'estensione `x-security-analysis.api4_findings` con regola, severità, parametro, difesa
mancante e confidenza. Aggiunge solo campi `x-`, che le regole di estensione OpenAPI permettono, e
non modifica mai i campi esistenti.

Formati supportati dal livello 3: OpenAPI 3.0, 3.1 e Swagger 2.0. I `$ref` locali vengono risolti.
Una specifica malformata non solleva errori: il livello restituisce una lista vuota.

## A.6 Deduplicazione, ordinamento e soglie

- **Deduplicazione e ordinamento avvengono solo nel livello AST** (`_dedup` e `_sort_findings` in
  `layer1_ast.py`). Più segnalazioni con la stessa chiave (regola, file, riga) si riducono a una,
  tenendo quella con confidenza più alta. L'ordine è: severità, confidenza decrescente, file, riga.
  Il `detector` non deduplica e non riordina le segnalazioni dei livelli config e OpenAPI:
  le accoda nell'ordine di esecuzione.
- **Soglie**: `SANE_MAX_LIMIT = 1000` (livello 3) e `NGINX_BODY_SIZE_WARN_THRESHOLD = 50 MB`
  (livello 2). Sono **costanti con un nome, dichiarate in testa al modulo**, non argomenti di
  `analyze()`. Si leggono e si modificano in un punto solo, ma non si configurano a runtime.

## A.7 Integrazione nella piattaforma

- [`entrypoints/runners/run_unified_core_scanners.py`](../entrypoints/runners/run_unified_core_scanners.py)
  chiama `urc_detector.analyze(repo_path, openapi_spec)` insieme agli altri scanner Core e alimenta
  la card "Panoramica Sicurezza".
- [`src/presentation/api/server.py`](../src/presentation/api/server.py) esegue il modulo con la
  specifica caricata da `load_openapi_spec()` e serializza le segnalazioni per la dashboard.
- [`run_all_validations.py`](../entrypoints/runners/run_all_validations.py) include
  `validate_ground_truth.py` nella campagna di validazione.
- Una scansione API4 impiega meno di un secondo su un target piccolo: rientra nei 15–20 secondi
  complessivi delle scansioni senza BOLA.

## A.8 Validazione

**Coppia gemella** `data/test_targets/unrestricted_resource_consumption/{vulnerable_app,secure_app}`
(ognuna con `app.py`, `graphql_app.py`, `docker-compose.yml`, `nginx.conf`, `gunicorn.conf.py`),
eseguita con `tests/unit/api4_resource_consumption/validate_ground_truth.py`:

| Esito | Valore |
| --- | --- |
| TP / TN / FP / FN | 9 / 1 / 0 / 0 |
| TPR | **100%** (soglia ≥ 80%) |
| FPR | **0%** (soglia = 0%) |
| Regole verificate su file | RC-001…RC-009 (inclusa RC-004, con la fixture `graphql_app.py`) |
| Regole verificate con specifiche costruite nei test | RC-010…RC-013 |

**Storia dei cicli** (dal registro di copertura): RC-006 è stato messo a punto legando la chiamata
all'import dell'SDK a pagamento; è stato rimosso un falso positivo di RC-003 su codice lato client
(`userSaga.ts`); RC-004 è stato verificato con una fixture GraphQL dedicata.

**Repo target realistica** (`data/test_targets/repo_target`, con il suo `openapi.yaml`), eseguita il
25/09/2026:

| Regola | Livello | Dove | Lettura |
| --- | --- | --- | --- |
| RC-001 | AST | `app.py:98`, parametro `limit` di `GET /api/projects` | vero positivo atteso (MEDIUM 0.6) |
| RC-010 | OpenAPI | `GET /api/projects`, parametro `limit` senza `maximum` | **lo stesso difetto visto dal contratto**: esempio concreto di correlazione fra livelli |
| RC-005 | AST | `cooperative_harness.py:59`, ciclo su `payload.items()` in `POST /test/seed` | tecnicamente corretto (ciclo non limitato su un payload utente), ma si trova nell'harness di test cooperante, non nella logica applicativa |
| RC-012 | OpenAPI | `GET /api/invoices/{id}` | **non scatta più**: in origine scattava per la parola chiave "invoice" su una lettura semplice. Corretto distinguendo parole di azione e di risorsa (quest'ultime valgono solo con POST) |

## A.9 Evoluzioni rispetto al testo attuale della tesi

Il testo attuale del Capitolo 3 (righe ~982–1136) **non corrisponde più al codice** in questi punti:

1. **Le regole sono tredici, non dodici.** RC-013 (array nel payload senza `maxItems`) si aggiunge
   al livello del contratto, che ora ha quattro regole (RC-010–013). Vanno aggiornati la tabella
   `tab:regole-resource`, la sua didascalia e i riferimenti nel testo.
2. **Il limite su JavaScript è risolto.** Il testo dice che il riconoscimento su JS è parziale per
   una variazione della grammatica di tree-sitter. Oggi le regole riconoscono i nodi
   `member_expression`/`property_identifier` e il campo `constructor` di `new ApolloServer(...)`,
   e FastAPI usa il campo `value` di tree-sitter 0.25. I tre test prima saltati passano. Il limite
   va tolto, o riformulato come nota storica.
3. **RC-005 copre più forme di iterazione**: `while`, comprensioni Python, `for` indicizzato JS e
   metodi funzionali (`forEach`, `map`, `filter`, `reduce`, `flatMap`).
4. **Deduplicazione: il testo è impreciso.** Dice che le segnalazioni vengono deduplicate e
   ordinate "prima dell'aggregazione" in modo generale. In realtà succede solo per il livello AST.
5. **Soglie: il testo è impreciso.** Dice che sono "parametri espliciti dell'analisi". In realtà
   sono costanti con un nome, dichiarate in un punto solo e non nascoste nelle regole, ma non
   configurabili dall'esterno.
6. **Manca la verifica su repo realistica** (A.8): la coppia RC-001 + RC-010 sullo stesso
   parametro è un buon esempio concreto per la correlazione richiesta da RQ1.1; il falso positivo
   RC-012 su `/api/invoices/{id}` è stato corretto e la tesi lo riporta come falso positivo risolto; il limite dichiarato è ora la natura statica (costo ed efficacia dei limiti sono proprietà runtime).

## A.10 Limiti attuali (verificati sul codice)

1. **Correlazione (risolto)**: `correlation.py` ricollega le segnalazioni AST alla rotta che le
   contiene (decoratori Flask/FastAPI, chiamate Express) e le confronta con il contratto:
   *corroborated* (RC-001↔RC-010, RC-002↔RC-011, RC-005↔RC-013, RC-006↔RC-012 sulla stessa
   rotta: collegate, confidenza +0.1), *compensated* (RC-002/RC-011 con un tetto al corpo in
   nginx/.env/settings: severità INFO, difesa citata in `compensated_by`), *derived* (RC-006 nel
   codice genera RC-012 sull'operazione non protetta del contratto, anche con nome neutro).
   Limiti residui: riconoscimento delle rotte solo per le forme più comuni; la compensazione
   copre solo il tetto al corpo delle richieste.
2. **Riconoscimento euristico in RC-012**: nomi (parole intere, risorsa vs azione, forma
   dell'operazione) e segnali strutturali del contratto coprono anche endpoint con nome neutro, ma
   restano indizi: un endpoint costoso con nome neutro, input generici e risposta JSON sincrona
   sfugge al livello del contratto. Nel codice lo copre RC-006, che riconosce l'SDK a pagamento
   chiamato indipendentemente dal nome della rotta. Su crAPI la regola non segnala più
   `GET /workshop/api/mechanic/receive_report`, che registra un report (scrittura economica).
3. **Taint semplificato** in RC-005: è intra-procedurale e si basa sul testo che precede il ciclo.
   Non segue i dati tra funzioni diverse e accetta come guardia qualunque `len(`/`MAX` presente
   prima del ciclo.
4. **Nessuna conoscenza della soglia giusta**: il modulo dice che un limite manca o che un valore
   è fuori scala, non quale valore sia appropriato al contesto.
5. **Le segnalazioni misurano l'importanza di un presidio mancante, non la certezza di un attacco**:
   nessuna verifica dinamica (per esempio un test di carico) conferma che il consumo sia davvero
   sfruttabile.
6. **Copertura linguistica**: Python e JavaScript/TypeScript. Nessun supporto a Java, Go o altri
   linguaggi.

---

# PARTE B — Prompt per riscrivere la sezione della tesi

> Copia tutto il blocco seguente in una nuova conversazione, allegando (o incollando) la sezione
> attuale `\section{Rilevamento dell'Unrestricted Resource Consumption}` di `capitolo3.tex` e la
> Parte A di questo documento.

```text
RUOLO
Sei un co-autore esperto di tesi di laurea in informatica / sicurezza del software. Mi aiuti a
riscrivere e aggiornare UNA sezione del Capitolo 3 della mia tesi, in italiano, in LaTeX.

CONTESTO
La tesi presenta una piattaforma per rilevare vulnerabilità delle API cloud secondo l'OWASP API
Security Top 10 (2023). Il Capitolo 3 descrive l'approccio metodologico e poi un modulo di
rilevamento per categoria. Devi lavorare SOLO sulla sezione
\section{Rilevamento dell'Unrestricted Resource Consumption} (\label{sec:rilevamento-resource}),
con le sue sottosezioni:
  - \subsection{I tre livelli di analisi}          (\label{sec:resource-layers})
  - \subsection{Aggregazione e correlazione fra livelli} (\label{sec:resource-correlation})
  - \subsection{Validazione e limiti}              (\label{sec:validazione-resource})
e la tabella \label{tab:regole-resource}.

Ti fornisco: (1) il testo LaTeX attuale della sezione; (2) il riepilogo tecnico aggiornato
dell'implementazione (Parte A). Quando testo e riepilogo non coincidono, vale il riepilogo:
è stato verificato sul codice.

COSA DEVI AGGIORNARE (obbligatorio)
1. Le regole sono TREDICI, non dodici. Aggiungi RC-013 (array nel corpo JSON senza maxItems:
   un'operazione "batch" che accetta un numero illimitato di elementi) al livello del contratto,
   che passa a RC-010--013. Aggiorna tabella, didascalia e ogni riferimento a "dodici".
2. Rimuovi il limite sul riconoscimento parziale di JavaScript: è stato risolto. Al massimo una
   frase che dice che il modulo è stato allineato all'evoluzione della grammatica di tree-sitter.
   Nessun dettaglio sui nomi dei nodi.
3. Nel primo livello, di' che la regola sui cicli copre ora le principali forme di iterazione
   (cicli for e while, comprensioni in Python, metodi come forEach e map in JavaScript). Una frase
   basta: niente elenchi di nomi di nodi.
4. Correggi due imprecisioni:
   - la deduplicazione (stessa regola, stesso punto, si tiene la confidenza più alta) e
     l'ordinamento per severità riguardano le segnalazioni del codice sorgente, non l'intero
     rapporto;
   - le soglie (per esempio il valore massimo oltre il quale un limite di paginazione appare
     eccessivo, o la dimensione oltre la quale il limite del corpo è considerato troppo alto)
     sono costanti dichiarate in un unico punto e con un nome esplicito, non valori nascosti nelle
     regole. NON dire che sono parametri configurabili dall'esterno. Mantieni il collegamento con
     il requisito di configurabilità (Sottosezione~\ref{sec:requisiti}) in modo onesto: la
     predisposizione c'è, la configurazione a runtime no.
5. Nella validazione aggiungi la prova sulla repository bersaglio realistica, oltre alla coppia
   di applicazioni gemelle (100% di veri positivi, nessun falso positivo; le regole del contratto
   sono verificate con specifiche costruite nei test). Usala per due scopi:
   - ESEMPIO DI CORRELAZIONE (collegato a \RQ{1.1}): lo stesso parametro di paginazione
     dell'endpoint che elenca i progetti è segnalato sia nel codice (il valore arriva dalla
     richiesta e viene usato senza tetto) sia nel contratto (il parametro non dichiara un
     massimo). Stesso difetto, due livelli: è la dimostrazione concreta della tesi della sezione.
   - ESEMPIO ONESTO DI LIMITE: l'endpoint che legge una fattura viene considerato "costoso" solo
     perché il nome contiene una parola associata ai pagamenti, anche se è una semplice lettura.
     È un limite del riconoscimento per parole chiave.
   Presenta i numeri così come sono: non gonfiarli e non aggiungerne di nuovi.
6. Aggiorna i limiti. Tieni: correlazione solo presentativa; nessuna conoscenza della soglia
   corretta; le segnalazioni indicano presidi mancanti, non attacchi certi. Aggiungi: il
   riconoscimento degli endpoint costosi si basa su parole chiave ed è quindi approssimativo;
   il tracciamento del dato dalla richiesta al ciclo resta confinato alla singola funzione.

COSA DEVI CONSERVARE
- La struttura in sottosezioni e TUTTE le \label esistenti (sono referenziate altrove).
- I riferimenti bibliografici e incrociati già presenti: \cite{owasp2023api4},
  \cite{treesitter2026docs}, \cite{cwe400}, \cite{cwe770}, \cite{cwe799},
  \ref{subsubsec:api4}, \ref{sec:criterio}, \ref{sec:requisiti},
  \ref{sec:disegno-valutazione}, la macro \RQ{1.1}. Non inventare nuove chiavi \cite: se ti
  servisse una fonte che non c'è, scrivi [CITAZIONE DA AGGIUNGERE].
- L'argomento centrale della sezione: l'assenza di un limite è una proprietà strutturale, per
  questo il modulo è interamente statico; lo stesso difetto può trovarsi nel codice, nella
  configurazione o nel contratto, e nessun livello da solo basta. Tieni l'esempio del caricamento
  senza controllo nel codice ma limitato dal proxy.
- Lo stile delle note a piè di pagina per i termini tecnici (paginazione, timeout, maximum /
  maxLength / maxItems). Se introduci "operazione batch" o "maxItems" senza spiegarli, aggiungi
  una nota breve dello stesso tipo.
- Il formato della tabella (tabularx, booktabs, \small, \linespread{1.0}).

STILE DI SCRITTURA (vincolante)
Registro e tono
- Italiano accademico da tesi di laurea: preciso, ma scorrevole e leggibile da un docente che non
  ha visto il codice.
- Chiaro e semplice: una idea per frase, frasi di lunghezza media. Alterna frasi brevi e frasi più
  articolate, così il ritmo non diventa monotono.
- Non troppo tecnico: spiega COSA fa il modulo e PERCHÉ, non come è scritto il codice. Niente
  nomi di funzioni, classi, variabili, file Python o numeri di riga. Ammessi solo i nomi di
  artefatti che il lettore riconosce (docker-compose.yml, contratto OpenAPI, GraphQL,
  tree-sitter) e gli identificativi delle regole (RC-001...) nella tabella. Niente valori di
  confidenza puntuali (0,85, 0,9...) nel testo.
- Non noioso: ogni paragrafo parte da un problema concreto o da una domanda implicita, poi dà la
  risposta. Usa esempi concreti e brevi (un invio di SMS, un parametro "limit", un caricamento di
  file) invece di concetti astratti. Scegli verbi precisi e evita i nomi astratti accumulati
  ("l'effettuazione della verifica" -> "verificare").
- Prima persona plurale o forma impersonale, come nel resto del capitolo ("il modulo verifica",
  "si osserva"). Niente seconda persona.
- Coerenza terminologica con il resto del capitolo: "segnalazione" (non "finding"), "livello"
  (non "layer"), "contratto" per la specifica OpenAPI, "difesa mancante", "applicazioni gemelle",
  "versione vulnerabile" / "versione irrobustita". I termini inglesi consolidati vanno in
  \emph{} alla prima occorrenza.

Pattern di scrittura "da IA" da EVITARE (vincolante)
- Formule di apertura e chiusura vuote: "In questa sezione vedremo...", "È importante
  sottolineare che...", "Vale la pena notare...", "In conclusione...", "In sintesi...",
  "Questo approccio consente di...", "giocare un ruolo chiave/cruciale/fondamentale".
- Aggettivi enfatici e marketing: "robusto", "potente", "innovativo", "completo", "avanzato",
  "sofisticato", "fondamentale", "cruciale", "essenziale", "rivoluzionario", "all'avanguardia",
  "senza soluzione di continuità", "a 360 gradi".
- Terne automatiche di aggettivi o sostantivi ("chiaro, conciso ed efficace") e l'abitudine di
  elencare sempre per tre.
- Frasi a contrasto costruito: "Non si tratta solo di X, ma di Y", "Non è X: è Y".
- Domande retoriche usate come transizione ("Ma come si può...?").
- Riassunti ridondanti alla fine dei paragrafi che ripetono quanto appena detto.
- Elenchi puntati nel corpo del testo: la tesi è in prosa. Solo la tabella resta tabellare.
- Uso eccessivo dei due punti e dei trattini lunghi (---) come effetto retorico: usali con
  parsimonia, solo quando servono davvero.
- Grassetti nel testo corrente; corsivo solo per termini alla prima occorrenza.
- Connettivi ripetitivi a inizio frase ("Inoltre", "Infine", "Pertanto", "Tuttavia",
  "Di conseguenza"): varia oppure lascia che la frase si colleghi da sola.
- Superlativi e certezze non dimostrate ("elimina completamente", "garantisce"): affermare solo
  ciò che la validazione mostra. Onestà sui limiti, nessuna autocelebrazione.
- Iperbole sul rischio ("catastrofico", "devastante").

Vincoli di forma
- Lunghezza: simile a quella attuale (circa 1.600-2.000 parole), con una tolleranza di più o meno
  il 15%. Se aggiungi contenuto, compensa tagliando le ripetizioni.
- Output: SOLO codice LaTeX pronto da incollare al posto della sezione attuale, dalla riga
  \section{...} fino alla fine di \subsection{Validazione e limiti}, seguito soltanto dal breve
  elenco di controllo descritto al punto 4 della PROCEDURA.
- Caratteri: accenti italiani diretti (è, à, perché), virgolette ``...'', \emph{} per i termini
  stranieri, \texttt{} per i nomi di campo del contratto (maximum, maxItems), \path{} per i nomi
  di file, ~ prima di \cite e \ref.
- Non modificare i contenuti delle altre sezioni. Non introdurre numeri, risultati o funzionalità
  che non compaiono nel riepilogo tecnico.

PROCEDURA
1. Leggi il testo attuale e il riepilogo; individua le differenze (usa l'elenco "COSA DEVI
   AGGIORNARE" come lista di controllo).
2. Riscrivi la sezione.
3. Rileggi il tuo testo contro la lista dei pattern da evitare e correggi ogni occorrenza.
4. Restituisci il LaTeX. Poi, SEPARATAMENTE e dopo il codice, aggiungi un elenco di massimo 6
   righe con le modifiche sostanziali fatte (per poterle controllare), e segnala ogni
   [CITAZIONE DA AGGIUNGERE].
```
