# Report Tecnico: Modulo API7:2023 — Server-Side Request Forgery (SSRF)

## 1. Introduzione ed Obiettivo

Il modulo [`src/core/api7_ssrf`](file:///Users/marcodonatiello/DetectionCloudSecurityRisk/src/core/api7_ssrf) è il componente della piattaforma dedicato all'identificazione e all'analisi statica e contrattuale delle vulnerabilità classificate come **OWASP API7:2023 — Server-Side Request Forgery (SSRF)** (CWE-918).

L'obiettivo del modulo è intercettare l'esposizione di endpoint API che effettuano chiamate HTTP o di rete verso risorse remote utilizzando parametri o URI controllati dall'utente privi di adeguata validazione (allowlist, schema sanitization, gestione dei redirect), prevenendo scenari critici quali:
- **Port scanning e scansione della rete interna** (localhost, VPC, container contigui).
- **Esfiltrazione di credenziali cloud** mediante l'Instance Metadata Service (IMDS / `169.254.169.254`).
- **Bypass dei controlli di sicurezza** tramite catene di redirect HTTP malevoli.

---

## 2. Architettura del Modulo e Motore di Analisi

Il modulo combina un motore **Static Application Security Testing (SAST)** basato su analisi del flusso dei dati (Taint Analysis via Semgrep) e un livello di **Contract-Level Analysis** sulle specifiche OpenAPI 3.x.

```
src/core/api7_ssrf/
├── detector.py                  # Orchestratore del modulo: coordina SAST, layer OpenAPI e sintesi dei risultati
├── models.py                    # Modelli tipizzati: SsrfFinding e SsrfReport
├── semgrep_runner.py            # Gestore dell'esecuzione sicura di Semgrep (isolamento ambiente, timeout)
├── normalizer.py                # Estrazione da dataflow_trace, normalizzazione finding e mapping categorie
├── rules/
│   └── semgrep_rules.yml        # Regole Semgrep in Taint Mode (SS-001 .. SS-005)
├── layers/
│   └── layer3_openapi.py        # Analisi del contratto OpenAPI 3.x (SS-006)
├── fixtures/                    # Target per validazione ground-truth (vulnerable_app e secure_app)
└── docs/
    └── owasp_api7_coverage.md   # Registro formale di copertura e scenari verificati
```

### Caratteristiche del Motore Taint Mode

A differenza dei tradizionali controlli sintattici basati su pattern testuali o corrispondenze rigide all'interno della stessa istruzione, il modulo opera in **Semgrep Taint Mode (`mode: taint`)**:

1. **Tracciamento Completo Sorgente $\rightarrow$ Destinazione (Source-to-Sink)**:
   - **Sources**: intercetta tutte le vie d'ingresso dei dati utente (`request.args`, `request.json`, `request.form`, `request.headers`, `request.values`, `request.data`, `request.get_json(...)` in Python; `req.query`, `req.body`, `req.params`, `req.headers` in Node.js/Express).
   - **Sanitizers**: riconosce le guardie di validazione e allowlist (`validate_url`, `is_valid_url`, `is_allowed`) sanificando le variabili e prevenendo falsi positivi su flussi protetti.
   - **Sinks**: identifica le chiamate verso i client HTTP, verificando l'assenza di controlli condizionali prima della richiesta.

2. **Rilevamento di SSRF Parziale (Partial SSRF)**:
   - Il motore di taint propaga lo stato di "contaminazione" attraverso **f-strings** (es. `f"https://api.partner.com/v1/{path}"`), **concatenazioni di stringhe**, metodi di formattazione (`.format(...)`) e assegnazioni di variabili intermedie multiple. Ciò consente di intercettare attacchi di path traversal o host override su URL composti.

3. **Copertura Estesa dei Client HTTP Moderni**:
   - **Python**: supporto completo per `requests` (chiamate dirette e `requests.Session`), `httpx` (client sincrono `httpx.Client`, asincrono `httpx.AsyncClient` e metodi top-level), `aiohttp` (`ClientSession`) e `urllib` (`urlopen`, `urlretrieve`).
   - **Node.js / TypeScript**: supporto per `fetch` nativo e `axios` (`axios.get`, `axios.post`, `axios.$METHOD`, istanze dirette).

4. **Isolamento dell'Ambiente di Esecuzione**:
   - Il runner (`semgrep_runner.py`) configura dinamicamente una cartella di lavoro isolata (`.tmp`) per la gestione dei log di Semgrep, garantendo l'esecuzione deterministica sia in locale sia all'interno di pipeline CI/CD o ambienti con permessi restrittivi.

---

## 3. Matrice delle Regole Implementate

| Regola | CWE | Titolo / Categoria | Linguaggi / Target | Descrizione e Funzionamento |
| :--- | :--- | :--- | :--- | :--- |
| **SS-001** | CWE-918 | `direct_url_from_input` (Python/requests/httpx/aiohttp) | Python | Identifica URL o frammenti di URL non validati passati a client HTTP moderni (`requests`, `httpx`, `aiohttp`). Traccia il flusso del dato in Taint Mode attraverso assegnazioni intermedie e formattazioni di stringhe. |
| **SS-002** | CWE-918 | `direct_url_from_input` (Python/urllib) | Python | Traccia in Taint Mode l'input non validato fornito alle API standard `urllib.request.urlopen` o `urllib.request.urlretrieve`. |
| **SS-003** | CWE-918 | `direct_url_from_input` (JS/Express) | JavaScript, TypeScript | Rileva in Taint Mode input da parametri query o body inoltrati verso client HTTP Node.js (`fetch`, `axios`) in assenza di guardie difensive. |
| **SS-004** | CWE-918 | `redirect_following` | Python | Segnala l'uso esplicito di `allow_redirects=True` (`requests`) o `follow_redirects=True` (`httpx`) con URL controllati dall'utente, evidenziando il rischio di bypass delle allowlist tramite catene di redirect HTTP 30x. |
| **SS-005** | CWE-918 | `cloud_metadata_access` | Python, JS, TS | Intercetta chiamate HTTP dirette verso indirizzi IP o hostname di metadata cloud noti (`169.254.169.254`, `metadata.google.internal`, `100.100.100.200`) su `requests`, `urllib`, `httpx`, `aiohttp`, `fetch`, `axios`. |
| **SS-006** | CWE-918 | `unvalidated_url_parameter` | OpenAPI 3.x | Ispeziona query, path, header e proprietà del `requestBody` (webhook, callback, redirect, destination, proxy, target). Segnala la mancanza di `format: uri` e di `pattern` (allowlist regex). |

---

## 4. Confronto con la Specifica OWASP API7:2023

Il modulo risponde in modo puntuale ai concetti, agli scenari d'attacco e alle raccomandazioni di bonifica definite dallo standard OWASP:

### 4.1. Concetto Chiave e Vettori di Attacco
* **Definizione OWASP**: Accesso da parte dell'API a un URI fornito dal client in assenza di opportuna convalida.
* **Copertura nel Modulo**: Le regole **SS-001**, **SS-002**, **SS-003** e **SS-006** intercettano l'intero ciclo di vita dell'input utente fino al sink di rete.
* **Basic vs Blind SSRF**: L'analisi statica opera sul flusso del dato (source-to-sink). Pertanto, rileva la presenza della vulnerabilità a prescindere dal fatto che la risposta del server remoto sia restituita al client (Basic SSRF) o trattenuta/omessa (Blind SSRF).

### 4.2. Scenari di Attacco Esaminati

1. **Scenario #1 OWASP — Upload Immagine / Anteprima / Port Scanning Interno**:
   - *Descrizione OWASP*: Un endpoint `POST /api/profile/upload_picture` accetta un parametro `picture_url` e tenta di scaricare la risorsa remota. L'attaccante inserisce `localhost:8080` per eseguire una mappatura dei servizi interni.
   - *Rilevamento*: Intercettato a livello di codice da **SS-001/SS-003** (anche in presenza di URL composti tramite la nuova analisi di SSRF parziale), e a livello di schema contrattuale da **SS-006** (campi URL privi di `format: uri` e `pattern` allowlist).

2. **Scenario #2 OWASP — Webhook verso Cloud Metadata Service**:
   - *Descrizione OWASP*: Configurazione di un canale di notifica webhook in cui l'utente specifica un URL. L'attaccante indica l'indirizzo `http://169.254.169.254/latest/meta-data/iam/security-credentials/...` per sottrarre i token di autenticazione temporanei dell'ambiente cloud.
   - *Rilevamento*: Coperto direttamente da:
     - **SS-005**: Blocca accessi a endpoint IMDS noti.
     - **SS-004**: Rileva webhook eseguiti con redirect attivi (`allow_redirects=True` / `follow_redirects=True`), vettore privilegiato per aggirare controlli superficiali.
     - **SS-006**: Riconosce parametri `webhook` e `callback_url` nel contratto OpenAPI segnalando l'assenza di restrizioni di destinazione.

### 4.3. Metodi Preventivi Raccomandati da OWASP

* **Allowlist di domini, schemi e porte**:
  - Il motore esclude i flussi protetti da funzioni di validazione sanificanti (`pattern-sanitizers` e guardie condizionali).
  - Il normalizzatore distingue le validazioni sicure a livello semantico (`allowlist`) da quelle deboli o incomplete (`blocklist`).
  - L'approccio sicuro è attestato nella fixture [`secure_app/app.py`](file:///Users/marcodonatiello/DetectionCloudSecurityRisk/src/core/api7_ssrf/fixtures/secure_app/app.py): parsing con `urlparse`, verifica rigorosa dello schema (`https`) e controllo su set chiuso `ALLOWED_HOSTS`.
* **Disabilitazione dei Redirect HTTP**:
  - Implementata con severità dedicata nella regola **SS-004**, istruendo la remediation a impostare `allow_redirects=False` in `requests` e `follow_redirects=False` in `httpx`.
* **Convalida a Livello di Contratto**:
  - La regola **SS-006** incentiva l'adozione preventiva di schemi OpenAPI stringenti (`format: uri` combinato con `pattern`).

---

## 5. Metodologia di Validazione e Verifica del Comportamento

La correttezza del modulo è verificata mediante una suite di test automatizzati e un'impalcatura di **ground-truth validation** ([`validate_ground_truth.py`](file:///Users/marcodonatiello/DetectionCloudSecurityRisk/tests/unit/api7_ssrf/validate_ground_truth.py)):

* **Rilevamento dei Flussi Vulnerabili (`vulnerable_app`)**:
  - Verifica che tutte le tipologie di SSRF non protette vengano correttamente identificate:
    - Passaggio diretto di parametri query o JSON verso `requests`, `httpx`, `aiohttp` e `urllib`.
    - Flussi di SSRF parziale con f-string e concatenazioni.
    - Webhook con redirect abilitati.
    - Chiamate dirette o bypass di blocklist verso indirizzi metadata cloud.
* **Assenza di Falsi Allarmi su Codice Protetto (`secure_app`)**:
  - Verifica che gli endpoint protetti da allowlist stringente (con convalida dell'hostname parsato e redirect disabilitati) non generino alcuna segnalazione, attestando l'efficacia dei sanificatori in Taint Mode.
* **Verifica su Repository Target Reale (`repo_target`)**:
  - Conferma l'identificazione della vulnerabilità sull'endpoint reale non mitigato (`POST /api/projects/{id}/import`), mentre l'endpoint corrispondente dotato di allowlist e redirect disabilitati (`POST /api/projects/{id}/import-safe`) risulta regolarmente esente da segnalazioni.

---

## 6. Limiti Attuali e Sviluppi Futuri

Nonostante l'adozione di Taint Mode e il supporto esteso ai client asincroni e alla composizione di URL, rimangono fuori dal perimetro dell'analisi statica alcune dinamiche runtime:

1. **Modulo DAST Attivo con Out-Of-Band (OOB) Interaction**:
   - Per verificare empiricamente a runtime la **Blind SSRF**, è necessario un modulo dinamico in grado di inviare payload contenenti callback listener univoci (stile Interactsh/Burp Collaborator) per intercettare le richieste DNS/HTTP in uscita effettivamente generate dal server.
2. **Protezione da DNS Rebinding e TOCTOU (Time-of-Check to Time-of-Use)**:
   - Se l'applicazione valida l'IP di un dominio e poi delega la risoluzione al client HTTP in momenti distinti, un attaccante può sfruttare record DNS con TTL=0 che risolvono su IP pubblico al controllo e su `127.0.0.1` alla richiesta. Questo fenomeno runtime non è rilevabile a livello di codice applicativo e richiede controlli a livello di socket o proxy egress.
3. **Analisi Taint Inter-Procedurale tra Microservizi / Repository Distinti**:
   - Le regole operano all'interno del modulo analizzato. Qualora il parametro URL sia veicolato attraverso code di messaggi (RabbitMQ, SQS) o microservizi separati prima di giungere al client HTTP, l'analisi intra-servizio necessita di correlazione di traccia distribuita.
