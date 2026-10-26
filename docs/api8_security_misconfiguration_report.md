# Report Tecnico: Modulo API8:2023 — Security Misconfiguration

## 1. Introduzione ed Obiettivo

Il modulo [`src/core/api8_security_misconfig`](file:///Users/marcodonatiello/DetectionCloudSecurityRisk/src/core/api8_security_misconfig) è il componente della piattaforma dedicato al rilevamento statico delle vulnerabilità classificate come **OWASP API8:2023 — Security Misconfiguration**.

L'obiettivo del modulo è intercettare in modo deterministico, veloce e privo di dipendenze esterne le cattive configurazioni di sicurezza presenti nel codice applicativo delle API (Flask, FastAPI, Django, Express.js) e nei relativi manifesti di dipendenze.

---

## 2. Implementazione e Punti di Forza

L'architettura del modulo si articola su un orchestratore centrale ([`detector.py`](file:///Users/marcodonatiello/DetectionCloudSecurityRisk/src/core/api8_security_misconfig/detector.py)), un modello dati tipizzato ([`models.py`](file:///Users/marcodonatiello/DetectionCloudSecurityRisk/src/core/api8_security_misconfig/models.py)) e una suite di **9 regole specializzate** suddivise per categoria OWASP e CWE.

```
src/core/api8_security_misconfig/
├── detector.py                  # Orchestratore: scansione file, parsing AST, filtri e aggregazione
├── models.py                    # Strutture dati MisconfigFinding e MisconfigReport
└── rules/
    ├── cors_wildcard.py             # SC-001 (CWE-942): CORS permissivo / wildcard
    ├── debug_mode.py                # SC-002 (CWE-94):  Modalità debug e live reload attive
    ├── verbose_error_handler.py     # SC-003 (CWE-209): Esposizione di traceback e dettagli eccezione
    ├── missing_security_headers.py  # SC-004 (CWE-693): Assenza di middleware per security headers
    ├── hardcoded_secret.py          # SC-005 (CWE-798): Segreti cablati con Entropia di Shannon
    ├── missing_cors_policy.py       # SC-006 (CWE-942): Assenza totale di configurazione CORS
    ├── vulnerable_dependency.py     # SC-007 (CWE-1395/1104): Analisi SCA delle dipendenze
    ├── unrestricted_http_methods.py # SC-008 (CWE-650/749): Verbi HTTP permissivi o errati
    └── missing_cache_control.py     # SC-009 (CWE-525/524): Mancanza di Cache-Control: no-store
```

### Punti di Forza dell'Analisi Semantica AST

A differenza di strumenti basati su semplici espressioni regolari (regex) o pattern matching testuale grezzo, il modulo sfrutta l'**Abstract Syntax Tree (AST)** per ricostruire la struttura logica del codice:
- Distingue istruzioni attive da commenti e stringhe di documentazione.
- Analizza le relazioni gerarchiche tra funzioni, decoratori, parametri e payload di ritorno.
- Calcola parametri quantitativi di confidenza e metriche matematiche (Entropia di Shannon) per prevenire l'alert fatigue e i falsi positivi.
- Fornisce per ogni segnalazione una raccomandazione prescrittiva di bonifica (`missing_guard`) direttamente utilizzabile dagli sviluppatori.

---

### Dettaglio delle Regole Implementate

#### SC-001 — CORS Permissivo / Wildcard (CWE-942)
* **File**: [`cors_wildcard.py`](file:///Users/marcodonatiello/DetectionCloudSecurityRisk/src/core/api8_security_misconfig/rules/cors_wildcard.py)
* **Funzionamento e Punti di Forza**:
  - Rileva l'uso indiscriminato di origini jolly (`origins="*"`, `allow_origins=["*"]`) sia su Flask che su Express e FastAPI.
  - **Correlazione contestuale avanzata**: in FastAPI (`CORSMiddleware`), analizza congiuntamente `allow_origins=["*"]` e `allow_credentials=True`. Quando le credenziali sono abilitate insieme al wildcard, la severità viene elevata a **`CRITICAL`**, riconoscendo la gravità di una configurazione che espone token e cookie di sessione a chiamate cross-origin arbitrarie.

#### SC-002 — Modalità Debug e Live Reload Attivi (CWE-94)
* **File**: [`debug_mode.py`](file:///Users/marcodonatiello/DetectionCloudSecurityRisk/src/core/api8_security_misconfig/rules/debug_mode.py)
* **Funzionamento e Punti di Forza**:
  - Individua le chiamate AST ai runner dei server web (`app.run(debug=True)` in Flask e `uvicorn.run(..., debug=True, reload=True)`).
  - Riconosce i valori booleani letterali hardcoded suggerendo la conversione a letture sicure da variabili d'ambiente (`os.environ`).

#### SC-003 — Error Handling Verboso e Leak di Stack Trace (CWE-209)
* **File**: [`verbose_error_handler.py`](file:///Users/marcodonatiello/DetectionCloudSecurityRisk/src/core/api8_security_misconfig/rules/verbose_error_handler.py)
* **Funzionamento e Punti di Forza**:
  - Utilizza un'architettura a **doppio visitor AST**: `ErrorHandlerVisitor` identifica i decoratori `@app.errorhandler`, mentre `VerboseBodyVisitor` analizza il flusso di dati interno alla funzione.
  - Intercetta non solo le chiamate esplicite a `traceback.format_exc()` o `traceback.print_exc()`, ma anche conversioni dirette dell'eccezione (`str(e)`, `repr(e)`) e **interpolazioni in f-string (`JoinedStr`)** restituite all'interno di risposte `jsonify(...)`, bloccando fughe di informazioni sull'architettura interna.

#### SC-004 — Assenza Globale di Security Headers (CWE-693)
* **File**: [`missing_security_headers.py`](file:///Users/marcodonatiello/DetectionCloudSecurityRisk/src/core/api8_security_misconfig/rules/missing_security_headers.py)
* **Funzionamento e Punti di Forza**:
  - **Analisi globale a livello di sistema**: invece di generare centinaia di segnalazioni duplicate per ogni rotta, scansiona l'intero target alla ricerca di middleware e configurazioni centralizzate (es. `Talisman`, `helmet`, HSTS, CSP, X-Frame-Options).
  - Se il progetto non adotta alcuna linea difensiva sugli header, genera **un unico finding consolidato**, fornendo la configurazione corretta da applicare a monte.

#### SC-005 — Segreti e Credenziali Hardcoded (CWE-798)
* **File**: [`hardcoded_secret.py`](file:///Users/marcodonatiello/DetectionCloudSecurityRisk/src/core/api8_security_misconfig/rules/hardcoded_secret.py)
* **Funzionamento e Punti di Forza**:
  - Ispezione mirata sui nodi di assegnazione AST associati a identificatori sensibili (`jwt_secret`, `stripe_key`, `api_key`, `token`, `password`, ecc.).
  - **Analisi dell'Entropia di Shannon**: calcola la complessità della stringa assegnata per distinguere chiavi reali ad alta entropia (> 3.5 bit/carattere) da stringhe semplici.
  - **Filtri anti-falsi positivi**: scarta stringhe corte (< 8 caratteri), stringhe contenenti spazi e una lista estesa di placeholder convenzionali (`"changeme"`, `"test"`, `"your_secret_here"`, `"todo"`).

#### SC-006 — Assenza Completa di Configurazione CORS (CWE-942)
* **File**: [`missing_cors_policy.py`](file:///Users/marcodonatiello/DetectionCloudSecurityRisk/src/core/api8_security_misconfig/rules/missing_cors_policy.py)
* **Funzionamento e Punti di Forza**:
  - Colma la discrepanza in cui un'applicazione API è esposta a client browser ma non dichiara alcuna policy CORS.
  - Verifica la presenza di un framework web API attivo (Flask, FastAPI, Express) e accerta se esista un middleware CORS: in caso di totale assenza, segnala la necessità di definire un'allowlist esplicita.

#### SC-007 — Software Composition Analysis (SCA) (CWE-1395 / CWE-1104)
* **File**: [`vulnerable_dependency.py`](file:///Users/marcodonatiello/DetectionCloudSecurityRisk/src/core/api8_security_misconfig/rules/vulnerable_dependency.py)
* **Funzionamento e Punti di Forza**:
  - Analizza i file di configurazione delle dipendenze (`requirements.txt`, `package.json`).
  - **Rilevamento unpinned**: segnala pacchetti senza vincolo di versione o con wildcard (`*`, `>=*`), che espongono il sistema a build non riproducibili e ad attacchi supply chain.
  - **Database CVE offline**: confronta le versioni con un catalogo di vulnerabilità ad alto impatto per componenti web fondamentali (es. Flask < 2.2.5 [CVE-2023-30861], Werkzeug < 2.2.3 [CVE-2023-25577], PyYAML < 5.4 [CVE-2020-14343], urllib3 < 1.26.18, Express < 4.19.2) tramite confronto semantico (`packaging.specifiers.SpecifierSet`).

#### SC-008 — Restrizione dei Verbi HTTP (CWE-650 / CWE-749)
* **File**: [`unrestricted_http_methods.py`](file:///Users/marcodonatiello/DetectionCloudSecurityRisk/src/core/api8_security_misconfig/rules/unrestricted_http_methods.py)
* **Funzionamento e Punti di Forza**:
  - Ispeziona i decoratori `@app.route`:
    - Rileva operazioni mutanti (es. percorsi contenenti `/delete`, `/update`, `/create`, `/reset`, `/transfer`) che non specificano il parametro `methods=[...]`, accettando di default il metodo `GET` e rendendo l'operazione vulnerabile a CSRF e prefetching indesiderato del browser.
    - Rileva route con liste di metodi eccessivamente permissive (presenza contemporanea di `>= 5` verbi HTTP) o handler catch-all (`app.all()` in Express).

#### SC-009 — Cache-Control Mancante su Dati Privati (CWE-525 / CWE-524)
* **File**: [`missing_cache_control.py`](file:///Users/marcodonatiello/DetectionCloudSecurityRisk/src/core/api8_security_misconfig/rules/missing_cache_control.py)
* **Funzionamento e Punti di Forza**:
  - Risponde in modo mirato allo **Scenario #2 di OWASP API8:2023** (conversazioni private o dati personali memorizzati nella cache del browser a causa della mancanza di direttive no-cache).
  - Rintraccia le route che gestiscono dati sensibili o privati (`/dm`, `/messages`, `/user`, `/profile`, `/orders`, `/tokens`, `/billing`) e verifica se il controller o un hook globale (`@app.after_request`) imposta l'header `Cache-Control: no-store, private`.
  - Isola il codice sorgente attivo dai commenti per evitare falsi negativi e fornisce la prescrizione per disabilitare la memorizzazione temporanea lato client.

---

## 3. Limiti del Modulo (Moduli Non Implementati)

Poiché il modulo opera esclusivamente mediante analisi statica del codice sorgente (SAST/AST) e dei manifesti, alcune aree dello standard OWASP API8 che dipendono dal comportamento dinamico di rete o da servizi esterni non possono essere coperte da questo modulo e richiedono moduli architetturali separati:

1. **Modulo DAST per HTTP Request Smuggling / Desync (CWE-444)**:
   * Le discrepanze di interpretazione dei messaggi HTTP lungo la catena di server (es. divergenze tra reverse proxy e backend server sulla precedenza tra header `Content-Length` e `Transfer-Encoding`) non sono presenti nel codice applicativo. La loro rilevazione richiede necessariamente un **modulo dinamico attivo (DAST)** dedicato all'invio di probe malformati con analisi dei tempi di risposta e dei disallineamenti di socket.

2. **Modulo DAST per la Sonda dei Verbi a livello Server/Proxy (es. `TRACE` / `TRACK`)**:
   * Mentre il modulo statico disciplina i metodi definiti nel codice applicativo (Flask/FastAPI), l'abilitazione di metodi pericolosi a livello di web server o proxy (come il comando `TRACE`, impiegabile in attacchi Cross-Site Tracing) dipende dalla configurazione a runtime del server HTTP (Nginx, Apache, Envoy, Uvicorn). Questo controllo richiede un **modulo dinamico di scansione attiva** che effettui probe HTTP diretti verso il listener di rete.

3. **Modulo SCA con Sincronizzazione Live di Feed CVE Esterni**:
   * L'analisi delle dipendenze del modulo opera tramite un motore statico locale e un database offline di vulnerabilità critiche note. L'interrogazione continua e sincrona di banche dati remote in tempo reale (come il National Vulnerability Database - NVD o le API di OSV.dev) richiede un **modulo SCA online dedicato**, dotato di connettività di rete e gestione delle cache locali dei feed.
