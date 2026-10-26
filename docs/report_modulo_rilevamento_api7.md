# Report Strutturato: Modulo di Rilevamento API7:2023 (SSRF)

Il modulo [`src/core/api7_ssrf`](file:///Users/marcodonatiello/DetectionCloudSecurityRisk/src/core/api7_ssrf) è il componente della piattaforma dedicato all'individuazione e all'analisi statica e contrattuale delle vulnerabilità riconducibili a **OWASP API7:2023 — Server-Side Request Forgery (SSRF)** ([CWE-918](https://cwe.mitre.org/data/definitions/918.html)).

---

## 1. Obiettivo ed Ambito di Analisi

L'obiettivo del modulo è intercettare l'esposizione di endpoint API che effettuano chiamate HTTP o di rete verso risorse remote utilizzando parametri o URI controllati dall'utente privi di adeguata validazione (allowlist, schema sanitization, gestione dei redirect), prevenendo scenari critici quali:
* **Port scanning e scansione della rete interna**: mappatura di servizi su `localhost`, VPC e container contigui.
* **Esfiltrazione di credenziali cloud**: accesso non autorizzato all'Instance Metadata Service (IMDS / `169.254.169.254`).
* **Bypass delle difese perimetrali**: catene di redirect HTTP 30x arbitrarie.

---

## 2. Architettura dei Componenti

Il modulo implementa un approccio ibrido: un motore **SAST semantico con Taint Analysis** (tramite Semgrep) combinato con un motore di **Contract-Level Analysis** su specifiche OpenAPI 3.x.

```
src/core/api7_ssrf/
├── detector.py                  # Entrypoint orchestratore del modulo
├── models.py                    # Dataclass tipizzate: SsrfFinding e SsrfReport
├── semgrep_runner.py            # Wrapper sicuro per esecuzione e isolamento Semgrep
├── normalizer.py                # Parsing dataflow trace, severità, confidenza e mapping
├── rules/
│   └── semgrep_rules.yml        # Regole Semgrep in Taint Mode (SS-001 .. SS-005)
├── layers/
│   └── layer3_openapi.py        # Analisi contrattuale OpenAPI 3.x (SS-006)
├── fixtures/                    # Casi di test sintetici (vulnerable_app e secure_app)
└── docs/
    └── owasp_api7_coverage.md   # Registro di copertura formale e validazione
```

### Ruolo dei Moduli Principali

* [`detector.py`](file:///Users/marcodonatiello/DetectionCloudSecurityRisk/src/core/api7_ssrf/detector.py): Funzione entry point `analyze()`. Coordina l'esecuzione del layer Semgrep e dell'analisi contrattuale OpenAPI, gestisce i timeout e genera il modello finale [`SsrfReport`](file:///Users/marcodonatiello/DetectionCloudSecurityRisk/src/core/api7_ssrf/models.py#L25-L32) con metriche di copertura e riepilogo.
* [`models.py`](file:///Users/marcodonatiello/DetectionCloudSecurityRisk/src/core/api7_ssrf/models.py): Definisce [`SsrfFinding`](file:///Users/marcodonatiello/DetectionCloudSecurityRisk/src/core/api7_ssrf/models.py#L5-L23) (con campi: `source`, `sink`, `validation_found`, `validation_type`, `allow_redirects`, `confidence`, `layer`, `evidence`) e [`SsrfReport`](file:///Users/marcodonatiello/DetectionCloudSecurityRisk/src/core/api7_ssrf/models.py#L25-L32).
* [`semgrep_runner.py`](file:///Users/marcodonatiello/DetectionCloudSecurityRisk/src/core/api7_ssrf/semgrep_runner.py): Gestisce il ciclo di vita dell'eseguibile Semgrep. Individua il binario nel `PATH` di sistema o nel `.venv`, isola la variabile `HOME` in `.tmp` per evitare blocchi di permessi, imposta limitazioni di memoria (`--max-memory 1000` MB) e gestisce i timeout per singolo file e globali.
* [`normalizer.py`](file:///Users/marcodonatiello/DetectionCloudSecurityRisk/src/core/api7_ssrf/normalizer.py): Converte l'output JSON di Semgrep nei modelli interni, estraendo sorgente e destinazione sia dalla `dataflow_trace` nativa di Semgrep sia tramite fallback regex, calcolando il punteggio di confidenza e mappando le severità.
* [`layer3_openapi.py`](file:///Users/marcodonatiello/DetectionCloudSecurityRisk/src/core/api7_ssrf/layers/layer3_openapi.py): Ispeziona contratti OpenAPI 3.x ricercando parametri e proprietà del request body correlati a URL (`webhook`, `callback_url`, `redirect`, `endpoint`, ecc.) privi di vincoli (`format: uri` e regex `pattern`). Supporta anche l'arricchimento in-place della specifica tramite estensione `x-security-analysis`.

---

## 3. Matrice delle Regole di Rilevamento

| Regola | CWE | Categoria | Target / Linguaggio | Modalità | Descrizione Operativa |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SS-001** | CWE-918 | `direct_url_from_input` | Python (`requests`, `httpx`, `aiohttp`) | **Taint Mode** | Traccia parametri utente (query, json, form, header) passati a client HTTP moderni (sincroni e asincroni), inclusi flussi con formattazione stringhe/f-strings (Partial SSRF). |
| **SS-002** | CWE-918 | `direct_url_from_input` | Python (`urllib`) | **Taint Mode** | Rileva input contaminato che fluisce in `urllib.request.urlopen` e `urlretrieve`. |
| **SS-003** | CWE-918 | `direct_url_from_input` | Node.js / Express (`fetch`, `axios`) | **Taint Mode** | Traccia `req.query`, `req.body`, `req.params`, `req.headers` verso chiamate di rete in JavaScript e TypeScript. |
| **SS-004** | CWE-918 | `redirect_following` | Python (`requests`, `httpx`) | **Taint Mode** | Identifica l'uso esplicito di `allow_redirects=True` o `follow_redirects=True` con URL controllati dall'utente (vettore di bypass per allowlist deboli). |
| **SS-005** | CWE-918 | `cloud_metadata_access` | Python, JS, TS | **Pattern Match / Regex** | Intercetta chiamate HTTP dirette verso indirizzi IP e domini critici di cloud metadata (`169.254.169.254`, `metadata.google.internal`, `100.100.100.200`). |
| **SS-006** | CWE-918 | `unvalidated_url_parameter` | OpenAPI 3.x | **Contract Analysis** | Individua campi URL esposti a contratto privi di formattazione (`format: uri`) o privi di pattern regex di allowlist. |

---

## 4. Dettagli di Funzionamento del Motore di Analisi

### 4.1. Taint Analysis (Source $\rightarrow$ Sink)
A differenza dei controlli puramente sintattici, le regole del modulo operano in modalità di propagazione del flusso:
* **Fonti tracciate (Sources)**: `request.args`, `request.json`, `request.form`, `request.headers`, `request.values`, `request.data`, `request.get_json(...)` in Python; `req.query`, `req.body`, `req.params`, `req.headers` in Node.js.
* **Sanificatori riconosciuti (Sanitizers)**: Funzioni di guardia come `validate_url(...)`, `is_valid_url(...)`, `is_allowed(...)` azzerano lo stato di contaminazione prevenendo falsi allarmi su codice bonificato.
* **Partial SSRF**: La contaminazione si propaga attraverso concatenazioni, costrutti `.format()` e f-string (es. `f"https://api.partner.com/v1/{path}"`), intercettando host override o path traversal verso servizi interni.

### 4.2. Calcolo della Confidenza
Il modulo assegna una confidenza calibrata in [`_compute_confidence()`](file:///Users/marcodonatiello/DetectionCloudSecurityRisk/src/core/api7_ssrf/normalizer.py#L45-L58):
* **`0.90`**: Match diretto source $\rightarrow$ sink nello stesso flusso senza guardie.
* **`0.75`**: Presenza di validazione sintattica debole o parziale (es. solo `urlparse` o presenza di `format: uri` senza regex).
* **`0.70`**: Accesso a endpoint di metadata statici (SS-005, dove la chiamata potrebbe essere intenzionale a livello architetturale).

### 4.3. Classificazione delle Difese
Il normalizzatore classifica la strategia difensiva adottata nel codice:
* **Allowlist**: Riconosce controlli positivi espliciti (`allowlist`, `whitelist`, `is_allowed`).
* **Blocklist**: Segnala controlli deboli o aggirabili basati su liste nere (`blacklist`, `blocklist`, `not_allowed`).
* **None**: Nessuna guardia identificata.

---

## 5. Validazione Ground Truth e Risultati

La verifica del modulo è documentata in [`owasp_api7_coverage.md`](file:///Users/marcodonatiello/DetectionCloudSecurityRisk/src/core/api7_ssrf/docs/owasp_api7_coverage.md) ed eseguibile tramite [`tests/unit/api7_ssrf/validate_ground_truth.py`](file:///Users/marcodonatiello/DetectionCloudSecurityRisk/tests/unit/api7_ssrf/validate_ground_truth.py):

* **Target Vulnerabili (`vulnerable_app`)**: Rilevamento al 100% di tutti i pattern di SSRF non mitigati (client sincroni, asincroni, urllib, redirect attivi, IMDS).
* **Target Protetti (`secure_app`)**: Nessun falso positivo (FPR: 0%) su codice che effettua parsing con `urlparse`, validazione dello schema `https`, allowlist chiusa di hostname e `allow_redirects=False`.
* **Verifica su Repository Reale (`repo_target`)**:
  * Endpoint `POST /api/projects/{id}/import`: Correttamente segnalato su riga 117 (True Positive SS-001).
  * Endpoint `POST /api/projects/{id}/import-safe`: Nessuna segnalazione (True Negative).

---

## 6. Limiti Noti e Possibili Estensioni

1. **Blind SSRF a Runtime (DAST)**: L'analisi statica rileva la presenza del flusso rischioso, ma non può confermare empiricamente l'esfiltrazione Out-Of-Band (OOB) senza un listener DNS/HTTP esterno (es. integrazione stile Interactsh).
2. **DNS Rebinding e TOCTOU**: Se la validazione dell'IP e la risoluzione del socket avvengono in momenti distinti, un record DNS con TTL=0 può aggirare le allowlist a runtime; questo scenario richiede mitigazioni a livello di proxy egress o socket resolver.
3. **Flussi Asincroni Distribuiti**: Se l'URL dell'utente transita attraverso un message broker (es. Kafka, RabbitMQ, SQS) prima di essere consumato dal client HTTP in un worker separato, il tracciamento intra-procedurale necessita di correlazione di traccia distribuita.
