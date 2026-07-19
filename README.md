# Cloud Security Risk Assessment & API Vulnerability Detection Platform

[![CI](https://github.com/MarcoDonatiello04/DetectionCloudSecurityRisk/actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-351%20passed-brightgreen.svg)](#qualita-del-codice-e-test)
[![Coverage](https://img.shields.io/badge/coverage-76%25-green.svg)](#qualita-del-codice-e-test)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](#prerequisiti)
[![Ruff](https://img.shields.io/badge/lint-ruff-261230.svg)](https://docs.astral.sh/ruff/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Una piattaforma unificata per l'analisi statica e dinamica della sicurezza delle API cloud e dell'infrastruttura (IaC). Lo strumento automatizza il rilevamento delle vulnerabilità a livello infrastrutturale e applicativo, correla i findings statici con prove empiriche di runtime, calcola un punteggio di rischio pesato, fornisce raccomandazioni di remediation immediate (offline e con AI locale) e offre una ricca interfaccia desktop (GUI PySide6) per la visualizzazione delle problematiche riscontrate e il catalogo degli endpoint.

---

## Architettura del Sistema

La piattaforma è progettata seguendo una **Clean Architecture** event-driven e si articola in quattro fasi logiche fondamentali:

1. **Discovery & Static Analysis (IaC & AST)**:
   - **Checkov Adapter**: Esegue l'analisi statica su configurazioni Terraform per rilevare misconfiguration (storage pubblici, IAM troppo permissivi, log disattivati).
   - **Semgrep Adapter**: Scansiona il codice sorgente (Python, JS, Java) per mappare preventivamente le rotte API esposte e controllare lo stato dell'autenticazione.
   - **Spectral Adapter**: Valuta i contratti OpenAPI rispetti alle linee guida OWASP API Security Top 10.
2. **Dynamic Seeding**:
   - **Database Seeder**: Popola deterministicamente lo stato dell'applicazione target prima degli attacchi attivi per garantire la consistenza ed evitare race condition nel DB.
3. **Attack & Runtime Stimulation (D-AST)**:
   - **OWASP ZAP (differential scan)**: Stimola gli endpoint dinamici con token differenziali (User A vs User B vs Anonimo) per scovare vulnerabilità logiche come BOLA (Broken Object Level Authorization) e Broken Authentication.
   - **Mitmproxy Addon**: Intercetta ed estrae il traffico di rete reale a runtime per raccogliere evidenze di chiamate non autorizzate o endpoint non documentati (Shadow APIs).
4. **Risk Correlation & Scoring**:
   - **RiskCorrelationEngine**: Unisce i findings statici e dinamici mediante chiavi basate su URL normalizzati (tramite `APIEndpointNormalizer`). In presenza di verifiche empiriche positive (es: exploit confermato a runtime), eleva la severità a `CRITICAL` o `HIGH` e ricalcola il punteggio di rischio normalizzato (0-10) in base al contesto.

---

## Prerequisiti

### Requisiti di Sistema
- **Python**: Versione `3.10` o superiore.
- **Node.js / npm**: Richiesto per l'esecuzione di `@stoplight/spectral-cli` tramite `npx`.
- **Docker & Docker Compose**: Richiesto per sollevare i container di Keycloak, OWASP ZAP, Mitmproxy e dell'applicazione di test.
- **Terraform CLI**: Necessario per il provisioning dell'infrastruttura locale su LocalStack.

### Servizi Cloud Locali (Emulati)
- **LocalStack**: Emulazione locale dei servizi AWS (S3, DynamoDB, Lambda, API Gateway).
- **Keycloak**: Server di identità per la gestione di token JWT OIDC.

---

## Installazione

1. **Clona il repository**:
   ```bash
   git clone https://github.com/MarcoDonatiello04/DetectionCloudSecurityRisk.git
   cd DetectionCloudSecurityRisk
   ```

2. **Inizializza l'ambiente virtuale di Python**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Assicurati che Docker sia in esecuzione**, quindi avvia la suite dei container:
   ```bash
   docker compose up -d
   ```

---

## Configurazione

### File ambientali
I file di configurazione e le chiavi per i test DAST vengono autogenerati nella cartella `config/environments/` al termine della fase di analisi IaC.
- **`config/environments/.target_env`**: Contiene gli endpoint URL per gli attacchi esposti su LocalStack.

### File di configurazione degli scanner
- **`config/scanner_configs/spectral-owasp.yaml`**: Regole Spectral per il contratto OpenAPI basate sullo standard OWASP.
- **`config/scanner_configs/route-detect.yaml`**: Regole Semgrep per il tracciamento dei mapping di route applicative.

---

## Istruzioni per l'Esecuzione

L'esecuzione del progetto è strutturata in 3 fasi automatizzate tramite un `Makefile` centrale:

### Fase 1: Setup dell'Ambiente e Provisioning Keycloak
Configura il realm, i client e le identità di test fittizie su Keycloak (`user_a` per la vittima e `user_b` per l'attaccante):
```bash
make setup-env
```

### Fase 2: Provisioning Cloud (Terraform) e Analisi IaC
Esegue il deployment dell'infrastruttura locale vulnerabile su LocalStack ed avvia la scansione statica con Checkov:
```bash
make iac-analysis
```

### Fase 3: Esecuzione Pipeline di API Security & D-AST
Esegue il linter dei contratti OpenAPI, analizza i sorgenti con Semgrep, esegue gli attacchi dinamici contro le rotte per convalidare BOLA e Broken Auth, esegue il risk rating e genera il report unificato e l'inventario API:
```bash
make api-security
```

### Fase 4: Avvio Dashboard Interattiva (Desktop App PySide6)
Dopo aver completato l'analisi, è possibile avviare l'interfaccia desktop GUI per esplorare in modo interattivo i risultati (findings Checkov, violazioni OpenAPI, rotte BOLA/D-AST) ed esaminare le raccomandazioni di remediation del motore intelligente:
```bash
python3 cloud_security_analyzer/launcher.py
```


### Pulizia dell'ambiente
Per spegnere i container ed eliminare i file di stato temporanei:
```bash
make clean
```

---

## Qualita del Codice e Test

Il progetto adotta un quality gate unico, condiviso tra ambiente locale e CI
(GitHub Actions, `.github/workflows/ci.yml`). Tutta la configurazione degli
strumenti risiede in un solo file, `pyproject.toml`.

| Comando | Cosa fa |
| --- | --- |
| `make install` | Installa le dipendenze runtime (pinnate) e gli strumenti di sviluppo |
| `make lint` | Analisi statica e verifica formattazione con **Ruff** |
| `make format` | Applica fix automatici e formattazione |
| `make test` | Esegue l'intera suite `pytest` con report di coverage |
| `make check` | Quality gate completo: lint + test (identico alla CI) |

**Stato attuale:** 351 test superati, 3 skippati, **76%** di copertura su
`src/` e `remediation/`; `ruff check` e `ruff format --check` puliti su tutto
il codice di progetto.

### Organizzazione dei test
- `tests/unit/` — test isolati (event bus, normalizzatore dei path, adapter).
- `tests/integration/` — test che attraversano piu componenti reali.
- `src/core/<vulnerabilita>/tests/` — test per singolo rilevatore OWASP, inclusi
  i test di *ground truth* che confrontano l'output degli scanner con le
  vulnerabilita note delle applicazioni bersaglio.
- `test_targets/` — applicazioni vulnerabili e sicure usate come **input** degli
  scanner. Sono escluse dalla raccolta di pytest (`norecursedirs`): non sono
  test del progetto e i loro package inquinerebbero `sys.path`.

Per eseguire un singolo modulo:
```bash
.venv/bin/python -m pytest tests/unit/test_clean_arch.py
```

---

## Struttura delle Cartelle

```
├── cloud_security_analyzer/   # Dashboard desktop (PySide6) basata su pattern MVC
│   ├── controllers/           # Controller MVC per la gestione delle schermate
│   ├── gui/                   # Viste ed elementi grafici di interfaccia
│   ├── models/                # Modelli dei dati per findings ed endpoint
│   ├── services/              # Logica di business e integrazione pipeline
│   ├── widgets/               # Componenti e grafici custom riutilizzabili
│   └── launcher.py            # Entrypoint per l'avvio della dashboard desktop GUI
├── config/
│   ├── environments/          # Contiene le variabili d'ambiente generate (.target_env)
│   └── scanner_configs/       # Contiene le configurazioni degli scanner (rulesets)
├── fixtures/infrastructure_misconfiguration/  # File infrastrutturali IaC di test
│   └── terraform/             # Configurazioni Terraform (vulnerable_infra.tf, main.tf)
├── remediation/               # Modulo offline di Remediation Intelligence
│   ├── knowledge_base/        # Database locale delle remediation e cache locale
│   ├── models/                # Modelli dei dati del modulo di remediation
│   ├── llm_provider.py        # Integrazione offline con LLM locale (Ollama)
│   └── remediation_engine.py  # Motore di raccomandazione ed elaborazione fallback
├── scripts/                   # Script bash di orchestrazione della pipeline
│   ├── 1_setup_environment.sh
│   ├── 2_iac_analysis.sh
│   └── 3_api_security.sh
├── src/                       # Codice sorgente dell'Orchestratore di Sicurezza (Python)
│   ├── application/           # Logica applicativa, Event Bus e Risk engine
│   ├── core/                  # Logica principale D-AST (dynamic_orchestrator.py)
│   ├── domain/                # Entità di dominio ed eccezioni (entities.py, events.py)
│   ├── infrastructure/        # Adattatori infrastrutturali per gli scanner esterni
│   ├── normalization/         # Modulo di normalizzazione URL delle API
│   ├── plugins/               # Plugin detector (bola_detector, shadow_api_detector)
│   └── presentation/          # Esposizione API (FastAPI) e CLI di comando (cli.py)
├── test_targets/              # Target di test consolidati (tutti i moduli)
│   ├── bola/                  # BOLA: microservizio Flask + openapi.yaml
│   ├── broken_authentication/ # API2: vulnerable_app, secure_app, README, answer_key
│   ├── security_misconfiguration/           # API8: vulnerable_app, secure_app
│   ├── broken_function_level_authorization/ # API5: vulnerable_app, secure_app
│   ├── unrestricted_resource_consumption/   # API4: vulnerable_app, secure_app
│   └── docker-compose.yml     # Orchestrazione unificata di tutti i target
├── tests/                     # Test unitari e di integrazione
├── output/                    # Destinazione dei report JSON (generati a runtime)
├── docker-compose.yml         # Servizi Docker (ZAP, Keycloak, Mitmproxy)
├── Makefile                   # Target per il workflow locale
└── requirements.txt           # Dipendenze Python del progetto
```

---

## Esempi di Output

### Report dei Findings Generato (`output/unified_security_report.json`)
```json
[
  {
    "finding_id": "semgrep-a1b2c3d4e5f6",
    "source": "SEMGREP",
    "category": "AUTHENTICATION",
    "title": "Endpoint API non protetto rilevato (Statico)",
    "description": "L'endpoint API [flask]: GET /api/orders/{id} non sembra richiedere controlli di autenticazione a livello statico.",
    "severity": "CRITICAL",
    "confidence": 1.0,
    "rule_id": "unauthenticated-api-route",
    "rule_name": "API Route Detection",
    "location": {
      "file_path": "test_targets/bola/app.py",
      "start_line": 112,
      "end_line": null,
      "code_snippet": null
    },
    "api": {
      "endpoint": "/api/orders/{id}",
      "method": "GET",
      "base_url": "http://localhost:5000",
      "api_version": null,
      "requires_authentication": false
    },
    "validation_status": "CONFIRMED",
    "runtime_evidence": {
      "tested_url": "http://localhost:5000/api/orders/100",
      "http_status": 200,
      "response_time_ms": null,
      "response_headers": {},
      "response_snippet": "{\"resource_name\": \"orders\", \"resource_id\": \"100\", \"owner\": \"user_a\", \"accessed_by\": \"user_b\"}",
      "accessible_without_auth": true,
      "rate_limit_detected": null
    },
    "risk_context": {
      "internet_exposed": true,
      "sensitive_data_detected": null,
      "public_resource": null,
      "exploitable": true,
      "attack_complexity": null,
      "impact": null
    },
    "correlation_key": "api:GET:/api/orders/{id}",
    "related_findings": [
      "runtime_validator-9f8e7d6c5b4a"
    ],
    "owasp_api_category": null,
    "cwe_id": null,
    "cve_id": null,
    "remediation": "Abilitare il middleware di validazione JWT e verificare l'ownership della risorsa.",
    "tags": [
      "OWASP-API-1",
      "BOLA"
    ],
    "references": [],
    "raw_data": {
      "correlated_risk_score": 9.6
    },
    "detected_at": "2026-06-02T12:44:24.000000"
  }
]
```

### Dashboard Desktop GUI & Remediation Intelligence
L'applicazione desktop basata su PySide6 fornisce una visualizzazione ricca e interattiva delle metriche del progetto e supporta le seguenti sezioni:
1. **Overview Dashboard**: Statistiche generali, conteggio findings per severità (con grafici) e percentuale di confidenza runtime.
2. **Findings Viewer**: Elenco dettagliato di tutte le vulnerabilità con filtri per categoria e severità. Integra il motore di **Remediation Intelligence** che estrae raccomandazioni da un database offline locale o genera risposte intelligenti interfacciandosi localmente con modelli AI (es. Ollama / Llama3).
3. **API Catalog**: Mappa in tempo reale le rotte documentate e individua le **Shadow API** scoperte analizzando il traffico di rete a runtime.
4. **Infrastructure (IaC)**: Dettaglio delle violazioni statiche rilevate da Checkov sui file Terraform.
5. **Console Logs**: Log dettagliati della esecuzione della pipeline CLI.

Per lanciare la Dashboard Desktop:
```bash
python3 cloud_security_analyzer/launcher.py
```

---

## Stato del Progetto e Limiti Noti

Il sistema e un **proof of concept** funzionante e riproducibile end-to-end
sull'ambiente di riferimento descritto in questo README. I confini attuali sono
dichiarati esplicitamente:

- **Analisi vincolata all'ambiente di riferimento.** Gli scanner sono validati
  contro i bersagli in `test_targets/` (incluso crAPI) e contro l'infrastruttura
  emulata da LocalStack/Keycloak. L'esecuzione su una repository arbitraria e
  possibile ma non garantita: l'inferenza automatica dello stack, dei percorsi di
  configurazione e delle credenziali di test non e ancora generalizzata. E il
  principale lavoro di estensione previsto.
- **Fase dinamica dipendente dai container.** I test D-AST (BOLA, Broken
  Authentication, BOPLA) richiedono la suite Docker attiva; senza di essa la
  pipeline degrada alla sola analisi statica.
- **Remediation con LLM opzionale.** In assenza di un server Ollama locale il
  motore ricade su una knowledge base offline deterministica, quindi la suite di
  test resta verde anche senza modello.

---

## Licenza

Questo progetto è distribuito sotto licenza **MIT**. Consultare il file `LICENSE` per ulteriori informazioni.