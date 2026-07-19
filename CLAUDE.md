# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Piattaforma unificata per l'analisi statica e dinamica della sicurezza di API cloud e infrastruttura (IaC). Combina scanner statici (Checkov su Terraform, Semgrep su codice sorgente, Spectral su contratti OpenAPI) con attacchi dinamici (D-AST via OWASP ZAP, cattura traffico via Mitmproxy) per rilevare vulnerabilità OWASP API Security Top 10 (BOLA, Broken Authentication, BOPLA, BFLA, SSRF, ecc.), correlare i findings statici con prove empiriche runtime, calcolare un risk score pesato e presentare tutto tramite una dashboard FastAPI.

## Comandi principali

```bash
make install          # dipendenze runtime + ruff/pytest-cov
make lint              # ruff check + ruff format --check
make format             # ruff check --fix + ruff format
make test               # pytest con coverage (src + remediation)
make check              # lint + test (identico alla CI)

make setup-env          # provisioning Keycloak (realm, client, utenti user_a/user_b)
make iac-analysis        # provisioning Terraform su LocalStack + scansione Checkov
make api-security         # Spectral + Semgrep + attacchi D-AST + risk scoring + report unificato
make dashboard           # avvia dashboard su http://localhost:8000 (make dashboard DASHBOARD_PORT=8080)
make stop-dashboard       # libera la porta della dashboard da istanze precedenti
make clean               # docker compose down -v + rimozione stato Terraform/.target_env

make bola-repo-target    # scansione BOLA su una repo target arbitraria cooperante (vedi test_targets/repo_target)
make semgrep-repo-target   # inventario endpoint (Semgrep) della repo target
make spectral-repo-target  # analisi contratto OpenAPI della repo target (ruleset OWASP)
make core-modules-repo-target  # moduli Core non-BOLA (Broken Auth, BOPLA, BFLA, SSRF, URC, ...) sulla repo target
```

Eseguire un singolo file/modulo di test:
```bash
.venv/bin/python -m pytest tests/unit/test_clean_arch.py
.venv/bin/python -m pytest src/core/security_misconfiguration/tests/ -k nome_test
```

Runner CLI in `entrypoints/runners/` (vanno lanciati dalla radice con `PYTHONPATH=.`):
```bash
PYTHONPATH=. .venv/bin/python entrypoints/runners/run_unified_core_scanners.py
PYTHONPATH=. .venv/bin/python entrypoints/runners/run_all_security_tests.py --help
```

| Runner | Nota |
| --- | --- |
| `run_unified_core_scanners.py` | Tutti gli scanner Core in sequenza, alimenta la card "Panoramica Sicurezza" |
| `run_all_security_tests.py` | Pipeline completa dei tre scanner principali |
| `run_all_validations.py` | Campagna di validazione (`--include-crapi` per crAPI) |
| `run_ground_truth_validation.py` | Confronto in cieco app vulnerabile vs sicura |
| `run_crapi_validation.py` | Richiede i container crAPI attivi |
| `run_bola_scan.py`, `run_bola_dynamic_demo.py` | **30+ minuti**, attacchi dinamici reali con snapshot/rollback dello stato; richiedono il target attivo |
| `run_bola_repo_target.py` | Scansione BOLA riutilizzabile su repo target arbitraria (usato da `make bola-repo-target`) |
| `run_broken_auth_scan.py` | Richiede Keycloak attivo |

Le scansioni senza BOLA (statiche + D-AST leggero) impiegano circa 15-20 secondi; qualunque scansione che includa il modulo BOLA supera i 30 minuti a causa delle chiamate di rete reali.

## Architettura

Clean Architecture event-driven, quattro fasi logiche:

1. **Discovery & Static Analysis (IaC & AST)** — `src/infrastructure/adapters/`: `checkov_adapter.py` (Terraform misconfiguration), `semgrep_adapter.py` (mapping rotte API + stato auth), `spectral_adapter.py` (contratti OpenAPI vs OWASP API Top 10).
2. **Dynamic Seeding** — popola deterministicamente lo stato dell'app target (utenti `user_a`/`user_b` su Keycloak) prima degli attacchi attivi, per evitare race condition.
3. **Attack & Runtime Stimulation (D-AST)** — `zap_adapter.py` (differential scan con token di `user_a` vs `user_b` vs anonimo per BOLA/Broken Auth) e `src/infrastructure/adapters/mitmproxy/addon.py` (cattura traffico reale per scovare Shadow API).
4. **Risk Correlation & Scoring** — `src/application/correlation/engine.py`: unisce findings statici e dinamici tramite chiavi su URL normalizzati (`src/normalization/normalizer.py`, classe `APIEndpointNormalizer`); in presenza di conferma empirica runtime eleva la severità e ricalcola il risk score (0-10, vedi `docs/adr/adr-001-risk-scoring.md` per la formula pesata).

### Layer principali (`src/`)

- `domain/` — entità (`entities.py`, es. `Finding`), eventi (`events.py`), eccezioni, interfacce astratte (`interfaces.py`: `IScanner`, `IDetector`, `IRemediation`, `IEventBus`).
- `application/` — `event_bus.py` (in-memory event bus thread-safe), `orchestrator.py` (coordina le fasi), `plugin_loader.py` (carica i plugin/detector dinamici a runtime), `correlation/engine.py` (risk correlation engine).
- `infrastructure/adapters/` — un adapter per ogni tool esterno, traduce l'output grezzo (JSON/XML) nel modello di dominio unificato `Finding`.
- `core/<vulnerabilita>/` — un modulo autosufficiente per ciascun rilevatore OWASP (`object_level_authorization` = BOLA, `broken_authentication`, `broken_function_level_authorization`, `broken_object_property_level_access` = BOPLA, `security_misconfiguration`, `server_side_request_forgery`, `unrestricted_resource_consumption`, `unsafe_consumption`), ciascuno con proprie `rules/`, `fixtures/` e `tests/`.
- `plugins/detectors/` — detector dinamici (es. `shadow_api_detector.py`) caricati da `PluginLoader`, comunicano solo tramite l'Event Bus sottoscrivendo/emettendo eventi (`EVENT_STATIC_SCAN_COMPLETED`, `EVENT_TRAFFIC_CAPTURED`, `EVENT_FINDING_DETECTED`).
- `presentation/` — `rest_api.py` (FastAPI, servito da `make dashboard`), `cli.py`, template HTML in `templates/`.

Il disaccoppiamento via Event Bus è una scelta architetturale deliberata (vedi `docs/adr/adr-002-architecture-separation.md`): scanner, risk engine e reporter non si conoscono direttamente, comunicano solo tramite eventi — questo è il motivo per cui aggiungere un nuovo scanner/detector non richiede modifiche all'orchestratore.

### Gestione credenziali (ADR-003)

Le credenziali (Keycloak, AWS/LocalStack) e gli endpoint dinamici vengono gestiti via variabili d'ambiente + file dotenv, mai committati:
- `config/environments/.target_env` — generato automaticamente dallo script di provisioning Terraform (contiene l'URL invoke di API Gateway estratto dagli output).
- `.env` (da `.env.example`) — parametri fissi/di default.

### `remediation/`

Modulo offline di Remediation Intelligence: `remediation_engine.py` estrae raccomandazioni da una knowledge base locale (`knowledge_base/`) oppure, se disponibile un server Ollama locale, genera risposte via LLM (`llm_provider.py`). Senza Ollama il motore ricade sulla knowledge base deterministica (i test restano verdi in entrambi i casi).

## Organizzazione dei test

Due collocazioni distinte, per una ragione precisa:

- **Test accanto al modulo** — `src/core/<vulnerabilita>/tests/`: ogni rilevatore OWASP è un'unità autosufficiente con proprie regole, fixture e test (inclusi i test di *ground truth* contro le vulnerabilità note dei target). I path sono relativi al modulo, quindi restano accanto al codice che verificano.
- **Test trasversali** — `tests/unit/` (componenti condivisi: event bus, normalizzatore path, adapter scanner) e `tests/integration/` (test multi-componente non legati a un singolo modulo OWASP).
- **`test_targets/`** — applicazioni vulnerabili/sicure usate come bersaglio degli scanner (input, non test). Escluse da `norecursedirs` in pytest: raccoglierle inquinerebbe `sys.path` mascherando le dipendenze installate. Include `repo_target/` (target Terraform riutilizzabile per test su repo arbitrarie) e `crapi_repo/`.

## Convenzioni di linting (ruff, `pyproject.toml`)

- Target Python 3.10, line-length 100, quote-style double.
- `test_targets/`, `fixtures/`, `output/`, `crapi_repo/` esclusi dal linting.
- `__init__.py` ignora `F401` (re-export intenzionali); `entrypoints/**` ignora `E402` (bootstrap di `sys.path` prima degli import); i moduli `tests/**` ignorano `B011`/`E402`.
- Test asincroni in modalità strict: marcare esplicitamente con `@pytest.mark.asyncio`.
