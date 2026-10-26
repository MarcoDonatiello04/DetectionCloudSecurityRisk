.PHONY: install lint format test check setup-env iac-analysis api-security bola-repo-target semgrep-repo-target spectral-repo-target stop-dashboard dashboard clean dashboard-vampi dashboard-vampi-sicuro dashboard-dvapi dashboard-sadcloud traffico-esercizio bersagli-esterni

PY := .venv/bin/python

## Installa dipendenze runtime + strumenti di sviluppo
install:
	@$(PY) -m pip install -r requirements.txt
	@$(PY) -m pip install ruff pytest-cov

## Analisi statica del codice
lint:
	@$(PY) -m ruff check .
	@$(PY) -m ruff format --check .

## Applica formattazione e fix automatici
format:
	@$(PY) -m ruff check . --fix
	@$(PY) -m ruff format .

## Esegue la suite di test con coverage
test:
	@$(PY) -m pytest --cov=src --cov-report=term-missing

## Quality gate completo (lo stesso della CI)
check: lint test

setup-env:
	@bash entrypoints/operations/setup_environment.sh

iac-analysis:
	@bash entrypoints/operations/run_iac_analysis.sh

api-security:
	@bash entrypoints/operations/run_api_security.sh

DASHBOARD_PORT ?= 8000
REPO_TARGET_URL ?= http://localhost:5000

## Esegue la scansione BOLA su una repository target cooperante (vedi data/test_targets/repo_target)
bola-repo-target:
	@PYTHONPATH=. $(PY) entrypoints/runners/run_bola_repo_target.py \
		--target-url $(REPO_TARGET_URL) \
		--openapi data/test_targets/repo_target/openapi.yaml

## Estrae l'inventario degli endpoint (Semgrep) dalla repo target cooperante
semgrep-repo-target:
	@PYTHONPATH=. $(PY) entrypoints/runners/run_semgrep_repo_target.py \
		--target data/test_targets/repo_target

## Analizza il contratto OpenAPI della repo target (Spectral, ruleset OWASP)
spectral-repo-target:
	@PYTHONPATH=. $(PY) entrypoints/runners/run_spectral_repo_target.py \
		--openapi data/test_targets/repo_target/openapi.yaml

## Esegue i moduli Core non-BOLA (Broken Auth, BOPLA, BFLA, SSRF, URC, ...) sulla repo target
core-modules-repo-target:
	@PYTHONPATH=. $(PY) entrypoints/runners/run_unified_core_scanners.py \
		--repo-path data/test_targets/repo_target \
		--output-dir output/repo_target/core_modules \
		--skip-bola

## Libera la porta della dashboard da eventuali istanze precedenti
stop-dashboard:
	@pids=$$(lsof -ti tcp:$(DASHBOARD_PORT) 2>/dev/null); \
	if [ -n "$$pids" ]; then \
		echo "=> Porta $(DASHBOARD_PORT) occupata dai processi: $$pids. Chiusura in corso..."; \
		kill $$pids 2>/dev/null || true; \
		for i in 1 2 3 4 5 6 7 8 9 10; do \
			sleep 0.3; \
			lsof -ti tcp:$(DASHBOARD_PORT) >/dev/null 2>&1 || break; \
		done; \
		pids=$$(lsof -ti tcp:$(DASHBOARD_PORT) 2>/dev/null); \
		if [ -n "$$pids" ]; then \
			echo "=> Terminazione forzata di: $$pids"; \
			kill -9 $$pids 2>/dev/null || true; \
			sleep 0.5; \
		fi; \
		echo "=> Porta $(DASHBOARD_PORT) liberata."; \
	else \
		echo "=> Porta $(DASHBOARD_PORT) gia libera."; \
	fi

dashboard: stop-dashboard
	@echo "🚀 starting Security Dashboard on http://localhost:$(DASHBOARD_PORT)"
	@PYTHONPATH=. .venv/bin/uvicorn src.presentation.api.server:app --host 0.0.0.0 --port $(DASHBOARD_PORT) --reload


## ── Validazione su bersagli esterni (insieme di prova, vedi validation/PROTOCOLLO.md) ──
## Ogni dashboard lavora su UN bersaglio: codice, contratto, URL e cartella dei report
## sono fissati all'avvio. Niente --reload: il bersaglio non deve cambiare a scansione in corso.
EXT := data/test_targets/external
define run_dashboard_target
	@echo "🎯 Bersaglio: $(1)  |  URL: $(2)  |  report: $(3)"
	@mkdir -p $(3)
	@TARGET_DIR=$(1) TARGET_BASE_URL=$(2) OUTPUT_DIR=$(3) BOLA_TARGET_CONFIG=$(4) \
		PYTHONPATH=. .venv/bin/uvicorn src.presentation.api.server:app --host 0.0.0.0 --port $(DASHBOARD_PORT)
endef

dashboard-vampi: stop-dashboard
	$(call run_dashboard_target,$(EXT)/vampi,http://localhost:5002,output/external/vampi,config/targets/vampi_bola.yaml)

dashboard-vampi-sicuro: stop-dashboard
	$(call run_dashboard_target,$(EXT)/vampi,http://localhost:5001,output/external/vampi_sicuro,config/targets/vampi_sicuro_bola.yaml)

dashboard-dvapi: stop-dashboard
	$(call run_dashboard_target,$(EXT)/dvapi,http://localhost:3000,output/external/dvapi,config/targets/dvapi_bola.yaml)

## sadcloud e' solo Terraform: nessuna applicazione in esecuzione (URL volutamente irraggiungibile)
dashboard-sadcloud: stop-dashboard
	$(call run_dashboard_target,$(EXT)/sadcloud,http://127.0.0.1:9,output/external/sadcloud,config/bola_target.yaml)

## Sezione "Bersagli esterni": dashboard principale aperta sulla pagina da cui si preparano
## (app, traffico, dashboard dedicata) e si archiviano tutti i bersagli con un clic.
bersagli-esterni: stop-dashboard
	@echo "🎯 Bersagli esterni: http://localhost:$(DASHBOARD_PORT)/external-targets"
	@(sleep 3; open http://localhost:$(DASHBOARD_PORT)/external-targets >/dev/null 2>&1 || true) &
	@PYTHONPATH=. .venv/bin/uvicorn src.presentation.api.server:app --host 0.0.0.0 --port $(DASHBOARD_PORT)

## Traffico di esercizio per la BOLA dinamica (BERSAGLIO=vampi|vampi_sicuro|dvapi)
traffico-esercizio:
	@PYTHONPATH=. $(PY) entrypoints/operations/genera_traffico_esercizio.py $(BERSAGLIO)

clean:
	@echo "=> Cleaning up environment..."
	@docker compose down -v
	@rm -rf data/test_targets/repo_target/terraform/.terraform
	@rm -f data/test_targets/repo_target/terraform/*.tfstate*
	@rm -f config/environments/.target_env
	@echo "=> Cleanup complete."
