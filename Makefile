.PHONY: install lint format test check setup-env iac-analysis api-security bola-repo-target stop-dashboard dashboard clean

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
	@$(PY) -m pytest --cov=src --cov=remediation --cov-report=term-missing

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

## Esegue la scansione BOLA su una repository target cooperante (vedi test_targets/repo_target)
bola-repo-target:
	@PYTHONPATH=. $(PY) entrypoints/runners/run_bola_repo_target.py \
		--target-url $(REPO_TARGET_URL) \
		--openapi test_targets/repo_target/openapi.yaml

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
	@PYTHONPATH=. .venv/bin/uvicorn src.presentation.rest_api:app --host 0.0.0.0 --port $(DASHBOARD_PORT) --reload


clean:
	@echo "=> Cleaning up environment..."
	@docker compose down -v
	@rm -rf test_targets/repo_target/terraform/.terraform
	@rm -f test_targets/repo_target/terraform/*.tfstate*
	@rm -f config/environments/.target_env
	@echo "=> Cleanup complete."
