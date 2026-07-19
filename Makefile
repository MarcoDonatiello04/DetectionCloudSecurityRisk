.PHONY: install lint format test check setup-env iac-analysis api-security dashboard clean

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

dashboard:
	@echo "🚀 starting Security Dashboard on http://localhost:8000"
	@PYTHONPATH=. .venv/bin/uvicorn src.presentation.rest_api:app --host 0.0.0.0 --port 8000 --reload


clean:
	@echo "=> Cleaning up environment..."
	@docker compose down -v
	@rm -rf fixtures/infrastructure_misconfiguration/terraform/.terraform
	@rm -f fixtures/infrastructure_misconfiguration/terraform/*.tfstate*
	@rm -f config/environments/.target_env
	@echo "=> Cleanup complete."
