.PHONY: setup-env iac-analysis api-security dashboard clean

setup-env:
	@bash entrypoints/operations/setup_environment.sh

iac-analysis:
	@bash entrypoints/operations/run_iac_analysis.sh

api-security:
	@bash entrypoints/operations/run_api_security.sh

dashboard:
	@echo "🚀 starting Security Dashboard on http://localhost:8000"
	@PYTHONPATH=. .venv/bin/uvicorn src.presentation.rest_api:app --host 0.0.0.0 --port 8000


clean:
	@echo "=> Cleaning up environment..."
	@docker compose down -v
	@rm -rf fixtures/infrastructure_misconfiguration/terraform/.terraform
	@rm -f fixtures/infrastructure_misconfiguration/terraform/*.tfstate*
	@rm -f config/environments/.target_env
	@echo "=> Cleanup complete."
