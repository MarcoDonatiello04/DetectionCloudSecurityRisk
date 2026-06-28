.PHONY: setup-env iac-analysis api-security clean

setup-env:
	@bash entrypoints/operations/setup_environment.sh

iac-analysis:
	@bash entrypoints/operations/run_iac_analysis.sh

api-security:
	@bash entrypoints/operations/run_api_security.sh

clean:
	@echo "=> Cleaning up environment..."
	@docker compose down -v
	@rm -rf fixtures/infrastructure_misconfiguration/terraform/.terraform
	@rm -f fixtures/infrastructure_misconfiguration/terraform/*.tfstate*
	@rm -f config/environments/.target_env
	@echo "=> Cleanup complete."
