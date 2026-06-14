.PHONY: setup-env iac-analysis api-security gui clean

setup-env:
	@bash scripts/1_setup_environment.sh

iac-analysis:
	@bash scripts/2_iac_analysis.sh

api-security:
	@bash scripts/3_api_security.sh

gui:
	@.venv/bin/python3 cloud_security_analyzer/launcher.py

clean:
	@echo "=> Cleaning up environment..."
	@docker compose down -v
	@rm -rf problema_misconfiguration/terraform/.terraform
	@rm -f problema_misconfiguration/terraform/*.tfstate*
	@rm -f config/environments/.target_env
	@echo "=> Cleanup complete."
