.PHONY: setup start-localstack terraform scan-dast clean

setup:
	@echo "=> Setting up the entire Cloud Security Testing Environment..."
	@bash scripts/setup/start_system.sh

start-localstack:
	@echo "=> Starting LocalStack..."
	@bash scripts/localstack/start_localstack.sh

terraform:
	@echo "=> Provisioning Vulnerable Infrastructure..."
	@bash scripts/terraform/run_terraform.sh

scan-dast:
	@echo "=> Starting OWASP ZAP DAST Scan..."
	@bash scripts/scanning/run_zap_scan.sh

clean:
	@echo "=> Cleaning up environment..."
	@docker compose down
	@rm -rf problema_misconfiguration/terraform/.terraform
	@rm -f problema_misconfiguration/terraform/*.tfstate*
	@rm -f config/environments/.target_env
	@echo "=> Cleanup complete."
