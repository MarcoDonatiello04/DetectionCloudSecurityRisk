.PHONY: zap-scan check-target

zap-scan:
	@echo "=> Starting OWASP ZAP Dynamic Scan..."
	@bash scripts/run_zap_scan.sh

check-target:
	@echo "=> Checking target reachability..."
	@bash scripts/check_target.sh
