#!/bin/bash
set -e

# Colori
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}=========================================================${NC}"
echo -e "${BLUE}   Cloud Security Thesis - System Setup Orchestrator     ${NC}"
echo -e "${BLUE}=========================================================${NC}"

# Rendi eseguibili gli script interni
chmod +x scripts/localstack/start_localstack.sh
chmod +x scripts/terraform/run_terraform.sh
chmod +x scripts/scanning/run_zap_scan.sh 2>/dev/null || true

echo -e "\n${YELLOW}[STEP 1] Inizializzazione LocalStack e Docker...${NC}"
bash scripts/localstack/start_localstack.sh

echo -e "\n${YELLOW}[STEP 2] Provisioning dell'Infrastruttura Vulnerabile (Terraform)...${NC}"
bash scripts/terraform/run_terraform.sh

echo -e "\n${YELLOW}[STEP 3] Controllo OWASP ZAP...${NC}"
ZAP_CONTAINER=$(docker ps --filter "ancestor=ghcr.io/zaproxy/zaproxy:stable" --format "{{.Names}}" | head -n 1)
if [ -z "$ZAP_CONTAINER" ]; then
    echo -e "${YELLOW}[!] ZAP non trovato in Docker. Verificare se è avviato.${NC}"
else
    echo -e "${GREEN}[+] OWASP ZAP è in esecuzione nel container: $ZAP_CONTAINER${NC}"
fi

echo -e "\n${BLUE}=========================================================${NC}"
echo -e "${GREEN} TUTTI I SISTEMI OPERATIVI!${NC}"
echo -e "${BLUE}=========================================================${NC}"
echo -e "L'infrastruttura è pronta in LocalStack."
echo -e "Per avviare la scansione DAST:"
echo -e "  bash scripts/scanning/run_zap_scan.sh"
echo -e "${BLUE}=========================================================${NC}"
