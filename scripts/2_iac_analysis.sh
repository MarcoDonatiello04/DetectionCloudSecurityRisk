#!/bin/bash
set -e

# Colori
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}=========================================================${NC}"
echo -e "${BLUE}   [FASE 2] IaC Provisioning & Security Scan             ${NC}"
echo -e "${BLUE}=========================================================${NC}"

# 1. Provisioning con Terraform
echo -e "${YELLOW}[2.1] Esecuzione Terraform su LocalStack...${NC}"
cd problema_misconfiguration/terraform

terraform init
terraform apply -auto-approve

# Recupera URL dell'API Gateway creata su LocalStack
API_URL=$(terraform output -raw vulnerable_api_base_url || echo "")

cd ../..

if [ -n "$API_URL" ] && [ "$API_URL" != "None" ]; then
    echo -e "${GREEN}[+] API Gateway creata su LocalStack: ${API_URL}${NC}"
    # Salva l'URL configurato nel file di configurazione ambientale per gli scanner
    mkdir -p config/environments
    echo "TARGET_URL=${API_URL}" > config/environments/.target_env
    # Sostituiamo localhost con host.docker.internal per l'accesso da dentro i container Docker (ZAP)
    ZAP_TARGET_URL=$(echo "$API_URL" | sed 's/localhost/host.docker.internal/g' | sed 's/127.0.0.1/host.docker.internal/g')
    echo "ZAP_TARGET_URL=${ZAP_TARGET_URL}" >> config/environments/.target_env
    echo -e "${GREEN}[+] File config/environments/.target_env creato con successo.${NC}"
else
    echo -e "${RED}[-] Attenzione: Impossibile determinare l'URL di API Gateway. Controlla LocalStack/Terraform.${NC}"
fi

# 2. Analisi IaC con Checkov
echo -e "\n${YELLOW}[2.2] Esecuzione scansione IaC statica con Checkov...${NC}"
if command -v checkov &> /dev/null; then
    checkov -d problema_misconfiguration/terraform --framework terraform || true
elif [ -f "./.venv/bin/checkov" ]; then
    ./.venv/bin/checkov -d problema_misconfiguration/terraform --framework terraform || true
else
    echo -e "${RED}[-] Checkov non trovato nel sistema. Scansione IaC saltata.${NC}"
fi

echo -e "\n${GREEN}[+] PROVISIONING E ANALISI IAC COMPLETATI!${NC}"
echo -e "${BLUE}=========================================================${NC}"
