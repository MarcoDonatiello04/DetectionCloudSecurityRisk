#!/bin/bash
set -e

# Colori per il logging
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}=========================================================${NC}"
echo -e "${BLUE}   Terraform Provisioning (LocalStack)                   ${NC}"
echo -e "${BLUE}=========================================================${NC}"

TF_DIR="infrastructure/terraform"

# Verifica se LocalStack è online
echo -e "${YELLOW}[*] Verificando lo stato di LocalStack...${NC}"
if ! curl -s http://localhost:4566/_localstack/health > /dev/null; then
    echo -e "${RED}[-] Errore: LocalStack non è raggiungibile sulla porta 4566.${NC}"
    echo -e "Avvia LocalStack prima di eseguire Terraform."
    exit 1
fi
echo -e "${GREEN}[+] LocalStack è online.${NC}"

# Esecuzione Terraform
cd "$TF_DIR"

echo -e "${YELLOW}[*] Inizializzando Terraform (se necessario)...${NC}"
if [ ! -d ".terraform" ]; then
    terraform init -backend=false
else
    echo -e "${GREEN}[+] Terraform provider già installati. Skipping init.${NC}"
fi

echo -e "${YELLOW}[*] Validando il codice...${NC}"
terraform validate

echo -e "${YELLOW}[*] Applicando l'infrastruttura (Auto-Approve)...${NC}"
terraform apply -auto-approve

echo -e "${GREEN}[+] Infrastruttura Cloud creata con successo!${NC}"

# Estrazione Endpoint
echo -e "${YELLOW}[*] Estraendo l'ID dell'API Gateway...${NC}"
API_GW_ID=$(docker exec localstack-main awslocal apigateway get-rest-apis --query 'items[?name==`VulnerableLambdaAPI`].id' --output text 2>/dev/null)

if [ -z "$API_GW_ID" ] || [ "$API_GW_ID" == "None" ]; then
    echo -e "${RED}[-] Errore: VulnerableLambdaAPI non trovata in LocalStack.${NC}"
    exit 1
fi

echo -e "${GREEN}[+] API Gateway ID: $API_GW_ID${NC}"
API_URL="http://localhost:4566/restapis/${API_GW_ID}/dev/_user_request_"
ZAP_TARGET_URL="http://host.docker.internal:4566/restapis/${API_GW_ID}/dev/_user_request_"

echo -e "${BLUE}=========================================================${NC}"
echo -e "Endpoint base: ${API_URL}"
echo -e "Endpoint ZAP : ${ZAP_TARGET_URL}"
echo -e "${BLUE}=========================================================${NC}"

# Salva l'output in un .env condiviso per gli altri script
cd ../../
echo "TARGET_URL=$API_URL" > config/environments/.target_env
echo "ZAP_TARGET_URL=$ZAP_TARGET_URL" >> config/environments/.target_env
echo "ZAP_API_URL=http://localhost:8080" >> config/environments/.target_env
echo -e "${GREEN}[+] Environment salvato in config/environments/.target_env${NC}"
