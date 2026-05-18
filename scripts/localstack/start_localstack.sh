#!/bin/bash
set -e

# Colori
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}=========================================================${NC}"
echo -e "${BLUE}   LocalStack Orchestrator                               ${NC}"
echo -e "${BLUE}=========================================================${NC}"

echo -e "${YELLOW}[*] Controllo se LocalStack è già in esecuzione...${NC}"

if docker ps --format '{{.Names}}' | grep -q "^localstack-main$"; then
    echo -e "${GREEN}[+] Il container 'localstack-main' è già in esecuzione.${NC}"
else
    echo -e "${YELLOW}[*] Avviando i servizi via Docker Compose...${NC}"
    # Si assume che Docker Compose includa ZAP o altri tool necessari
    docker compose up -d
fi

echo -e "${YELLOW}[*] Attesa che l'API di LocalStack diventi 'available'...${NC}"
MAX_RETRIES=15
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    HEALTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:4566/_localstack/health || echo "000")
    if [ "$HEALTH_STATUS" == "200" ] || [ "$HEALTH_STATUS" == "201" ]; then
        echo -e "\n${GREEN}[+] LocalStack è pronto e operativo!${NC}"
        exit 0
    fi
    printf "."
    sleep 2
    RETRY_COUNT=$((RETRY_COUNT+1))
done

echo -e "\n${RED}[-] Errore: LocalStack non è diventato operativo in tempo.${NC}"
exit 1
