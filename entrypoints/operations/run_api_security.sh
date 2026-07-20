#!/bin/bash
set -e

# Colori
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}=========================================================${NC}"
echo -e "${BLUE}   [FASE 3] API Security Assessment & D-AST (BOLA)        ${NC}"
echo -e "${BLUE}=========================================================${NC}"

# 1. Verifica ambiente configurato
if [ ! -f "config/environments/.target_env" ]; then
    echo -e "${RED}[-] ERRORE: Ambiente non configurato.${NC}"
    echo -e "Esegui prima la Fase 2 (make iac-analysis) per ottenere l'URL dell'infrastruttura."
    exit 1
fi

source config/environments/.target_env
echo -e "${GREEN}[+] URL di stimolazione dell'infrastruttura: ${TARGET_URL}${NC}"

# 2. Esecuzione Pipeline Core (Discovery + Correlation + D-AST BOLA)
echo -e "${YELLOW}[3.1] Avvio della Pipeline Unificata di API Discovery ed Event Correlation...${NC}"
PYTHONPATH=. ./.venv/bin/python3 -m src.presentation.cli.main \
    --target-dir . \
    --target-base-url http://localhost:5000 \
    --zap-url http://localhost:8090 \
    --keycloak-url http://localhost:8080

echo -e "\n${GREEN}[+] SECURITY PIPELINE COMPLETATA CON SUCCESSO!${NC}"
echo -e "Report dei findings: output/unified_security_report.json"
echo -e "Report DAST di ZAP: output/zap_report.json"
echo -e "Per visualizzare la dashboard interattiva (Desktop App):"
echo -e "  make dashboard"
echo -e "${BLUE}=========================================================${NC}"
