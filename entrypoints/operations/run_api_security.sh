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

# 2. Allineamento bersaglio statico <-> dinamico
# Il bersaglio della scansione statica e' la repo target (TARGET_DIR), non la radice
# della piattaforma: ogni scanner riceve questo perimetro in scan(). La STESSA
# directory viene montata in api-server (docker-compose.yml) come bersaglio degli
# attacchi D-AST: se i due divergessero, la correlazione non troverebbe mai rotte
# in comune. Il path deve essere assoluto: Compose interpreta un path relativo
# senza "./" come volume nominato.
TARGET_DIR="${TARGET_DIR:-data/test_targets/repo_target}"
if [ ! -d "$TARGET_DIR" ]; then
    echo -e "${RED}[-] ERRORE: TARGET_DIR '$TARGET_DIR' non esiste o non e' una directory.${NC}"
    exit 1
fi
TARGET_DIR="$(cd "$TARGET_DIR" && pwd)"
export TARGET_DIR
TARGET_BASE_URL="${TARGET_BASE_URL:-http://localhost:5000}"
echo -e "${GREEN}[+] Bersaglio (statico e dinamico): ${TARGET_DIR}${NC}"

echo -e "${YELLOW}[3.1] Avvio/aggiornamento del container api-server con il bersaglio corrente...${NC}"
# 'up -d' ricrea il container solo se la configurazione (es. il mount) e' cambiata.
docker compose up -d api-server

# 3. Verifica di raggiungibilita' del target cooperante prima degli attacchi
# L'endpoint /test/snapshot e' il contratto minimo dell'harness cooperante: se non
# risponde, la fase D-AST non puo' partire (nessun seeding/snapshot/rollback).
echo -e "${YELLOW}[3.2] Attesa del target cooperante su ${TARGET_BASE_URL}/test/snapshot...${NC}"
TARGET_WAIT_SECONDS="${TARGET_WAIT_SECONDS:-120}"
elapsed=0
until [ "$(curl -s -o /dev/null -w "%{http_code}" "${TARGET_BASE_URL}/test/snapshot" || echo '000')" = "200" ]; do
    if [ "$elapsed" -ge "$TARGET_WAIT_SECONDS" ]; then
        echo -e "\n${RED}[-] ERRORE: il target non risponde su ${TARGET_BASE_URL}/test/snapshot dopo ${TARGET_WAIT_SECONDS}s.${NC}"
        echo -e "Verifica con: docker compose logs api-server"
        exit 1
    fi
    printf "."
    sleep 2
    elapsed=$((elapsed + 2))
done
echo -e "\n${GREEN}[+] Target cooperante raggiungibile.${NC}"

# 4. Esecuzione Pipeline Core (Discovery + Correlation + D-AST BOLA)
echo -e "${YELLOW}[3.3] Avvio della Pipeline Unificata di API Discovery ed Event Correlation...${NC}"
PYTHONPATH=. ./.venv/bin/python3 -m src.presentation.cli.main \
    --target-dir "$TARGET_DIR" \
    --target-base-url "$TARGET_BASE_URL" \
    --zap-url http://localhost:8090 \
    --keycloak-url http://localhost:8080

echo -e "\n${GREEN}[+] SECURITY PIPELINE COMPLETATA CON SUCCESSO!${NC}"
echo -e "Report dei findings: output/unified_security_report.json"
echo -e "Report DAST di ZAP: output/zap_report.json"
echo -e "Per visualizzare la dashboard interattiva (Desktop App):"
echo -e "  make dashboard"
echo -e "${BLUE}=========================================================${NC}"
