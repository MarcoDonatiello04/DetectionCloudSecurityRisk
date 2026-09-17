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

# Directory della configurazione Terraform, ora ospitata nella repo target cooperante
TERRAFORM_DIR="data/test_targets/repo_target/terraform"
PROJECT_ROOT="$(pwd)"

# 1. Provisioning con Terraform
echo -e "${YELLOW}[2.1] Esecuzione Terraform su LocalStack...${NC}"
cd "$TERRAFORM_DIR"

terraform init

# Il provisioning e' best-effort: alcune emulazioni di LocalStack (community/freemium)
# non riportano lo stato 'AVAILABLE' dell'API Gateway REST, e il provider AWS 6.x
# fallisce l'attesa anche quando le risorse sono state create. Questo NON deve
# bloccare l'analisi statica IaC (Checkov), che e' il deliverable di questa fase.
if ! terraform apply -auto-approve; then
    echo -e "${YELLOW}[~] Provisioning parziale su LocalStack (probabile attesa stato API Gateway non supportata).${NC}"
    echo -e "${YELLOW}    Le risorse create restano disponibili; proseguo con la scansione IaC statica.${NC}"
fi

# Recupera URL dell'API Gateway creata su LocalStack.
# Nota: se l'output non esiste (apply parziale), `terraform output -raw` emette un
# warning multilinea con codici ANSI: va scartato, altrimenti finirebbe dentro
# .target_env e romperebbe il `source` a valle (Fase 3). Accettiamo solo un URL http(s).
API_URL=$(terraform output -raw vulnerable_api_base_url 2>/dev/null || true)

cd "$PROJECT_ROOT"

mkdir -p config/environments
if printf '%s' "$API_URL" | grep -Eq '^https?://[^[:space:]]+$'; then
    echo -e "${GREEN}[+] API Gateway creata su LocalStack: ${API_URL}${NC}"
    # Salva l'URL configurato nel file di configurazione ambientale per gli scanner
    echo "TARGET_URL=${API_URL}" > config/environments/.target_env
    # Sostituiamo localhost con host.docker.internal per l'accesso da dentro i container Docker (ZAP)
    ZAP_TARGET_URL=$(echo "$API_URL" | sed 's/localhost/host.docker.internal/g' | sed 's/127.0.0.1/host.docker.internal/g')
    echo "ZAP_TARGET_URL=${ZAP_TARGET_URL}" >> config/environments/.target_env
    echo -e "${GREEN}[+] File config/environments/.target_env creato con successo.${NC}"
else
    # Provisioning parziale/assente: scriviamo comunque un file valido (senza URL AWS),
    # cosi' la Fase 3 puo' proseguire usando il bersaglio locale (api-server:5000).
    echo "# Provisioning API Gateway non disponibile: uso il bersaglio locale." \
        > config/environments/.target_env
    echo "TARGET_URL=" >> config/environments/.target_env
    echo -e "${YELLOW}[~] Nessun URL API Gateway valido: .target_env creato senza TARGET_URL AWS.${NC}"
fi

# 2. Analisi IaC con Checkov
echo -e "\n${YELLOW}[2.2] Esecuzione scansione IaC statica con Checkov...${NC}"
if command -v checkov &> /dev/null; then
    checkov -d "$TERRAFORM_DIR" --framework terraform || true
elif [ -f "./.venv/bin/checkov" ]; then
    ./.venv/bin/checkov -d "$TERRAFORM_DIR" --framework terraform || true
else
    echo -e "${RED}[-] Checkov non trovato nel sistema. Scansione IaC saltata.${NC}"
fi

echo -e "\n${GREEN}[+] PROVISIONING E ANALISI IAC COMPLETATI!${NC}"
echo -e "${BLUE}=========================================================${NC}"
