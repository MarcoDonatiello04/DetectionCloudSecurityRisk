#!/bin/bash

# Script per avviare l'infrastruttura di simulazione cloud locale
# NOTA: Si aspetta che un container LocalStack (localstack-main) sia già in esecuzione

echo "========================================================="
echo " Avvio Ambiente Cloud Security (LocalStack + Docker)"
echo "========================================================="

echo "[1/5] Verifica disponibilità LocalStack principale (localstack-main)..."
if ! docker ps | grep -q "localstack-main"; then
  echo "ERRORE: Il container 'localstack-main' non è in esecuzione!"
  echo "Assicurati di aver avviato LocalStack PRO prima di lanciare questo script."
  exit 1
fi
until [ "$(curl -s -o /dev/null -w "%{http_code}" http://localhost:4566/_localstack/health || echo '000')" = "200" ]; do
  printf "."
  sleep 2
done
echo " LocalStack è pronto sulla porta 4566!"

echo "[2/5] Avvio dei restanti servizi (ZAP, Target App) via Docker Compose..."
docker-compose up -d

echo "[3/5] Inizializzazione ed esecuzione Terraform..."
bash scripts/terraform/run_terraform.sh

echo "[4/5] Verifica automatica infrastruttura..."
echo " - Controllo tabelle DynamoDB:"
docker exec localstack-main awslocal dynamodb list-tables
echo " - Controllo funzioni Lambda:"
docker exec localstack-main awslocal lambda list-functions
echo " - Controllo API Gateway:"
docker exec localstack-main awslocal apigateway get-rest-apis

echo "========================================================="
echo " Infrastruttura creata con successo!"
echo "========================================================="

echo "[5/5] Endpoint e Informazioni per OWASP ZAP:"
API_GW_ID=$(docker exec localstack-main awslocal apigateway get-rest-apis --query 'items[?name==`VulnerableLambdaAPI`].id' --output text)

if [ -n "$API_GW_ID" ] && [ "$API_GW_ID" != "None" ]; then
    API_URL="http://localhost:4566/restapis/${API_GW_ID}/dev/_user_request_"
    echo "API Gateway (Vulnerabile) Base URL: ${API_URL}"
    echo ""
    echo "Verifica Endpoint /users (CURL):"
    curl -s "${API_URL}/users" | jq || curl -s "${API_URL}/users"
    echo ""
    echo "========================================================="
    echo "Esempi CURL da testare manualmente:"
    echo "  curl ${API_URL}/users"
    echo "  curl ${API_URL}/users/1?cmd=id"
    echo "  curl -X POST ${API_URL}/login -d '{\"username\":\"admin\",\"password\":\"\"}'"
    echo "  curl ${API_URL}/admin"
    echo "  curl ${API_URL}/debug"
    echo ""
    echo "Per lanciare OWASP ZAP in Automazione (se configurato CLI):"
    echo "  zap.sh -cmd -quickurl ${API_URL} -quickprogress"
else
    echo "Impossibile recuperare l'ID di API Gateway. Controlla LocalStack e Terraform."
fi

echo "========================================================="
echo "Nota: Il progetto è strutturato per riutilizzare l'istanza LocalStack preesistente."
