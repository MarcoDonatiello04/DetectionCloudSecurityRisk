#!/bin/bash

echo "[*] Checking LocalStack health..."
HEALTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:4566/_localstack/health)
if [ "$HEALTH_STATUS" != "200" ] && [ "$HEALTH_STATUS" != "201" ]; then
    echo "[-] Error: LocalStack is not reachable (HTTP $HEALTH_STATUS)."
    exit 1
fi
echo "[+] LocalStack is healthy (HTTP $HEALTH_STATUS)."

echo "[*] Retrieving API Gateway ID..."
API_GW_ID=$(docker exec localstack-main awslocal apigateway get-rest-apis --query 'items[?name==`VulnerableLambdaAPI`].id' --output text 2>/dev/null)

if [ -z "$API_GW_ID" ] || [ "$API_GW_ID" == "None" ]; then
    echo "[-] Error: VulnerableLambdaAPI not found. Make sure Terraform has been applied."
    exit 1
fi
echo "[+] Found API Gateway ID: $API_GW_ID"

API_URL="http://localhost:4566/restapis/${API_GW_ID}/dev/_user_request_"
echo "[+] Base API URL is: $API_URL"

echo "[*] Testing connectivity to the API (/users)..."
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/users")

if [ "$HTTP_STATUS" == "200" ]; then
    echo "[+] API is reachable! (HTTP $HTTP_STATUS)"
else
    echo "[-] Warning: API responded with HTTP $HTTP_STATUS. It might not be fully operational."
    exit 1
fi

# Pass API URL to the caller if needed
echo "TARGET_URL=$API_URL" > config/environments/.target_env
# Replace localhost with host.docker.internal for ZAP
ZAP_TARGET_URL=$(echo $API_URL | sed 's/localhost/host.docker.internal/g')
echo "ZAP_TARGET_URL=$ZAP_TARGET_URL" >> config/environments/.target_env
exit 0
