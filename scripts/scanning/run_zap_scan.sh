#!/bin/bash

ZAP_API_URL="http://localhost:8090"
REPORTS_DIR="reports/zap"

echo "========================================================="
echo " OWASP ZAP Automated DAST Scan "
echo "========================================================="

# 1. Eseguiamo il check del target e recuperiamo l'URL
bash scripts/localstack/check_target.sh
if [ $? -ne 0 ]; then
    echo "[-] Target check failed. Aborting scan."
    exit 1
fi

source config/environments/.target_env
echo "[+] Starting scan against: $ZAP_TARGET_URL"

# Trova il container ZAP in esecuzione dinamicamente
ZAP_CONTAINER=$(docker ps --filter "ancestor=ghcr.io/zaproxy/zaproxy:stable" --format "{{.Names}}" | head -n 1)
if [ -z "$ZAP_CONTAINER" ]; then
    # Fallback su tesi-owasp-zap se non è rilevato alcun container attivo
    ZAP_CONTAINER="tesi-owasp-zap"
fi

if ! curl -s "$ZAP_API_URL" > /dev/null; then
    echo "[-] OWASP ZAP non è raggiungibile su $ZAP_API_URL"
    echo "Assicurati che le porte siano esposte e il container sia attivo."
    exit 1
fi

echo "[*] Cleaning previous ZAP session (starting a fresh session)..."
curl -s "$ZAP_API_URL/JSON/core/action/newSession/?overwrite=true" > /dev/null

echo "[*] Importing OpenAPI spec for LocalStack API ($ZAP_TARGET_URL)..."
docker cp problema_api/openapi.yaml "$ZAP_CONTAINER":/tmp/openapi.yaml
curl -s "$ZAP_API_URL/JSON/openapi/action/importFile/?file=/tmp/openapi.yaml&target=$ZAP_TARGET_URL" > /dev/null

echo "[*] ZAP is alive. Triggering Spider..."

# 3. Avvio Spidering
SPIDER_ID=$(curl -s "$ZAP_API_URL/JSON/spider/action/scan/?url=$ZAP_TARGET_URL" | jq -r '.scan')

if [ -z "$SPIDER_ID" ] || [ "$SPIDER_ID" == "null" ]; then
    echo "[-] Fallito avvio Spider. Target url: $ZAP_TARGET_URL"
    exit 1
fi

# Polling Spider status
echo "[*] Polling Spider status (ID: $SPIDER_ID)..."
while true; do
    STATUS=$(curl -s "$ZAP_API_URL/JSON/spider/view/status/?scanId=$SPIDER_ID" | jq -r '.status')
    printf "\r    Spider Progress: %s%%" "$STATUS"
    if [ "$STATUS" == "100" ]; then
        echo ""
        break
    fi
    sleep 2
done
echo "[+] Spidering completato."

# Aggiungiamo un attimo di pausa
sleep 2

# 4. Avvio Active Scan
echo "[*] Configuring ZAP scanner options for LocalStack compatibility..."
# Limita i thread a 1 per evitare di impallare LocalStack con troppe Lambda parallele
curl -s "$ZAP_API_URL/JSON/ascan/action/setOptionThreadPerHost/?Integer=1" > /dev/null
# Limita la durata massima di ogni singola regola a 1 minuto per evitare blocchi
curl -s "$ZAP_API_URL/JSON/ascan/action/setOptionMaxRuleDurationInMins/?Integer=1" > /dev/null
# Imposta il timeout di rete di ZAP a 2 secondi (essendo tutto locale, se ci mette di più è bloccato)
curl -s "$ZAP_API_URL/JSON/core/action/setOptionTimeoutInSecs/?Integer=2" > /dev/null

# Disabilita tutte le centinaia di regole web generiche che rallentano la scansione delle API
echo "[*] Disabling redundant ZAP scanners..."
curl -s "$ZAP_API_URL/JSON/ascan/action/disableAllScanners/" > /dev/null

# Abilita tutte le regole di scansione specifiche e rilevanti per le API (SQLi, NoSQLi, SSRF, XXE, LDAP, RCE, Path Traversal, Cloud Metadata, ecc.)
echo "[*] Enabling all API-specific active scan rules..."
API_SCANNER_IDS="40018,40024,40033,90039,90020,90019,6,7,40029,20019,90023,40015,90034,30003"
curl -s "$ZAP_API_URL/JSON/ascan/action/enableScanners/?ids=$API_SCANNER_IDS" > /dev/null

echo "[*] Triggering Active Scan (LocalStack)..."
ASCAN_ID=$(curl -s "$ZAP_API_URL/JSON/ascan/action/scan/?url=$ZAP_TARGET_URL&recurse=true" | jq -r '.scan')

if [ -z "$ASCAN_ID" ] || [ "$ASCAN_ID" == "null" ]; then
    echo "[-] Fallito avvio Active Scan su LocalStack."
else
    echo "[*] Polling Active Scan status (ID: $ASCAN_ID)..."
    while true; do
        STATUS=$(curl -s "$ZAP_API_URL/JSON/ascan/view/status/?scanId=$ASCAN_ID" | jq -r '.status')
        printf "\r    Active Scan Progress: %s%%" "$STATUS"
        if [ "$STATUS" == "100" ]; then
            echo ""
            break
        fi
        sleep 5
    done
    echo "[+] Active Scan LocalStack completato."
fi

# 5. Estrazione Report
echo "[*] Estrazione Report in corso..."
mkdir -p "$REPORTS_DIR"

curl -s "$ZAP_API_URL/OTHER/core/other/htmlreport/" > "$REPORTS_DIR/zap_report.html"
curl -s "$ZAP_API_URL/OTHER/core/other/jsonreport/" > "$REPORTS_DIR/zap_report.json"

echo "[+] Report salvati in $REPORTS_DIR/"

# 6. Analisi veloce degli Alert
echo "========================================================="
echo " SOMMARIO VULNERABILITA' (ALERTS) "
echo "========================================================="

# Estrarre alerts usando JQ e contarli per severity
HIGH=$(jq '[.site[].alerts[] | select(.riskdesc | contains("High"))] | length' "$REPORTS_DIR/zap_report.json" 2>/dev/null || echo "0")
MEDIUM=$(jq '[.site[].alerts[] | select(.riskdesc | contains("Medium"))] | length' "$REPORTS_DIR/zap_report.json" 2>/dev/null || echo "0")
LOW=$(jq '[.site[].alerts[] | select(.riskdesc | contains("Low"))] | length' "$REPORTS_DIR/zap_report.json" 2>/dev/null || echo "0")
INFO=$(jq '[.site[].alerts[] | select(.riskdesc | contains("Informational"))] | length' "$REPORTS_DIR/zap_report.json" 2>/dev/null || echo "0")

echo " - HIGH:   $HIGH"
echo " - MEDIUM: $MEDIUM"
echo " - LOW:    $LOW"
echo " - INFO:   $INFO"

echo ""
echo "Per i dettagli completi visualizza $REPORTS_DIR/zap_report.html"
echo "========================================================="
