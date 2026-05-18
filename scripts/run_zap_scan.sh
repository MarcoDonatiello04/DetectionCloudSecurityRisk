#!/bin/bash

ZAP_API_URL="http://localhost:8080"
REPORTS_DIR="reports/zap"

echo "========================================================="
echo " OWASP ZAP Automated DAST Scan "
echo "========================================================="

# 1. Eseguiamo il check del target e recuperiamo l'URL
bash scripts/check_target.sh
if [ $? -ne 0 ]; then
    echo "[-] Target check failed. Aborting scan."
    exit 1
fi

source .target_env
echo "[+] Starting scan against: $ZAP_TARGET_URL"

# 2. Check ZAP Health
if ! curl -s "$ZAP_API_URL" > /dev/null; then
    echo "[-] OWASP ZAP non è raggiungibile su $ZAP_API_URL"
    echo "Assicurati che il container tesi-owasp-zap sia in esecuzione."
    exit 1
fi

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
echo "[*] Triggering Active Scan..."
ASCAN_ID=$(curl -s "$ZAP_API_URL/JSON/ascan/action/scan/?url=$ZAP_TARGET_URL&recurse=true" | jq -r '.scan')

if [ -z "$ASCAN_ID" ] || [ "$ASCAN_ID" == "null" ]; then
    echo "[-] Fallito avvio Active Scan."
    exit 1
fi

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
echo "[+] Active Scan completato."

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
