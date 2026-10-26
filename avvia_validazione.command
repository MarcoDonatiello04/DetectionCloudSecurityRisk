#!/bin/bash
# Avvio dell'ambiente di validazione esterna (vedi validation/PROTOCOLLO.md).
# Doppio clic da Finder: apre il Terminale ed esegue tutto fino alla dashboard.
# Uso da terminale: ./avvia_validazione.command [vampi|vampi_sicuro|dvapi|sadcloud]   (default: vampi)
export PATH="/usr/local/bin:/opt/homebrew/bin:$HOME/.docker/bin:/Applications/Docker.app/Contents/Resources/bin:$PATH"
cd "$(dirname "$0")" || exit 1
BERSAGLIO="${1:-vampi}"
mkdir -p output/external
LOG="output/external/avvio_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1
echo "== Avvio ambiente di validazione — bersaglio: $BERSAGLIO — log: $LOG"

if ! git rev-parse -q --verify refs/tags/v-validazione >/dev/null; then
  echo "!! ATTENZIONE: il tag v-validazione non esiste. Strumento NON congelato:"
  echo "!! fare commit + 'git tag -a v-validazione' PRIMA di avviare le scansioni (PROTOCOLLO §2)."
fi

# 1. Docker
if ! docker info >/dev/null 2>&1; then
  echo "-> Avvio di Docker Desktop..."
  open -a Docker
  for i in $(seq 1 60); do docker info >/dev/null 2>&1 && break; sleep 3; done
fi
# attesa che il motore risponda davvero alle API delle immagini, non solo a 'docker info'
for i in $(seq 1 30); do docker image ls >/dev/null 2>&1 && break; sleep 2; done
docker info >/dev/null 2>&1 || { echo "!! Docker non disponibile"; read -r -p "Invio per chiudere"; exit 1; }
echo "-> Docker attivo"

riprova() {  # riprova <comando...>: il motore Docker appena avviato puo' rispondere 500
  for i in 1 2 3 4 5 6; do "$@" && return 0; echo "   tentativo $i fallito, nuovo tentativo fra 10 s"; sleep 10; done
  return 1
}

attendi() {  # attendi <url> <nome>
  for i in $(seq 1 90); do
    code=$(curl -s -o /dev/null -w "%{http_code}" "$1" || true)
    if [ -n "$code" ] && [ "$code" != "000" ]; then echo "   $2 risponde ($code) su $1"; return 0; fi
    sleep 2
  done
  echo "!! $2 non risponde su $1"; return 1
}

# 2. Servizi della piattaforma (Keycloak non serve per i bersagli esterni)
echo "-> Riavvio di mitmproxy e ZAP"
docker compose stop api-server keycloak >/dev/null 2>&1
riprova docker compose up -d --force-recreate mitmproxy owasp-zap
attendi http://localhost:8090 "ZAP" || true

# 3. Bersaglio
case "$BERSAGLIO" in
  vampi|vampi_sicuro)
    echo "-> Avvio VAmPI (5001 sicuro, 5002 vulnerabile)"
    (cd data/test_targets/external/vampi && riprova docker compose up -d --build)
    PORT=5002; [ "$BERSAGLIO" = "vampi_sicuro" ] && PORT=5001
    attendi "http://localhost:$PORT/" "VAmPI" ;;
  dvapi)
    echo "-> Avvio DVAPI (3000) + MongoDB"
    (cd data/test_targets/external/dvapi && riprova docker compose up -d --build)
    attendi "http://localhost:3000/" "DVAPI" ;;
  sadcloud)
    echo "-> sadcloud: solo Terraform, nessuna applicazione da avviare" ;;
  *) echo "!! bersaglio sconosciuto: $BERSAGLIO"; exit 1 ;;
esac

# 4. Traffico di esercizio per la BOLA dinamica
if [ "$BERSAGLIO" != "sadcloud" ]; then
  echo "-> Traffico di esercizio ($BERSAGLIO)"
  PYTHONPATH=. .venv/bin/python entrypoints/operations/genera_traffico_esercizio.py "$BERSAGLIO" \
    || echo "!! traffico di esercizio non generato: la BOLA dinamica si fermera' con un errore esplicito"
fi

# 5. Dashboard (resta in primo piano in questa finestra; Ctrl+C per fermarla)
TARGET_MAKE="dashboard-${BERSAGLIO//_/-}"
echo "-> make $TARGET_MAKE  —  apri http://localhost:8000"
echo "   Ordine: 1) scansione statica  2) scansione completa (BOLA inclusa)"
make "$TARGET_MAKE"
