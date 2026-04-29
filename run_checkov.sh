#!/bin/bash

# Path to the virtual environment's checkov executable
CHECKOV_BIN="./.venv/bin/checkov"

if [ ! -f "$CHECKOV_BIN" ]; then
    echo "❌ Checkov non trovato in .venv. Esegui 'pip install -r requirements.txt' prima."
    exit 1
fi

echo "🛡️  Avvio scansione Checkov..."
$CHECKOV_BIN --config-file .checkov.yaml
