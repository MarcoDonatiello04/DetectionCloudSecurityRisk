#!/bin/bash
# ==============================================================================
# Script di configurazione automatica per Ollama su macOS
# Installa Ollama, avvia il servizio e scarica il modello Llama 3.1
# ==============================================================================

set -e

GREEN='\033[0;32m'
NC='\033[0m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'

echo -e "${BLUE}====================================================================${NC}"
echo -e "${BLUE}🦙 CONFIGURAZIONE ED INSTALLAZIONE AUTOMATICA DI OLLAMA PER LA TESI${NC}"
echo -e "${BLUE}====================================================================${NC}"

# 1. Verifica se Ollama è già installato
if command -v ollama &> /dev/null; then
    echo -e "${GREEN}✓ Ollama è già installato nel sistema.${NC}"
else
    echo -e "${YELLOW}! Ollama non è installato. Tentativo di installazione tramite Homebrew...${NC}"
    
    if command -v brew &> /dev/null; then
        echo -e "${BLUE}--> Esecuzione di: brew install --cask ollama${NC}"
        brew install --cask ollama
        echo -e "${GREEN}✓ Ollama installato con successo tramite Homebrew!${NC}"
    else
        echo -e "${RED}❌ Homebrew non è installato sul tuo Mac.${NC}"
        echo -e "${YELLOW}Per favore, scarica Ollama manualmente da: https://ollama.com/download/Ollama-darwin.zip${NC}"
        echo -e "${YELLOW}Estrailo e trascina l'applicazione nella cartella Applicazioni.${NC}"
        exit 1
    fi
fi

# 2. Avvio di Ollama se spento
echo -e "${BLUE}--> Controllo dello stato del servizio Ollama...${NC}"
if curl -s http://localhost:11434 &> /dev/null; then
    echo -e "${GREEN}✓ Il servizio Ollama è attivo e risponde sulla porta 11434.${NC}"
else
    echo -e "${YELLOW}! Ollama è installato ma spento. Avvio dell'applicazione desktop...${NC}"
    
    # Cerca di aprire l'applicazione Mac OS
    if [ -d "/Applications/Ollama.app" ]; then
        open -a Ollama
    else
        # Fallback avviando via CLI in background
        ollama serve > /dev/null 2>&1 &
    fi
    
    echo -e "${BLUE}--> Attesa dell'avvio del servizio (attesa massima 15 secondi)...${NC}"
    SUCCESS=0
    for i in {1..15}; do
        if curl -s http://localhost:11434 &> /dev/null; then
            SUCCESS=1
            break
        fi
        sleep 1
    done
    
    if [ $SUCCESS -eq 1 ]; then
        echo -e "${GREEN}✓ Ollama avviato con successo!${NC}"
    else
        echo -e "${RED}❌ Impossibile avviare Ollama automaticamente.${NC}"
        echo -e "${RED}Per favore, avvia manualmente l'applicazione Ollama e riprova.${NC}"
        exit 1
    fi
fi

# 3. Download del modello Llama 3.1
echo -e "${BLUE}--> Download del modello 'llama3.1' (questo passaggio potrebbe richiedere del tempo a seconda della connessione)...${NC}"
ollama pull llama3.1

# 4. Verifica modelli installati
echo -e "${BLUE}--> Modelli attualmente installati in Ollama:${NC}"
ollama list

echo -e "${BLUE}====================================================================${NC}"
echo -e "${GREEN}🎉 OLLAMA CONFIGURATO CORRETTAMENTE!${NC}"
echo -e "Entrambi i moduli sono pronti a connettersi ad Ollama:"
echo -e " 1. ${BLUE}Remediation Intelligence${NC} (consigli per l'analisi statica e dinamica)"
echo -e " 2. ${BLUE}Broken Authentication Discovery${NC} (scansione ed identificazione automatica)"
echo -e "${BLUE}====================================================================${NC}"
