#!/bin/bash
set -e

# Colori
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}=========================================================${NC}"
echo -e "${BLUE}   [FASE 1] Setup Ambiente e Container Docker            ${NC}"
echo -e "${BLUE}=========================================================${NC}"

# 1. Verifica/Avvio LocalStack
echo -e "${YELLOW}[1.1] Controllo LocalStack...${NC}"
if ! docker ps --format '{{.Names}}' | grep -q "^localstack-main$"; then
    echo -e "${BLUE}[~] Il container 'localstack-main' non è in esecuzione. Tento l'avvio...${NC}"
    if docker ps -a --format '{{.Names}}' | grep -q "^localstack-main$"; then
        docker start localstack-main
        echo -e "${GREEN}[+] Container 'localstack-main' avviato.${NC}"
    else
        echo -e "${BLUE}[~] Creazione e avvio di un nuovo container LocalStack...${NC}"
        docker run -d \
          --name localstack-main \
          -p 4566:4566 \
          -p 4510-4559:4510-4559 \
          -v /var/run/docker.sock:/var/run/docker.sock \
          localstack/localstack:latest
        echo -e "${GREEN}[+] Container 'localstack-main' creato e avviato.${NC}"
    fi
else
    echo -e "${GREEN}[+] LocalStack è già in esecuzione.${NC}"
fi


until [ "$(curl -s -o /dev/null -w "%{http_code}" http://localhost:4566/_localstack/health || echo '000')" = "200" ]; do
    printf "."
    sleep 2
done
echo -e "\n${GREEN}[+] LocalStack è pronto sulla porta 4566!${NC}"

# 2. Avvio dei container via docker-compose
echo -e "${YELLOW}[1.2] Avvio servizi (Keycloak, ZAP, Mitmproxy, API Target) via Docker Compose...${NC}"
docker compose up -d

# 3. Attesa Keycloak
echo -e "${YELLOW}[1.3] Attesa caricamento di Keycloak...${NC}"
until [ "$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/realms/master || echo '000')" = "200" ]; do
    printf "."
    sleep 2
done
echo -e "\n${GREEN}[+] Keycloak è pronto sulla porta 8080!${NC}"

# 4. Configurazione Realm, Client e Utenti in Keycloak
echo -e "${YELLOW}[1.4] Configurazione automatica degli utenti e client in Keycloak...${NC}"
docker exec -t tesi-keycloak /opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master --user admin --password admin

# Crea il Realm 'myrealm' se non esiste
if ! docker exec -t tesi-keycloak /opt/keycloak/bin/kcadm.sh get realms/myrealm >/dev/null 2>&1; then
    docker exec -t tesi-keycloak /opt/keycloak/bin/kcadm.sh create realms -s realm=myrealm -s enabled=true
    echo -e "${GREEN}[+] Realm 'myrealm' creato con successo.${NC}"
else
    echo -e "${BLUE}[~] Realm 'myrealm' già esistente.${NC}"
fi

# Crea il Client 'security-platform-client' se non esiste
if ! docker exec -t tesi-keycloak /opt/keycloak/bin/kcadm.sh get clients -r myrealm | grep -q "security-platform-client"; then
    docker exec -t tesi-keycloak /opt/keycloak/bin/kcadm.sh create clients -r myrealm -s clientId=security-platform-client -s enabled=true -s publicClient=true -s directAccessGrantsEnabled=true
    echo -e "${GREEN}[+] Client 'security-platform-client' creato con successo.${NC}"
else
    echo -e "${BLUE}[~] Client 'security-platform-client' già esistente.${NC}"
fi

# Crea l'utente 'user_a' se non esiste
if ! docker exec -t tesi-keycloak /opt/keycloak/bin/kcadm.sh get users -r myrealm | grep -q "user_a"; then
    docker exec -t tesi-keycloak /opt/keycloak/bin/kcadm.sh create users -r myrealm -s username=user_a -s enabled=true -s email=user_a@example.com -s firstName=User -s lastName=A -s emailVerified=true
    docker exec -t tesi-keycloak /opt/keycloak/bin/kcadm.sh set-password -r myrealm --username user_a --new-password Password123!
    echo -e "${GREEN}[+] Utente 'user_a' (Vittima) configurato.${NC}"
else
    # Aggiorna la password in ogni caso per sicurezza
    docker exec -t tesi-keycloak /opt/keycloak/bin/kcadm.sh set-password -r myrealm --username user_a --new-password Password123!
    echo -e "${BLUE}[~] Utente 'user_a' già esistente. Password ripristinata.${NC}"
fi

# Crea l'utente 'user_b' se non esiste
if ! docker exec -t tesi-keycloak /opt/keycloak/bin/kcadm.sh get users -r myrealm | grep -q "user_b"; then
    docker exec -t tesi-keycloak /opt/keycloak/bin/kcadm.sh create users -r myrealm -s username=user_b -s enabled=true -s email=user_b@example.com -s firstName=User -s lastName=B -s emailVerified=true
    docker exec -t tesi-keycloak /opt/keycloak/bin/kcadm.sh set-password -r myrealm --username user_b --new-password Password123!
    echo -e "${GREEN}[+] Utente 'user_b' (Attaccante) configurato.${NC}"
else
    # Aggiorna la password in ogni caso per sicurezza
    docker exec -t tesi-keycloak /opt/keycloak/bin/kcadm.sh set-password -r myrealm --username user_b --new-password Password123!
    echo -e "${BLUE}[~] Utente 'user_b' già esistente. Password ripristinata.${NC}"
fi

# Crea l'utente 'admin_user' se non esiste
if ! docker exec -t tesi-keycloak /opt/keycloak/bin/kcadm.sh get users -r myrealm | grep -q "admin_user"; then
    docker exec -t tesi-keycloak /opt/keycloak/bin/kcadm.sh create users -r myrealm -s username=admin_user -s enabled=true -s email=admin_user@example.com -s firstName=Admin -s lastName=User -s emailVerified=true
    docker exec -t tesi-keycloak /opt/keycloak/bin/kcadm.sh set-password -r myrealm --username admin_user --new-password Password123!
    # Crea il ruolo 'admin' se non esiste e assegnalo all'utente
    docker exec -t tesi-keycloak /opt/keycloak/bin/kcadm.sh create roles -r myrealm -s name=admin || true
    docker exec -t tesi-keycloak /opt/keycloak/bin/kcadm.sh add-roles -r myrealm --uusername admin_user --rolename admin || true
    echo -e "${GREEN}[+] Utente 'admin_user' (Admin) configurato.${NC}"
else
    docker exec -t tesi-keycloak /opt/keycloak/bin/kcadm.sh set-password -r myrealm --username admin_user --new-password Password123!
    echo -e "${BLUE}[~] Utente 'admin_user' già esistente. Password ripristinata.${NC}"
fi

echo -e "\n${GREEN}[+] CONFIGURAZIONE AMBIENTE COMPLETATA CON SUCCESSO!${NC}"
echo -e "${BLUE}=========================================================${NC}"
