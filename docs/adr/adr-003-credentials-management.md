# ADR-003: Strategia di Gestione delle Credenziali Cloud per i Test (Environment Variables vs Secrets Manager vs Config File)

## Status
Accepted

## Context
La pipeline di scansione ed esecuzione dei test D-AST necessita di credenziali per l'interazione con Keycloak (credenziali degli utenti di test `user_a` e `user_b`, credenziali client secrets), credenziali temporanee AWS per l'interazione con LocalStack (AWS access key e secret key di test), chiavi API per OWASP ZAP ed endpoint degli indirizzi delle API target. 

Trattandosi di un'applicazione automatizzata destinata all'esecuzione all'interno di pipeline CI/CD o in ambienti di sviluppo locali containerizzati, è fondamentale garantire che:
1. Nessuna credenziale sensibile venga committata nel repository Git (rischio di leaks).
2. La configurazione degli endpoint delle API sia dinamica, poiché a runtime l'URL dell'API Gateway sollevato da Terraform in LocalStack può variare.
3. Il caricamento delle credenziali sia compatibile con l'esecuzione in container isolati (es. dentro la rete Docker Compose).

## Decision
Si decide di gestire le credenziali e la configurazione degli indirizzi tramite **Variabili d'Ambiente (Environment Variables) supportate da un meccanismo di file dotenv locale (`.env` / `.target_env`)**.

- I parametri fissi o di default dell'ambiente vengono caricati dalle variabili d'ambiente di sistema.
- I parametri generati dinamicamente (es. l'URL di invoke di API Gateway estratto dagli output di Terraform) vengono scritti dallo script di provisioning in un file locale `config/environments/.target_env`.
- Il modulo CLI e l'orchestratore caricano queste impostazioni leggendo le variabili d'ambiente (con fallback sui file `.env` locali esclusi dal tracciamento Git tramite `.gitignore`).

## Considered Options

### Opzione A: Integrazione con Cloud Secrets Manager (AWS Secrets Manager / HashiCorp Vault)
- **Pro**: Standard di sicurezza industriale, tracciamento degli accessi ai segreti, rotazione automatica delle chiavi.
- **Contro**: Introduce una dipendenza esterna di rete; richiede connettività Internet/AWS reale per l'esecuzione dei test locali, invalidando l'emulazione offline basata su LocalStack.

### Opzione B: File di Configurazione Condiviso (JSON/YAML) a repository
- **Pro**: Semplicità immediata; nessun setup di variabili d'ambiente richiesto per gli sviluppatori.
- **Contro**: Rischio elevatissimo di leak accidentali di credenziali tramite commit su repository pubblici; scarsa flessibilità per configurazioni differenziate tra ambienti (locale vs CI/CD).

### Opzione C: Variabili d'Ambiente con Dotenv Fallback (Selezionata)
- **Pro**: Conforme alla metodologia 12-Factor App; permette il passaggio dinamico di parametri tra script della pipeline (es: Terraform scrive `.target_env` che viene poi caricato ed iniettato nel CLI Python); compatibile al 100% con Docker ed esecuzioni offline in ambiente lab.
- **Contro**: Richiede una gestione rigorosa del file `.gitignore` per escludere i file `.env`/`.target_env` locali; gli sviluppatori devono configurare manualmente l'ambiente se lanciano i comandi standalone.

## Consequences

### Positive
- Zero segreti committati su Git.
- Pipeline fluida e dinamica: l'output infrastrutturale di Terraform viene passato automaticamente allo script di D-AST in modo nativo e disaccoppiato.
- Esecuzione offline garantita in container Docker isolati.

### Negative
- Debito tecnico minore legato alla manutenzione manuale delle variabili ambientali per gli sviluppatori che eseguono test manuali fuori dal flusso orchestrato di `make`.
