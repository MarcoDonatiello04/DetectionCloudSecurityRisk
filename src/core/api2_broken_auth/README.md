# Broken Authentication Module

## Obiettivo
Il sistema deve essere repository-independent: dato qualsiasi repository in input, deve identificare automaticamente lo stack tecnologico, localizzare la gestione dell'autenticazione.

## Fase 1 - Discovery
- **Manifest Files**: Leggi i file di manifest:
  - `package.json` (Node.js)
  - `requirements.txt` (Python)
  - `pyproject.toml` (Python moderno)
  - `pom.xml` (Java Maven)
  - `build.gradle` (Java Gradle)
  - `go.mod` (Go)
  - `Gemfile` (Ruby)
  - `composer.json` (PHP)
  - `Cargo.toml` (Rust)
- **Configuration Files**: Leggi i file di configurazione:
  - `.env.example` (mai committare `.env` reale)
  - `config.yml` / `config.yaml`
  - `application.yml` / `application.properties` (Spring Boot)
  - `settings.py` (Django)
- **Infrastructure Files**: Leggi i file di infrastruttura:
  - `docker-compose.yml`
  - `Dockerfile`
- **LLM Processing**: Invia questi file a un LLM (via API) con il seguente obiettivo:
  - Identificare lo stack tecnologico.
  - Identificare le librerie di autenticazione usate.
  - Identificare i servizi esterni coinvolti (Cognito, Auth0, Okta, ecc.).
- **Output**: L'output di questa fase deve essere un oggetto strutturato JSON con:
  - `linguaggio`
  - `framework`
  - `librerie_auth`
  - `identity_provider`
  - `file_configurazione_rilevanti`

## Cosa NON fare
- Non analizzare tutti i file della repository indiscriminatamente.
- Non hardcodare liste di librerie note: delegare questo ragionamento all'LLM.
- Non eseguire mai test dinamici senza un ambiente isolato.
- Non loggare mai secret, token o credenziali anche se trovati nel codice.
