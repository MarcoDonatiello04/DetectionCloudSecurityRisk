# ADR-002: Separazione Architetturale tra Scanner, Risk Engine e Reporter (Clean Architecture & Event-Driven)

## Status
Accepted

## Context
L'integrazione di molteplici scanner di sicurezza (Checkov per IaC, Semgrep per AST, Spectral per OpenAPI, ZAP per DAST) introduce sfide significative di accoppiamento del codice. Scrivere un orchestratore monolitico accoppiato direttamente con le API o i comandi CLI dei singoli strumenti rende la piattaforma fragile, difficile da estendere (es. per aggiungere un nuovo scanner) e quasi impossibile da testare in isolamento. 

Inoltre, il flusso di analisi della sicurezza cloud si articola in fasi temporali differenti (analisi IaC pre-deployment, scansione del traffico live, stimolazione D-AST attiva). La piattaforma ha bisogno di un'architettura in grado di coordinare queste fasi in modo decoupled e reattivo.

## Decision
Si decide di adottare una **Clean Architecture** supportata da un **In-Memory Event Bus thread-safe** e da contratti ad interfacce astratte (`IScanner`, `IDetector`, `IRemediation`, `IEventBus`).

- **Scanner (Infrastructure Layer)**: Ciascun tool esterno viene incapsulato in un adapter concreto che implementa l'interfaccia `IScanner` e traduce l'output grezzo (JSON o XML) nel modello di entità unificato del dominio (`Finding`).
- **Risk Engine (Application Layer)**: Registra callbacks sull'Event Bus per eventi di scansione completata (`EVENT_STATIC_SCAN_COMPLETED`, `EVENT_TRAFFIC_CAPTURED`). Esegue la correlazione e lo scoring in modo del tutto indipendente rispetto alla logica di esecuzione fisica degli scanner.
- **Plugins/Detectors (Domain & Application)**: I detector dinamici (BOLA, Shadow API) sono plugin caricati a runtime tramite `PluginLoader` che interagiscono esclusivamente tramite l'Event Bus sottoscrivendosi ed emettendo eventi di vulnerabilità trovata (`EVENT_FINDING_DETECTED`).
- **Reporter/Presenter (Presentation Layer)**: Consuma i risultati finali dell'orchestratore per salvare i report persistenti (JSON) e renderizzare la dashboard interattiva (HTML).

## Considered Options

### Opzione A: Orchestrazione Monolitica Sequenziale (Script-Based)
- **Pro**: Semplicità iniziale di scrittura, tempi di sviluppo estremamente ridotti, overhead minimo dovuto all'assenza di classi e bus.
- **Contro**: Accoppiamento massimo; l'aggiunta di un plugin richiede la modifica diretta del codice dell'orchestratore principale; complessità insostenibile per testare i componenti con mock.

### Opzione B: Clean Architecture con Event Bus in memoria (Selezionata)
- **Pro**: Accoppiamento debole (decoupling) assoluto; estensibilità plug-and-play tramite plugin caricati dinamicamente; testabilità eccellente tramite mock degli adapter e asserzioni sui messaggi del bus degli eventi.
- **Contro**: Aumento della complessità strutturale; introduzione di boilerplate (interfacce, classi event, eccezioni specifiche); tracciamento del flusso di esecuzione (debugging delle callback) leggermente più complesso.

## Consequences

### Positive
- Gli scanner statici, i detector dinamici e la logica di reporting possono evolvere, essere aggiunti o rimossi in modo del tutto indipendente senza modificare l'orchestratore core.
- Codice altamente coeso e testabile tramite unit test veloci e isolati.

### Negative
- Necessità di gestire i lock di sincronizzazione (`RLock`) sull'Event Bus in contesti multithreading (es: active scanning concorrente).
- Curva di apprendimento più ripida per gli sviluppatori a causa delle astrazioni introdotte.
