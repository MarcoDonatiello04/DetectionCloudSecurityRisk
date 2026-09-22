# ADR-006: Rimozione del modulo Shadow API, dell'Event Bus e del caricamento dinamico dei plugin

## Status
Accepted — supera la parte di [ADR-002](adr-002-architecture-separation.md) relativa all'Event Bus e ai plugin.

## Context
ADR-002 aveva introdotto un Event Bus in memoria (`EventBus`, `IEventBus`, `DomainEvent`) e un `PluginLoader` che caricava a runtime i detector (`IDetector`), in ascolto di `EVENT_STATIC_SCAN_COMPLETED` e `EVENT_TRAFFIC_CAPTURED` e con i propri findings emessi su `EVENT_FINDING_DETECTED`. Una verifica sul codice ha mostrato che il meccanismo non era mai attivo:

1. **Un solo detector, mai caricato.** L'unica implementazione di `IDetector` era il rilevatore Shadow API (`src/core/shadow_api/`), ma il `PluginLoader` cercava in `src/plugins` (`DEFAULT_PLUGINS_DIR`), una cartella inesistente. Né la CLI né la dashboard lo eseguivano.
2. **Nessun sottoscrittore reale.** L'unico altro handler sul bus era l'orchestratore stesso, in ascolto dei findings dei detector; `EVENT_PIPELINE_COMPLETED` non aveva sottoscrittori. Tutti i moduli OWASP (`src/core/api*`) sono eseguiti direttamente dai runner, fuori dal bus.
3. **Traffico simulato.** Senza traffico mitmproxy la CLI generava due richieste fittizie, fra cui un endpoint di debug "ombra", solo per far girare i detector. Quel traffico finiva anche nella fase D-AST di BOLA, attivando l'inferenza di ownership su dati inventati.
4. **Nessuna validazione.** Il rilevatore Shadow API non aveva test né un riferimento di verità, e la sua confidenza (0.9) e l'esposizione a Internet erano costanti.

## Decision
Si rimuovono il rilevatore Shadow API, l'Event Bus, gli eventi di dominio, il `PluginLoader`, le interfacce rimaste senza utilizzatori (`IDetector`, `IEventBus`, `IRemediation`), l'eccezione `PluginLoadException`, la sorgente `FindingSource.SHADOW_API` e il traffico simulato della CLI.

`ScanPipelineOrchestrator` esegue gli scanner registrati e consegna i findings al `RiskCorrelationEngine` con chiamate dirette. Il disaccoppiamento resta affidato alle interfacce di dominio: l'orchestratore conosce solo `IScanner`, e aggiungere uno scanner significa registrare un nuovo adapter nel composition root (`cli/main.py`, `server.py`).

Il traffico catturato da mitmproxy resta: alimenta l'inferenza di identità e ownership del modulo BOLA (Assessment Mode).

## Consequences

### Positive
- Il flusso di esecuzione si legge in un solo metodo, senza callback registrate a runtime.
- Nessun componente dichiarato dall'architettura resta senza un'esecuzione reale.
- Senza traffico catturato, BOLA ricade sul seeding deterministico invece che su richieste inventate.

### Negative
- API9:2023 (Improper Inventory Management) non ha più un rilevatore. Il confronto fra rotte dichiarate e traffico osservato resta uno sviluppo futuro.
- Aggiungere uno scanner richiede una riga nel composition root: non esiste più la scoperta automatica dei plugin.
