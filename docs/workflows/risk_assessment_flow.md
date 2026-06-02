# Flowchart del Flusso di Scansione & Risk Assessment

Questo diagramma Mermaid descrive il flusso sequenziale e le diramazioni logiche eseguite dalla piattaforma durante una scansione completa di sicurezza cloud.

```mermaid
flowchart TD
    %% ==========================================
    %% DEFINIZIONE DEGLI STILI (CSS CLASSES)
    %% ==========================================
    classDef inputStyle fill:#D1E8E2,stroke:#116466,stroke-width:2px,color:#116466;
    classDef processingStyle fill:#EFE6DD,stroke:#D9B08C,stroke-width:2px,color:#2C3E50;
    classDef decisionStyle fill:#FFCB9A,stroke:#D1E8E2,stroke-width:2px,color:#2C3E50;
    classDef outputStyle fill:#F1F0E8,stroke:#2C3E50,stroke-width:2px,color:#2C3E50;
    classDef errorStyle fill:#FF6F59,stroke:#D10000,stroke-width:2px,color:#D10000;

    %% ==========================================
    %% STRUTTURA DEI NODI
    %% ==========================================
    Start([Inizio - Comando Utente o API Call]):::inputStyle
    Params[1. Ricezione parametri di input\n(target, tipo di scansione, soglie di rischio)]:::inputStyle
    Validate{2. Validazione input\ne credenziali cloud?}:::decisionStyle
    
    %% Ramificazioni Errore di Validazione
    ErrCreds[Errore: Input malformati o\ncredenziali non valide]:::errorStyle
    EndErr([Termina Esecuzione con Errore]):::errorStyle
    
    Connect[3. Connessione alle API Cloud\ne raccolta risorse attive]:::processingStyle
    ConnCheck{Connessione\ne API stabili?}:::decisionStyle
    
    %% Ramificazioni Errore di Connessione
    ErrConn[Errore: API cloud non raggiungibili,\ntimeout o permessi insufficienti]:::errorStyle
    
    LoopResources[4. Per ciascuna risorsa rilevata:\nesecuzione controlli di sicurezza IaC / AST / DAST]:::processingStyle
    DetectCheck{5. Rilevata vulnerabilità\no deviazione?}:::decisionStyle
    
    Score[6. Calcolo del risk score\n(Severità * Peso + Confidenza + Contesto)]:::processingStyle
    Classify[7. Classificazione del Rischio:\nCRITICAL / HIGH / MEDIUM / LOW]:::processingStyle
    
    NextResource{Altre risorse\nda scansionare?}:::decisionStyle
    
    Aggregate[8. Aggregazione dei risultati e\ndeduplicazione dei findings correlati]:::processingStyle
    Generate[9. Generazione report\n(JSON, PDF, HTML Dashboard)]:::processingStyle
    Output[10. Output finale e persistenza]:::outputStyle
    EndSuccess([Fine - Scansione Completata con Successo]):::outputStyle

    %% ==========================================
    %% COLLEGAMENTI E LOGICA DI FLUSSO
    %% ==========================================
    Start --> Params
    Params --> Validate
    
    Validate -- No/Fallito --> ErrCreds
    ErrCreds --> EndErr
    
    Validate -- Yes/Successo --> Connect
    Connect --> ConnCheck
    
    ConnCheck -- No/Fallito --> ErrConn
    ErrConn --> EndErr
    
    ConnCheck -- Yes/Successo --> LoopResources
    LoopResources --> DetectCheck
    
    DetectCheck -- Yes/Trovata --> Score
    Score --> Classify
    Classify --> NextResource
    
    DetectCheck -- No/Pulita --> NextResource
    
    NextResource -- Yes/Ancora risorsa --> LoopResources
    NextResource -- No/Completate --> Aggregate
    
    Aggregate --> Generate
    Generate --> Output
    Output --> EndSuccess
```
