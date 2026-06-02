# ADR-001: Scelta del Modello di Classificazione del Rischio (CVSS v3.1 vs Custom Scoring Pesato)

## Status
Accepted

## Context
Nei moderni ambienti cloud native, le vulnerabilità individuate tramite strumenti di analisi statica (IaC ed AST come Checkov e Semgrep) producono una quantità elevata di segnalazioni (alert fatigue), spesso etichettate con severità critica per default. Di contro, a livello di runtime, vulnerabilità reali (come BOLA/IDOR o Broken Authentication) possono presentare impatti e complessità differenti a seconda della configurazione ambientale del target (es. esposizione pubblica del bucket S3, presenza di dati sensibili o accessibilità senza autenticazione). 

Per calcolare un rischio accurato e contestualizzato, il sistema necessita di un modello di scoring in grado di fondere:
1. La gravità intrinseca della vulnerabilità (rilevata staticamente).
2. La confidenza empirica del finding (attribuendo un boost se la vulnerabilità è stata verificata attivamente a runtime).
3. Il contesto del rischio specifico della risorsa emulata (esposta a internet o contenente dati sensibili).

Lo standard internazionale CVSS v3.1 è rigido e complesso da calcolare programmaticamente in tempo reale per pipeline automatizzate senza la formulazione di complesse stringhe vettoriali.

## Decision
Si decide di implementare un **Modello di Scoring Pesato Personalizzato (Custom Weighted Risk Scoring)**.
La formula normalizza il punteggio di rischio finale in una scala da `0.0` a `10.0` combinando tre pesi specifici:
`Risk Score = (Base Severity * 0.6) + (Confidence * 2.0) + (Context Multiplier * 2.0)`

- **Base Severity (Peso 60%)**: Il punteggio di severità calcolato dagli scanner (Critical: 9.0, High: 7.0, Medium: 4.5, Low: 2.0).
- **Confidence (Peso 20%)**: Valore da 0.0 a 1.0 (moltiplicato per 10). Se il finding viene confermato dinamico a runtime tramite active scan/tampering, la confidenza viene forzata a 1.0.
- **Context Multiplier (Peso 20%)**: Moltiplicatore di contesto che aggiunge punti se la risorsa è esposta a Internet (+4.0), se gestisce dati sensibili (+4.0) o se è pubblica (+2.0).

## Considered Options

### Opzione A: Calcolo Dinamico dei Vettori CVSS v3.1
- **Pro**: Standardizzato a livello enterprise, interoperabilità immediata con strumenti terzi di Security Information and Event Management (SIEM).
- **Contro**: Estremamente complesso da calcolare automaticamente a partire da un output grezzo di linter; difficile mappare il boost dinamico di validazione a runtime (es. come indicare che ZAP ha sfruttato con successo la falla).

### Opzione B: Modello di Scoring Pesato Personalizzato (Custom)
- **Pro**: Estremamente flessibile ed adattabile al dominio Cloud Security; permette di differenziare in modo dinamico la severità (es. elevare un BOLA da HIGH a CRITICAL se confermato attivamente a runtime); implementazione programmatica semplice e testabile.
- **Contro**: Mancanza di standardizzazione esterna; richiede una mappatura manuale preliminare dei punteggi di severità di default per ciascun tool integrato.

## Consequences

### Positive
- Drastica riduzione dei falsi positivi: i findings puramente ipotetici (statici) rimangono con scoring intermedio, mentre le minacce verificate empiricamente a runtime salgono immediatamente a livelli critici.
- Calcolo del rischio dinamico dipendente dal contesto di rete e dai dati del backend emulato.

### Negative
- Il punteggio calcolato è specifico della piattaforma e non può essere esportato direttamente come standard CVSS senza uno strato di adattamento o di traduzione dei dati.
