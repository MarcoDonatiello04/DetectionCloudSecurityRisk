# ADR-004: Distinzione fra Esposizione e Irrobustimento nei Finding (FindingNature)

## Status
Accepted

## Context
L'adapter Checkov traduce ogni controllo fallito in un `Finding` e deriva la severità con regole a parole chiave (`public`, `admin`, `encrypt`, ...). Sul bersaglio di prova infrastrutturale e su crAPI è emerso che tali regole venivano confrontate con l'**identificativo** del controllo (`CKV_AWS_53`), che è opaco e non contiene mai quelle parole: nessuna condizione di elevazione scattava e tutte le segnalazioni (86 sul bersaglio di prova, 237 su crAPI) risultavano `MEDIUM` con punteggio uniforme `5,3`.

La fusione per risorsa del motore di correlazione aggravava l'effetto: con severità uniformi il criterio "severità maggiore" non seleziona nulla e la voce aggregata conserva il titolo del **primo controllo incontrato**. Per il bucket con ACL in lettura pubblica (`CKV_AWS_20`) il rapporto mostrava *"Ensure S3 buckets should have event notifications enabled"* (`CKV2_AWS_62`), relegando l'esposizione reale fra i sette controlli collegati.

Alla radice manca, nel catalogo Checkov, una distinzione fra controlli di **esposizione** (un varco sfruttabile: ACL pubblica, policy IAM con privilegi jolly, endpoint senza autorizzazione, segreto cablato) e controlli di **irrobustimento** (difesa in profondità o conformità: logging, versioning, lifecycle, notifiche). Senza questa distinzione un bucket privato e correttamente protetto riceve lo stesso punteggio di uno pubblico solo perché gli mancano i log.

## Decision
Si introduce una dimensione di **natura** del rischio, indipendente dallo scanner, e la si applica lungo tutta la pipeline.

### 1. Dominio — `FindingNature`
`src/domain/entities.py` definisce l'enumerazione `FindingNature` (`EXPOSURE`, `HARDENING`) e il campo opzionale `Finding.nature` (None = non classificato, comportamento storico). L'entità espone `is_directly_exploitable` e `nature_rank` (EXPOSURE 0 < non classificato 1 < HARDENING 2). La natura è serializzata in `to_dict()` con la chiave `nature`. Qualunque scanner (Checkov, Semgrep, Spectral, detector dinamici) può dichiararla.

### 2. Infrastruttura — catalogo semantico delle policy Checkov
`config/scanner_configs/checkov-policy-catalog.yaml` è un **parametro dell'analisi**, non una costante dell'adapter (percorso override via `CHECKOV_POLICY_CATALOG`). Per ogni controllo assegna natura, severità di base e flag `public` (la condizione fallita rende la risorsa raggiungibile da chiunque). Ordine di risoluzione, implementato da `CheckovPolicyCatalog` (`src/infrastructure/adapters/checkov_policy_catalog.py`):

1. `policies` — mappatura esplicita per identificativo (S3, IAM, API Gateway, Lambda, DynamoDB/SNS, rete, Kubernetes, Dockerfile, OpenAPI, segreti);
2. `prefixes` — famiglie di controlli (`CKV_SECRET_*`);
3. `keywords` — parole chiave confrontate con il **nome ufficiale** del controllo, in gruppi ordinati: termini difensivi (`encrypt`, `kms`, `waf`, ...) prima dei termini di esposizione, così che *"Secrets Manager secret is encrypted"* non sia letto come segreto esposto;
4. `defaults` — non classificato, `MEDIUM`.

Se il catalogo manca o non è leggibile, il classificatore ritorna sempre "non classificato / MEDIUM": identico all'esito precedente, nessuna pipeline si rompe.

L'adapter (`CheckovScannerAdapter.build_finding`) usa il catalogo per natura e severità, applica le regole di categoria anche al nome ufficiale (le segnalazioni S3 non ricadono più nella categoria generica) e allega `RiskContext(internet_exposed=True, public_resource=True)` **solo** ai controlli con `public: true`.

### 3. Correlazione — voce rappresentativa per natura
`RiskCorrelationEngine` non conserva più il primo finding incontrato: quando due findings condividono la chiave di risorsa, la voce rappresentativa è quella che **prevale per natura e poi per severità** (`_outranks`); a parità completa resta la prima (ordine deterministico). Un controllo di natura inferiore non altera mai la severità della voce rappresentativa. I controlli assorbiti restano come sotto-elementi informativi in `raw_data["aggregated_checks"]` (id, regola, titolo, severità, natura), oltre che in `related_findings`. Un riscontro empirico a runtime porta la natura a `EXPOSURE`, coerentemente con l'elevazione di severità già prevista.

### 4. Scoring — nessun bonus di esposizione per l'hardening
La formula di ADR-001 resta invariata. Per i finding `HARDENING` il fattore di contesto vale `DEFAULT_CONTEXT_HARDENING = 0` (in `src/core/config.py` e `config/risk_scoring.yaml`): una linea di difesa mancante non è un vettore d'accesso. Per i finding non classificati il punteggio è identico a prima (`5,3` per `MEDIUM` con confidenza 1).

Punteggi risultanti sul bersaglio di prova (confidenza 1; `CRITICAL = 10` dopo [ADR-005](adr-005-risk-scoring.md), che rende anche la confidenza dipendente dalla precisione della regola del catalogo):

| Finding | Natura | Severità | Contesto | Punteggio |
|---|---|---|---|---|
| ACL pubblica in lettura (`CKV_AWS_20`) | EXPOSURE | CRITICAL | esposto + pubblico (6) | **9,2** |
| Policy IAM `*`/`*` (`CKV_AWS_62`) | EXPOSURE | CRITICAL | default (3) | 8,6 |
| Metodo API senza autorizzazione (`CKV_AWS_59`) | EXPOSURE | HIGH | esposto + pubblico (6) | 7,4 |
| Public Access Block disattivato (`CKV_AWS_53`) | EXPOSURE | HIGH | default (3) | 6,8 |
| Controllo non classificato | — | MEDIUM | default (3) | 5,3 |
| Cifratura KMS assente (`CKV_AWS_145`) | HARDENING | MEDIUM | 0 | 4,7 |
| Notifiche di evento assenti (`CKV2_AWS_62`) | HARDENING | LOW | 0 | **3,2** |

### 5. Presentazione
La pagina dei risultati Checkov ordina le voci per natura, punteggio di rischio e severità, mostra il badge *Esposizione*/*Hardening*, il punteggio e il numero di controlli assorbiti sulla stessa risorsa (con il dettaglio di quanti sono di hardening).

## Considered Options

### Opzione A: applicare le parole chiave al nome ufficiale, senza natura
- **Pro**: correzione minima, ripristina il comportamento previsto dalla tabella dell'adapter.
- **Contro**: non distingue esposizione da irrobustimento; un bucket privato senza log continua a ricevere il bonus di contesto; la fusione per risorsa resta "primo incontrato" a parità di severità.

### Opzione B: natura nel dominio + catalogo esterno + correlazione per natura (scelta)
- **Pro**: la distinzione è un concetto di dominio riusabile da ogni scanner; il catalogo è configurabile senza toccare il codice; la voce aggregata rappresenta sempre il rischio maggiore; il punteggio separa davvero attack surface e igiene.
- **Contro**: il catalogo va mantenuto al crescere dei controlli; le parole chiave di ripiego restano euristiche (mitigato dalla precedenza dei termini difensivi e dalla mappatura esplicita dei controlli noti).

### Opzione C: due pipeline separate (attack surface vs compliance)
- **Pro**: separazione netta nella reportistica.
- **Contro**: duplica orchestrazione e correlazione; la stessa risorsa comparirebbe in due inventari, contro il requisito di una voce per risorsa.

## Consequences

### Positive
- L'ACL pubblica del primo bucket è ora la voce rappresentativa della risorsa (`CRITICAL`, 8,6) e i bucket quarto e quinto, privi di esposizione per costruzione, scendono a `LOW`/3,2.
- Le 207 segnalazioni Kubernetes di crAPI, in gran parte pratiche di irrobustimento, non competono più con le esposizioni reali nel punteggio.
- Nessuna rottura: campo opzionale, catalogo con degradazione sicura, punteggio invariato per i finding non classificati, test esistenti verdi.

### Negative
- I controlli Checkov non presenti nel catalogo e non riconosciuti dalle parole chiave restano non classificati (`MEDIUM`): la copertura del catalogo va estesa quando si integrano nuovi provider.
- La natura assegnata da un catalogo statico non tiene conto dell'intento (un bucket pubblico è legittimo per un sito statico): resta il limite di contesto già noto, mitigabile solo con informazioni esterne al manifest.
