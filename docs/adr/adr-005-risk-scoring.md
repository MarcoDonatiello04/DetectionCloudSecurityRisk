# ADR-005: Allineamento del punteggio di rischio alla formula documentata

## Status
Accepted

## Context
ADR-001 definisce il punteggio come `R = min(10, 0.6·S + 0.2·(10·C) + 0.2·X)`. Una verifica sul codice ha mostrato che l'implementazione se ne discostava in quattro punti:

1. **`C` non era mai calcolata.** Ogni adapter scriveva un letterale (Checkov 1.0, Spectral 1.0, Semgrep 0.8, ZAP 0.9, Shadow API 0.9) e il motore lo sovrascriveva a 0.9 per i finding runtime non correlati e a 1.0 per quelli correlati. Il termine pesava il 20% del punteggio senza trasportare informazione.
2. **`X` aveva una regola nascosta.** Senza `RiskContext`, i finding di categoria `AUTHENTICATION`/`AUTHORIZATION` ricevevano 6, gli altri 3: un bonus di esposizione deciso dalla categoria e non da un'evidenza. `CONTEXT_SCORE_SENSITIVE_DATA` era codice morto, perché nessun adapter impostava `sensitive_data_detected`; `attack_complexity` e `impact` venivano scritti da ZAP ma mai letti.
3. **`min(10, ·)` non scattava mai.** Con `CRITICAL = 9` il massimo raggiungibile era `0.6·9 + 2 + 2 = 9.4`.
4. **Il punteggio non era consumato.** Finiva in `raw_data["correlated_risk_score"]` ma la dashboard ordinava per natura e severità senza mostrarlo.

## Decision

### Formula e parametri
La formula resta quella di ADR-001; cambiano i suoi ingressi. Tutti i parametri sono in `config/risk_scoring.yaml` (percorso sovrascrivibile con la variabile `RISK_SCORING_CONFIG`), letto da `load_risk_scoring_config` in `src/core/config.py`; ogni chiave assente ricade sulla costante corrispondente del modulo. `src/core/risk_config.py` espone l'istanza condivisa usata da `RiskCorrelationEngine`, da `Severity.score` e dagli adapter.

| Parametro | Chiave YAML | Default |
|---|---|---|
| Peso severità `wS` | `weights.severity` | 0.6 |
| Peso confidenza `wC` | `weights.confidence` | 0.2 |
| Peso contesto `wX` | `weights.context` | 0.2 |
| `S` per CRITICAL / HIGH / MEDIUM / LOW / INFO | `severity_scores.*` | **10** / 7 / 4.5 / 2 / 0 |
| `X`: esposto a Internet | `context.internet_exposed` | +4 |
| `X`: dati sensibili | `context.sensitive_data` | +4 |
| `X`: risorsa pubblica | `context.public_resource` | +2 |
| `X` senza `RiskContext` (qualunque categoria) | `context.default_other` | 3 |
| `X` per natura HARDENING | `context.default_hardening` | 0 |
| Massimo | `max_risk_score` | 10 |
| Normalizzatore di `C` | `confidence_normalizer` | 10 |
| `C` Checkov per `matched_by` exact / prefix / keyword / default | `confidence.catalog_match.*` | 1.0 / 0.9 / 0.8 / 0.6 |
| `C` ZAP per livello User Confirmed / High / Medium / Low | `confidence.zap_level.*` | 1.0 / 0.9 / 0.7 / 0.5 |
| `C` Semgrep, autenticazione trovata | `confidence.semgrep_positive_match` | 0.95 |
| `C` Semgrep, assenza di autenticazione dedotta | `confidence.semgrep_inferred_absence` | 0.7 |

`CRITICAL` vale 10 così che il massimo teorico (`6 + 2 + 2`) coincida con `max_risk_score` e la guardia sia effettiva.

### Origine della confidenza per sorgente
- **Checkov**: la precisione della regola del catalogo che ha classificato il controllo (`PolicyClassification.matched_by`): mappatura esplicita per ID (`exact`) > famiglia per prefisso > parola chiave sul nome ufficiale > esito predefinito.
- **ZAP**: il livello dichiarato dall'alert; un alert `False Positive` viene scartato e non entra nell'inventario. Livello assente o sconosciuto: 0.7.
- **Semgrep**: un decoratore/handler di autenticazione trovato è un riscontro positivo (0.95); la sua assenza è solo dedotta dall'analisi statica (0.7).
- **Spectral** conserva il valore precedente (1.0): la violazione di contratto è deterministica. (Il rilevatore Shadow API, che dichiarava 0.9, è stato rimosso: vedi ADR-006.)
- **Conferma empirica**: un finding statico correlato con un riscontro a runtime riceve `C = 1.0`; un `RiskContext.exploitable = True` forza `C = 1.0` nel calcolo. I finding runtime non correlati conservano la confidenza del loro adapter.

### Contesto dichiarato, non inferito
- Nessuna regola per categoria: senza `RiskContext` vale sempre `default_other = 3`. L'esposizione va dichiarata dalla sorgente: Spectral e Semgrep allegano `RiskContext(internet_exposed=True)` agli endpoint senza autenticazione; Checkov costruisce `RiskContext(internet_exposed, public_resource, sensitive_data_detected)` dal catalogo (`public`, nuovo flag `sensitive_data` per segreti cablati e cifratura a riposo) e lo omette solo se tutti i flag sono falsi.
- **Irrobustimento**: `nature == HARDENING ⇒ X = 0`, sempre, anche se il catalogo dichiara dati sensibili o esposizione (ADR-004).
- `RiskContext` perde `attack_complexity` e `impact`, che nessuno leggeva.

### Consumo nella dashboard
La pagina dei risultati Checkov ordina per natura (EXPOSURE, non classificato, HARDENING), poi per `raw_data.correlated_risk_score` decrescente, poi per severità, e mostra il punteggio in un badge accanto alla severità (assente se il motore non lo ha calcolato).

## Considered Options

### Opzione A: lasciare la formula com'era e documentare le deviazioni
- **Pro**: nessuna modifica di codice.
- **Contro**: il 20% del punteggio resterebbe privo di informazione, il bonus per categoria continuerebbe a premiare la categoria e non l'evidenza, e la scala 0-10 non sarebbe mai raggiunta.

### Opzione B: ingressi della formula derivati dalle sorgenti, parametri esterni (scelta)
- **Pro**: `C` e `X` trasportano ciò che gli adapter sanno davvero; i parametri sono tarabili senza toccare il codice; il massimo è raggiungibile; il punteggio è visibile dove serve.
- **Contro**: i finding `CRITICAL` salgono di 0,6 punti (ad es. ACL pubblica da 8,6 a 9,2) e un controllo Checkov classificato solo per parola chiave scende (confidenza 0,8): le serie storiche di punteggi non sono direttamente confrontabili.

## Consequences

### Positive
- Esempi (confidenza 1): CRITICAL esposto e pubblico 9,2; HIGH senza contesto 6,8; MEDIUM non classificato 5,3; LOW hardening 3,2; CRITICAL esposto, pubblico e con dati sensibili 10,0.
- Un finding `AUTHENTICATION` senza evidenza di esposizione non è più avvantaggiato per la sola categoria.
- I parametri della formula sono in un unico file, con fallback sicuro sui default del codice.

### Negative
- I punteggi già pubblicati nei report d'esempio cambiano e vanno rigenerati.
- Il catalogo Checkov richiede la manutenzione del nuovo flag `sensitive_data` al crescere dei controlli.
