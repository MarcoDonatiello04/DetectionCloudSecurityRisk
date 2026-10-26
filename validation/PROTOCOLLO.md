# Protocollo di validazione su bersagli esterni

Questo protocollo serve a ottenere risultati che non dipendano dall'autore dello strumento.
Va seguito nell'ordine indicato, e ogni deviazione va annotata nel registro in fondo.

## 1. Insiemi di bersagli

| Insieme | Bersagli | Uso |
|---|---|---|
| Sviluppo | coppie gemelle in `data/test_targets/*`, `repo_target`, repository esterni BOLA/BFLA già usati, crAPI | verifica dell'implementazione (il risultato dice che il codice fa ciò che si intendeva) |
| **Prova** | `data/test_targets/external/{vampi,dvapi,sadcloud}` | **validazione** (vedi `data/test_targets/external/PROVENIENZA.md`) |

Se un bersaglio di prova viene usato per correggere regole o configurazione, passa all'insieme
di sviluppo: i suoi risultati restano nel capitolo solo come verifica, non come validazione.

## 2. Congelamento (prima di qualsiasi esecuzione)

1. Fare il commit dello stato attuale dello strumento, dei riferimenti di verità
   (`validation/ground_truth/`) e di questo protocollo.
2. Creare il tag: `git tag -a v-validazione -m "Strumento congelato per la validazione esterna"`.
3. Da qui in poi regole, cataloghi e configurazioni dei moduli non si modificano. Un difetto
   emerso durante le esecuzioni si annota nel registro; se lo si corregge, si ripete
   l'esecuzione e la si riporta separata, dichiarando la modifica.
4. L'agente di sviluppo non deve avere accesso a `data/test_targets/external/` né ai risultati.

## 3. Riferimenti di verità

`validation/ground_truth/{vampi,dvapi,sadcloud}.yaml`, scritti dalla documentazione degli autori
prima di ogni esecuzione. Ogni file riporta fonti, revisione del bersaglio e regola di
corrispondenza. Le scelte fissate a priori:

- categoria OWASP 2023 secondo la definizione, con un'eventuale **alternativa accettata**;
- le voci fuori dalla Top 10 2023 (VAmPI V01, DVAPI D10) sono riportate ma escluse dalle metriche;
- la numerazione di DVAPI da 0xa6 in poi non coincide con il 2023: fa fede la definizione.

## 4. Esecuzione

Servizi della piattaforma necessari (dalla radice): `docker compose up -d mitmproxy owasp-zap`.
Keycloak non serve: i bersagli esterni hanno un'autenticazione propria.

### VAmPI (modalità vulnerabile e sicura)
```bash
(cd data/test_targets/external/vampi && docker compose up -d)   # 5001 sicuro, 5002 vulnerabile
make traffico-esercizio BERSAGLIO=vampi
make dashboard-vampi             # dashboard: scansione statica (/scan), poi scansione completa
# terminata la prima, fermare la dashboard e ripetere sulla modalità sicura:
make traffico-esercizio BERSAGLIO=vampi_sicuro
make dashboard-vampi-sicuro
```

### DVAPI
```bash
(cd data/test_targets/external/dvapi && docker compose up --build -d)   # porta 3000 (+ MongoDB 27017)
make traffico-esercizio BERSAGLIO=dvapi
make dashboard-dvapi
```

### sadcloud (solo Terraform, nessuna applicazione)
```bash
make dashboard-sadcloud          # solo scansione statica (/scan); i moduli dinamici non si applicano
```

In ogni dashboard il riquadro "Bersaglio" della pagina dei risultati unificati deve mostrare il
bersaglio, il contratto e l'URL attesi. Se mostra altro, fermarsi.

Ordine in dashboard: prima la scansione statica (Checkov, Semgrep, Spectral: produce l'inventario
delle rotte), poi la scansione completa dei moduli Core (BOLA dinamica inclusa).

## 5. Evidenze da conservare

Per ogni esecuzione, al termine, copiare `output/external/<bersaglio>/` in
`validation/risultati/<AAAA-MM-GG>_<bersaglio>/` e fare il commit. I file contengono:
`unified_security_report.json` (statico), `core_findings.json` (tutte le segnalazioni dei moduli
Core con bersaglio e contratto usati), `benchmark_results.json`, `bola_scan_results.json`,
`raw_traffic.json`. Annotare inoltre: commit/tag dello strumento, versioni di Checkov, Semgrep,
Spectral e ZAP (`checkov --version`, `semgrep --version`, `spectral --version`).

## 6. Analisi

1. Per ogni voce del riferimento: segnalata (VP) o no (FN), con la segnalazione che la copre.
2. Per ogni segnalazione non corrispondente a una voce: classificazione manuale in
   vero positivo non documentato, falso positivo o indeterminato, con motivazione.
3. Metriche per categoria: VP, FP, FN. Recall **complessiva** e recall **nel perimetro**
   (le voci fuori perimetro, es. linguaggio non supportato, si contano a parte, con il motivo).
4. VAmPI: confronto fra modalità vulnerabile e sicura **solo per il livello dinamico** (il codice
   è identico nelle due modalità).
5. sadcloud: corrispondenza controllo Checkov ↔ voce stabilita a mano e riportata per esteso.
6. Se possibile, far classificare a un collega un campione di segnalazioni senza mostrargli il
   riferimento.

## 7. Limiti noti prima dell'esecuzione (da riportare, non da correggere)

- **DVAPI, contratto:** `src/swagger/DVAPI.postman_collection.yaml` contiene un carattere di
  tabulazione (riga 308) che lo rende YAML non valido per PyYAML; i livelli che leggono il contratto
  potrebbero non usarlo.
- **DVAPI, Broken Authentication:** la discovery del modulo cerca il manifest delle dipendenze
  nella radice del repository, mentre in DVAPI `package.json` sta in `src/`; il modulo può
  fallire su questo bersaglio.
- **DVAPI, BOLA dinamica:** dagli esempi della collezione Postman il JWT riporta `userId` e non
  `sub`; l'inferenza delle identità dal traffico richiede `sub`. In tal caso la scansione si ferma
  con un errore esplicito invece di usare identità fittizie.
- **VAmPI:** vulnerabile e sicuro sono lo stesso codice (interruttore a runtime).
- **sadcloud:** le voci derivano da ScoutSuite, che controlla l'account AWS in esecuzione; alcune
  descrivono l'assenza di una configurazione d'account, non visibile nei soli manifest.
- **Moduli dinamici:** PUT/PATCH/DELETE sono esclusi sui bersagli esterni (nessun rollback dello
  stato); le categorie che si manifestano solo con questi metodi non vengono sollecitate.

## 8. Registro delle deviazioni

| Data | Bersaglio | Deviazione | Effetto sui risultati |
|---|---|---|---|
| 2026-10-01 | tutti | Esecuzione senza congelamento: nessun commit né tag `v-validazione`; lo strumento aveva modifiche non committate (elencate in `versioni.txt` dell'archiviazione). | I risultati valgono come prova preliminare, non come validazione congelata; da ripetere dopo il tag. |
| 2026-10-01 | dvapi | Avvio con override di docker compose (`config/targets/dvapi.compose.override.yml`) che rinomina i soli container in `dvapi-nodejs` e `dvapi-mongodb`: il nome `mongodb` era occupato dal container di crAPI. Bersaglio non modificato. | Nessuno: servizi e rete invariati. |
| 2026-10-01 | tutti | L'agente di sviluppo ha letto `external/PROVENIENZA.md` e `external/dvapi/docker-compose.yml` e, su richiesta dell'autore, ha eseguito le scansioni e letto i risultati. | Separazione fra sviluppo e risultati non garantita per questa esecuzione. |
| | | | |
