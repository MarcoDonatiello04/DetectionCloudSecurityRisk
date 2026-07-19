# Repo Target — repository cooperante per i controlli del framework

Questo target dimostra come rendere **una repository qualsiasi** analizzabile dal
framework, raccogliendo al suo interno tutto ciò che serve al sistema per
eseguire i propri controlli su di essa. È il riferimento pratico per il limite di
*repository-independence* descritto nel README principale.

I controlli si costruiscono in modo incrementale. Attualmente la repo copre:

- **BOLA (dinamico)** — l'app cooperante e il contratto di identità/stato
  (sezioni sotto);
- **IaC / Checkov (statico)** — la configurazione Terraform in
  [`terraform/`](terraform/), analizzata dallo scanner Checkov del framework;
- **Discovery API / Semgrep (statico)** — il codice sorgente della repo, da cui
  Semgrep estrae l'inventario degli endpoint.

## IaC: configurazione Terraform analizzata da Checkov

La cartella [`terraform/`](terraform/) contiene la configurazione infrastrutturale
(`main.tf`, `vulnerable_infra.tf`) che prima risiedeva nella repo principale ed è
ora ospitata qui, dentro la repo target. Checkov, configurato via `.checkov.yaml`
nella radice del progetto, la scansiona insieme al resto del repository: il
risultato in dashboard è invariato (stesse misconfiguration IaC rilevate).

```bash
# Provisioning + analisi IaC (Terraform su LocalStack, poi Checkov)
make iac-analysis
```

## Discovery API: endpoint estratti da Semgrep

A differenza di Checkov e Terraform, per Semgrep non c'è configurazione da
spostare: lo scanner analizza il **codice sorgente**, e la repo lo contiene già
(`app.py`, `cooperative_harness.py`). Semgrep, scansionando la root del
progetto, ne ricava le rotte insieme al resto del repository. Un runner dedicato
permette di isolarne l'inventario:

```bash
make semgrep-repo-target
```

Le rotte scoperte (`/api/projects/{id}`, `/api/invoices/{id}`, `/test/*`)
combaciano con [`openapi.yaml`](openapi.yaml): è questa corrispondenza che
consente al motore di correlazione di unire la scoperta statica (Semgrep) con
gli attacchi dinamici (BOLA) sullo stesso endpoint.

`run_iac_analysis.sh` esegue `terraform apply` da `test_targets/repo_target/terraform`
e vi punta Checkov (`--framework terraform`). Il modello referenzia la Lambda di
esempio in `fixtures/api_vulnerabilities/generic_vulnerabilities` tramite percorso
relativo, che resta valido dalla nuova posizione.

## BOLA: il contratto cooperante (3 requisiti)

Una repo diventa testabile da BOLA — analisi **dinamica** che non può ispezionare
un'app sconosciuta — quando espone questi tre elementi.

## Il contratto cooperante (3 requisiti)

Una repo diventa testabile da BOLA quando espone questi tre elementi.

1. **Endpoint di controllo dello stato** — riforniti da
   [`cooperative_harness.py`](cooperative_harness.py):

   | Metodo | Rotta | Scopo |
   | --- | --- | --- |
   | `POST` | `/test/seed` | Popola lo stato con `{risorsa: {id: owner}}` |
   | `GET`/`POST` | `/test/snapshot` | Fotografa lo stato pulito prima di uno scenario |
   | `POST` | `/test/rollback` | Ripristina lo stato dopo ogni scenario |

   Il payload di seeding è quello prodotto da
   `IdentityManager.seed_target_application`:
   ```json
   { "projects": { "<uuid_utente>": "<owner_username>" } }
   ```

2. **Fiducia nell'identity provider condiviso** — [`identity.py`](identity.py)
   valida i JWT del realm Keycloak `myrealm` (RS256), con fallback sul solo
   payload per i token sintetici delle simulazioni. Gli utenti
   `user_a` / `user_b` / `admin_user` sono creati una sola volta da
   `make setup-env` e condivisi da tutti i target.

3. **Un modello risorsa → proprietario** — lo stato mappa
   `risorsa[id] = owner`, così che "accesso non autorizzato" abbia significato.
   [`app.py`](app.py) espone di proposito due casi:
   - `GET|PUT|DELETE /api/projects/{id}` — **vulnerabile** (nessun controllo di
     ownership): la scansione lo marca come BOLA.
   - `GET /api/invoices/{id}` — **protetto** (owner == richiedente, admin
     ammesso): la scansione lo marca come SAFE.

## Esecuzione

```bash
# 1. Ambiente condiviso (Keycloak + utenti), una tantum
make setup-env

# 2. Avvia il target (in Docker o localmente)
pip install -r test_targets/repo_target/requirements.txt
python test_targets/repo_target/app.py          # ascolta su :5000

# 3. Punta BOLA al target cooperante
PYTHONPATH=. .venv/bin/python entrypoints/runners/run_bola_repo_target.py \
    --target-url http://localhost:5000 \
    --openapi test_targets/repo_target/openapi.yaml
```

Gli endpoint attaccati sono ricavati da [`openapi.yaml`](openapi.yaml), non dal
codice del framework: è questo che rende il runner indipendente dalla singola
repository. Per adattare il target a una repo reale si sostituisce la logica di
business in `app.py` e la specifica in `openapi.yaml`, mantenendo invariati
`cooperative_harness.py` e il contratto dei tre endpoint.

> Nota sulla durata: come tutte le scansioni BOLA, l'esecuzione completa con
> snapshot/rollback per scenario supera i 30 minuti e richiede Keycloak e OWASP
> ZAP attivi.
