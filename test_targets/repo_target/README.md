# Repo Target — target cooperante per i test BOLA

Questo target dimostra come rendere **una repository qualsiasi** attaccabile
dall'orchestratore BOLA del framework (`src/core/object_level_authorization`),
esattamente come avviene per `test_targets/bola`. È il riferimento pratico per
il limite di *repository-independence* descritto nel README principale: BOLA è
un'analisi **dinamica** e non può ispezionare un'app sconosciuta — la repo deve
*collaborare*.

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
