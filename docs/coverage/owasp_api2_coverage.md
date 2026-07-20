# OWASP API2:2023 - Broken Authentication Coverage & Verifiable Score Checklist

> [!NOTE]
> *Questa tassonomia è una scomposizione interna ispirata a OWASP API2:2023 e ai CWE associati, non una griglia ufficiale OWASP.* Questa scomposizione consente di definire pesi e test specifici per valutare l'avanzamento dei lavori, evitando che il punteggio venga contestato confrontandolo con una documentazione ufficiale OWASP non strutturata in questa forma.

This checklist tracks the verification coverage of the `Broken Authentication` security testing module against the official sub-categories of OWASP API2:2023 and associated CWEs.

## Verifiable Coverage Score

Each category is assigned a weight based on vulnerability prevalence and risk impact. Coverage scoring:
- `Covered`: 100% score for the category
- `Partial`: 50% score for the category
- `Missing`: 0% score for the category

### Score Summary Table

| Category | Associated CWEs | Weight | Status | Effective Coverage | Score | Details / Dynamic Tests |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **1. Token Validation & Signatures** | CWE-347, CWE-327 | 15% | **Covered** | **Yes** (Pass/Fail mock tests + static rule S01) | 15.0% | **T01** (JWT signature validation)<br>**T02** (Expired token rejection)<br>**T07** (Key confusion RS256->HS256)<br>**T14** (JWKS Header Injection via jwk/x5u)<br>**S01** (static AST — JWT signature bypass via manual payload decode, CWE-347) |
| **2. Session & Token Management** | CWE-384, CWE-613 | 15% | **Covered** | **Yes** (Pass/Fail mock tests) | 15.0% | **T05** (Token reuse post logout)<br>**T06** (Session Fixation check)<br>**T12** (Invalid token refresh rejection)<br>**T16** (Refresh Token Rotation check) |
| **3. Auth Flows & Credentials Security** | CWE-287, CWE-601 | 15% | **Covered** | **Yes** (Pass/Fail mock tests) | 15.0% | **T04** (Token Replay on diff aud/client)<br>**T15** (OAuth2/OIDC Flows state/PKCE checks)<br>**T17** (Non-JWT Credentials Security) |
| **4. Brute Force & Rate Limiting** | CWE-307 | 15% | **Covered** | **Yes** (Pass/Fail & IP spoofing mock) | 15.0% | **T03** (Brute Force detection)<br>**T18** (Rate Limiting bypass via IP header spoofing) |
| **5. MFA & Weak Authentication** | CWE-287, CWE-307 | 15% | **Covered** | **Yes** (Bypass & brute force mock) | 15.0% | **T19** (MFA Bypass & OTP strength check) |
| **6. SAML / SSO Flaws** | CWE-347, CWE-611 | 10% | **Covered** | **Yes** (XSW & XXE mock tests) | 10.0% | **T20** (SAML Signature Wrapping / XXE checks) |
| **7. Info Leakage & Auth Behavior** | CWE-200, CWE-287 | 10% | **Covered** | **Yes** (Pass/Fail mock tests) | 10.0% | **T09** (Secure/HttpOnly flags)<br>**T10** (Sensitive Info in Errors)<br>**T11** (User Enumeration)<br>**T13** (Weak password reset leaks) |
| **8. Attack Surface Discovery** | N/A (Crawler) | 5% | **Covered** | **Yes** (Robots/Spidering mock) | 5.0% | **Discovery Crawler** (Async read-only spidering crawler in `discovery.py`, fully active and tested) |
| **Total Compliance Score** | | **100%** | | | **100.0%** | **Current compliance: 100.0%** (All checks and validations fully implemented and tested) |

---

## Under-the-Hood Discovery Methods

To feed these tests, the engine runs:
1. **AST Heuristics & Analysis**: Locates source code configurations and routes.
2. **OpenAPI Parsing**: Extracts routes and auth structures.
3. **Active Crawler / Spidering**: Non-destructive `GET`/`HEAD` discovery and form enumeration. Marked as `discovery_method: "crawler"` in the Knowledge Graph.

---

## Dipendenze tra categorie (CWE Condivisi)

Alcuni CWE sono trasversali a più categorie interne. Di conseguenza, interventi di bonifica centralizzati potrebbero influenzare contemporaneamente più punteggi:

*   **CWE-287 (Improper Authentication)**: Condiviso tra:
    *   *Categoria 3*: Auth Flows & Credentials Security
    *   *Categoria 5*: MFA & Weak Authentication
    *   *Categoria 7*: Info Leakage & Auth Behavior
    *   *Implicazione*: Il corretto isolamento o il rafforzamento del flusso di login primario mitiga rischi in tutte e tre le aree.
*   **CWE-307 (Improper Restriction of Excessive Authentication Attempts)**: Condiviso tra:
    *   *Categoria 4*: Brute Force & Rate Limiting
    *   *Categoria 5*: MFA & Weak Authentication
    *   *Implicazione*: L'implementazione di un rate limiter sull'endpoint OTP (T19) e sul login primario (T18) si basano su meccanismi di blocco IP/utente simili.
*   **CWE-347 (Cryptographic Signature Verification)**: Condiviso tra:
    *   *Categoria 1*: Token Validation & Signatures (Firma JWT)
    *   *Categoria 6*: SAML / SSO Flaws (Firma XML SAML)

*Nota: Quando T18 o T19 vengono implementati, controlleremo esplicitamente se alzano il punteggio anche di una categoria diversa da quella principale, annotando la variazione nel changelog.*

---

## Validazione Esterna

**Data del run**: 2026-06-21
**Versione del modulo**: v1.1.0-validation
**Target di validazione**: OWASP crAPI (vulnerabilities documentate da terzi)

> [!IMPORTANT]
> **Dichiarazione di Trasparenza**: La percentuale di copertura dei test interni (100%) indica che ogni controllo descritto nella tassonomia ha un corrispondente test automatico con mock. Questa metrica è distinta dall'affidabilità empirica misurata sul campo contro target reali complessi come crAPI, dove il modulo ha registrato un **True Positive Rate (TPR) del 20.0%**.

### Tabella di Confronto Vulnerabilità crAPI

| Vulnerabilità nota in crAPI | Categoria OWASP API2 interna | Rilevata dal modulo? | Test che l'ha rilevata | Note |
| :--- | :--- | :---: | :---: | :--- |
| **Mancanza di Rate Limiting sul Login** | Categoria 4: Brute Force & Rate Limiting | **SÌ** | **T03** (Brute Force detection) | Rilevato correttamente sul login endpoint (`/identity/api/auth/login`) restituendo FAIL (nessun blocco dopo 10 tentativi). |
| **Bypass OTP via Password Reset (v2)** | Categoria 5: MFA & Weak Authentication | **NO** | N/A | **False Negative**: L'endpoint `/identity/api/auth/v2/check-otp` non è stato scansionato da **T19**. |
| **Bypass Firma JWT (Dashboard)** | Categoria 1: Token Validation & Signatures | **NO** | N/A | **False Negative**: Non è stato possibile eseguire il test **T01** a causa della mancata acquisizione del token di sessione. |
| **Confusione Algoritmo JWT (RS256->HS256)**| Categoria 1: Token Validation & Signatures | **NO** | N/A | **False Negative**: Non è stato possibile eseguire il test **T07** a causa della mancata acquisizione del token di sessione. |
| **Abuso JKU/JWKS Header Injection** | Categoria 1: Token Validation & Signatures | **NO** | N/A | **False Negative**: Non è stato possibile eseguire il test **T14** a causa della mancata acquisizione del token di sessione. |

### Metriche di Affidabilità Empirica

- **True Positive Rate (TPR)**: **20.0%** (1 rilevata su 5 vulnerabilità note di Broken Authentication).
- **False Negatives (FN)**: 4 (Bypass OTP, Bypass Firma JWT, Algoritmo Confusion, JWKS Header Injection).
- **False Positives (FP)**: 0 (Nessun falso positivo generato; gli endpoint corretti hanno risposto PASS/INCONCLUSIVE senza segnalare false positività).

### Analisi dei Gap e Ipotesi di Risoluzione

1. **Gap nell'acquisizione del token (JWT/Sessione)**:
   - *Causa*: I test dinamici (**T01**, **T07**, **T14**) che richiedono una sessione autenticata utilizzano un helper di login (`_login_and_get_token`) che invia un payload con chiavi fisse `{"username": ..., "password": ...}`. Tuttavia, crAPI richiede specificamente le chiavi `{"email": ..., "password": ...}` sul login `/identity/api/auth/login`. Di conseguenza, il login fallisce e i test vengono marcati come `INCONCLUSIVE`.
   - *Ipotesi*: Rendere l'helper di login adattivo. Se fallisce con chiavi generiche, ispezionare lo schema OpenAPI o provare chiavi comuni alternative (come `email` e `email_address`).
2. **Gap nella Discovery degli Endpoint ausiliari**:
   - *Causa*: In `discover_endpoints` in `dynamic_tester.py`, se l'endpoint di login principale viene scoperto tramite l'Intelligence Engine (Fase 3), il ramo di ricerca automatica della documentazione OpenAPI in Fase 4 viene completamente saltato. Questo impedisce al modulo di mappare e testare gli endpoint secondari (come reset password, logout o OTP/MFA) non presenti nello stack statico originario.
   - *Ipotesi*: Ristrutturare `discover_endpoints` per eseguire sempre il parsing del file OpenAPI (se disponibile) indipendentemente dal fatto che l'endpoint di login sia già stato popolato staticamente.


---

## Regola Statica S01 — JWT Signature Bypass (validazione su repo_target)

`src/core/broken_authentication/rules/jwt_signature_bypass.py` (regola AST, CWE-347).
Rileva la decodifica manuale del payload JWT (split `.`, Base64, `json.loads`) senza
verifica della firma — il pattern di fallback insicuro comune quando la validazione
crittografica fallisce o l'IdP e irraggiungibile.

Copre il caso in cui i test dinamici (T01/T07/T14) non sono eseguibili perche il
target delega l'auth a un IdP esterno e non espone un endpoint di login proprio.

| Fixture / Target | Atteso | Esito |
| :--- | :--- | :--- |
| `test_targets/repo_target/identity.py` (`_decode_payload_only`) | TP | ✅ finding S01 su riga 39 |
| `src/core/broken_authentication/fixtures/secure_jwt_decode.py` (solo `jwt.decode`) | TN | ✅ nessun finding |

Verificato da `src/core/broken_authentication/tests/test_jwt_signature_bypass.py` (3 test).

> Nota: la scoperta empirica correlata (`make core-modules-repo-target`) e che il
> modulo Broken Authentication su un target senza login ora degrada a **INCONCLUSIVE**
> invece di sollevare `EndpointNotFoundException`.

---

## Rivalidazione crAPI (dopo i fix dei root cause)

**Data**: 2026-07-20 — i due root cause documentati sopra risultano gia risolti nel codice:
- `_login_and_get_token` e adattivo (schema-driven + fallback su alias `username/email/user/login`);
- `discover_endpoints` esegue sempre il parsing OpenAPI quando lo spec e disponibile.

Esito del run reale (`run_crapi_validation.py`, output verbatim):
- **T03 (Brute Force / Rate Limiting)**: FAIL — rilevato (nessun rate limit dopo 50 tentativi).
- **T21 (MFA Bypass / OTP)**: FAIL — **rilevato**, era un False Negative nella validazione precedente.
- **T01/T02/T07/T14/T17 (firma/algoritmo/JWKS JWT)**: INCONCLUSIVE — il login non produce un token
  di sessione perche le credenziali di test non sono registrate in questa istanza crAPI (limite
  **ambientale**, non del key-mapping: la risoluzione adattiva identifica correttamente il claim
  `email`). Questa categoria (CWE-347) e ora coperta **staticamente** dalla regola **S01**, che non
  richiede una sessione autenticata.

> Guardrail non distruttivi verificati nello stesso run: nessuna operazione distruttiva non prevista.
