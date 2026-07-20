# OWASP API7:2023 — Server-Side Request Forgery Coverage

> [!NOTE]
> *Questa tassonomia è una scomposizione interna ispirata a OWASP API7:2023 e ai CWE associati,
> non una griglia ufficiale OWASP.* Consente di definire pesi e test specifici per valutare
> l'avanzamento dei lavori in modo obiettivo e riproducibile.

## Metodologia

- **Effective Coverage = YES** solo se il detector produce un finding corretto contro la fixture corrispondente
- Self-reported coverage non accettata — ogni YES deve avere un test automatico che lo verifica
- I valori sono aggiornati dopo ogni ciclo di validazione eseguendo `validate_ground_truth.py`

---

## Coverage Table

| Rule ID | CWE | Categoria | Implementato | Fixture TP verificato | Fixture TN verificato | Effective Coverage |
|---------|-----|-----------|:---:|:---:|:---:|:---:|
| SS-001 | CWE-918 | direct_url_from_input (Python/requests) | ✅ | ✅ | ✅ | **YES** |
| SS-002 | CWE-918 | direct_url_from_input (Python/urllib) | ✅ | ✅ | ✅ | **YES** |
| SS-003 | CWE-918 | direct_url_from_input (JS/Express) | ✅ | ✅ | ✅ | **YES** |
| SS-004 | CWE-918 | redirect_following | ✅ | ✅ | ✅ | **YES** |
| SS-005 | CWE-918 | cloud_metadata_access | ✅ | ✅ | ✅ | **YES** |
| SS-006 | CWE-918 | unvalidated_url_parameter (OpenAPI) | ✅ | ✅ | ✅ | **YES** |

---

## Registro di validazione

| Data | Fixtures testate | TPR | FPR | Note |
|------|-------------------|:---:|:---:|------|
| 2026-06-27 | vulnerable_app + secure_app + crAPI | 100.0% | 0.0% | Verifica SS-005 completata con HTTP call reale |

---

## Eseguire la validazione

```bash
# Dal root del progetto:
python3 src/core/server_side_request_forgery/tests/validate_ground_truth.py
```

---

## Validazione su repo_target (2026-07-20)

Endpoint reale `POST /api/projects/{id}/import` (`test_targets/repo_target/app.py`):
URL da body utente passato a `requests.get` senza validazione, redirect seguiti.

| Regola | Atteso | Esito |
| :--- | :--- | :--- |
| **SS-001** (direct_url_from_input) | TP | ✅ finding su riga 117 |
| `POST /api/projects/{id}/import-safe` (allow-list + `allow_redirects=False`) | nessun FP | ✅ non segnalato |

**SS-005** (cloud_metadata_access): non applicabile qui — la regola rileva l'accesso hardcoded
all'IP metadata `169.254.169.254`, non un URL generico controllato dall'utente. Documentato come
limite di superficie, non come gap del modulo.
