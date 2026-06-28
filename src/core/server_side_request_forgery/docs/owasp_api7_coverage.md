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
