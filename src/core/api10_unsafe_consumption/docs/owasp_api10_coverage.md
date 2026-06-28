# OWASP API10:2023 — Unsafe Consumption of APIs Coverage

> [!NOTE]
> *Questa tassonomia è una scomposizione interna ispirata a OWASP API10:2023 e ai CWE associati,
> non una griglia ufficiale OWASP.* Consente di definire pesi e test specifici per valutare
> l'avanzamento dei lavori in modo obiettivo e riproducibile.

## Metodologia

- **Effective Coverage = YES** solo se il detector produce un finding corretto contro la fixture corrispondente
- Self-reported coverage non accettata — ogni YES deve avere un test automatico che lo verifica
- I valori sono aggiornati dopo ogni ciclo di validazione eseguendo `validate_ground_truth.py`

---

## Coverage Table

| Rule ID | CWE | Categoria | Implementato | Fixture TP | Fixture TN | Effective Coverage |
|---------|-----|-----------|:---:|:---:|:---:|:---:|
| UC-001 | CWE-20 | unvalidated_external_data | NO | NO | NO | **NO** |
| UC-002 | CWE-319 | http_instead_of_https | NO | NO | NO | **NO** |
| UC-003 | CWE-601 | blind_redirect_following | NO | NO | NO | **NO** |

---

## Registro di validazione

| Data | Fixtures testate | TPR | FPR | Note |
|------|-------------------|:---:|:---:|------|
| - | - | - | - | Non ancora validato |

---

## Eseguire la validazione

```bash
# Dal root del progetto:
python3 src/core/api10_unsafe_consumption/tests/validate_ground_truth.py
```
