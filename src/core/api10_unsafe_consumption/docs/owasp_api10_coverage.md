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
python3 src/core/unsafe_consumption/tests/validate_ground_truth.py
```

---

## Aggiornamento validazione (2026-07-20)

Rettifica: il modulo **passa** la ground truth, contrariamente a quanto indicato sopra.
`validate_ground_truth.py` (output verbatim):

| Metrica | Valore |
| :--- | :--- |
| TP | 3 (UC-001, UC-002, UC-003 su `fixtures/vulnerable_app`) |
| TN | 1 (`fixtures/secure_app` pulito) |
| TPR / FPR | 100% / 0% |

**repo_target**: 0 finding. Documentato come **N/A** — `app.py` consuma dati esterni solo
tramite l'endpoint `/import` con URL *variabile* controllato dall'utente; il detector UC-001
identifica le API esterne tramite URL *costante*, quindi la superficie non e applicabile qui
(lo stesso codice e coperto da **SS-001** del modulo SSRF).
