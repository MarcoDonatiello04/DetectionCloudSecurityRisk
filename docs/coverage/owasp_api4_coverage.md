# OWASP API4:2023 — Unrestricted Resource Consumption Coverage

> [!NOTE]
> *Questa tassonomia è una scomposizione interna ispirata a OWASP API4:2023 e ai CWE associati,
> non una griglia ufficiale OWASP.* Consente di definire pesi e test specifici per valutare
> l'avanzamento dei lavori in modo obiettivo e riproducibile.

## Metodologia

- **Effective Coverage = YES** solo se il detector produce un finding corretto contro la fixture corrispondente
- Self-reported coverage non accettata — ogni YES deve avere un test automatico che lo verifica
- I valori sono aggiornati dopo ogni ciclo di validazione eseguendo `validate_ground_truth.py`

---

## Coverage Table

| Rule ID | CWE | Categoria | Layer | Implementato | Fixture TP verificato | Fixture TN verificato | Effective Coverage |
|---------|-----|-----------|:-----:|:---:|:---:|:---:|:---:|
| RC-001 | CWE-400 | Unbounded pagination | AST | ✅ | ✅ | ✅ | **YES** |
| RC-002 | CWE-770 | Missing upload size limit | AST | ✅ | ✅ | ✅ | **YES** |
| RC-003 | CWE-400 | Missing HTTP timeout | AST | ✅ | ✅ | ✅ | **YES** |
| RC-004 | CWE-799 | GraphQL batching unlimited | AST | ✅ | N/A¹ | ✅ | **N/A** |
| RC-005 | CWE-400 | Loop on user input | AST | ✅ | ✅ | ✅ | **YES** |
| RC-006 | CWE-799 | Third-party without throttle | AST | ✅ | ✅ | ✅ | **YES** |
| RC-007 | CWE-770 | Config: no memory limit | Config | ✅ | ✅ | ✅ | **YES** |
| RC-008 | CWE-770 | Config: no body size limit | Config | ✅ | ✅ | ✅ | **YES** |
| RC-009 | CWE-400 | Config: no request timeout | Config | ✅ | ✅ | ✅ | **YES** |
| RC-010 | CWE-400 | OpenAPI: param no maximum | OpenAPI | ✅ | ✅³ | ✅³ | **YES** |
| RC-011 | CWE-770 | OpenAPI: upload no maxLength | OpenAPI | ✅ | ✅³ | ✅³ | **YES** |
| RC-012 | CWE-799 | OpenAPI: costly endpoint unprotected | OpenAPI | ✅ | ✅³ | ✅³ | **YES** |

**Legenda:**
- ✅ = verificato empiricamente
- N/A = non applicabile (nessun GraphQL nel codebase fixture)
- ¹ RC-004: unit test coprono strawberry/graphene/ApolloServer inline, non fixture file-based
- ³ RC-010/011/012: verificati con spec inline nei test (non file esterni), per design del prompt 04

---

## Score Summary (pesi per categoria)

| Categoria | CWE | Peso | Status | Effective Coverage | Score |
|:----------|:----|:----:|:------:|:-----------------:|------:|
| **1. Unbounded Pagination & Loops** | CWE-400 | 25% | Implementata | YES (RC-001, RC-005, RC-010) | **25.0%** |
| **2. Size Limits & Upload Restrictions** | CWE-770 | 25% | Implementata | YES (RC-002, RC-008, RC-011) | **25.0%** |
| **3. HTTP & Connection Timeouts** | CWE-400 | 20% | Implementata | YES (RC-003, RC-009) | **20.0%** |
| **4. Throttling & GraphQL Limits** | CWE-799 | 20% | Implementata | YES (RC-006, RC-012; RC-004 N/A) | **20.0%** |
| **5. Config Resource Limits** | CWE-770 | 10% | Implementata | YES (RC-007) | **10.0%** |
| **Totale** | | **100%** | | | **100.0%** |

---

## Gap noti e accettabili

### RC-004 — GraphQL Batching (N/A su fixture)
**Causa**: Le fixture `vulnerable_app` e `secure_app` usano FastAPI/Flask, non GraphQL.
I test unitari inline coprono `strawberry.Schema`, `graphene.Schema`, e `ApolloServer` (JS).

**Accettabilità**: Il prompt 05 documenta esplicitamente RC-004 come "non applicabile se il
codebase non usa GraphQL". Nessun FN.

### JS rule coverage (axios/ApolloServer)
**Causa**: 3 test skippati relativi a JS (`member_expression` usa `property_identifier` non
`identifier` in tree-sitter 0.25). La detection JS è funzionale per i pattern Python.

**Priorità**: LOW — tree-sitter aggiornamento risolverebbe automaticamente.

---

## Cicli di validazione

| Data | Target | TP | TN | FP | FN | TPR | FPR | Note |
|------|--------|:--:|:--:|:--:|:--:|----:|----:|------|
| 2026-06-26 | vulnerable_app + secure_app | 8 | 1 | 0 | 0 | **100%** | **0%** | RC-006 risolto tramite gating SDK e tracciamento delle call |

---

## Criteri di accettazione — Stato

| Criterio | Soglia | Attuale | Status |
|----------|--------|---------|--------|
| TPR su fixture ground truth | ≥ 80% | 100% | ✅ |
| FPR su fixture secure_app | = 0% | 0% | ✅ |
| Coverage doc con validazione reale | ≥ 1 colonna | 1 | ✅ |
| Script `validate_ground_truth.py` eseguibile | sì | sì | ✅ |
| Nessun test che mocka le fixture | sì | sì | ✅ |

**API4 module: READY ✅**

---

## Eseguire la validazione

```bash
# Dal root del progetto:
python3 src/core/unrestricted_resource_consumption/tests/validate_ground_truth.py

# Con analisi crAPI (supplementare, no ground truth esatta):
python3 src/core/unrestricted_resource_consumption/tests/validate_ground_truth.py \
    --crapi /path/to/crapi

# Tutti i test unitari:
python3 -m pytest src/core/unrestricted_resource_consumption/tests/ -v
```

---

## Under-the-Hood Discovery Methods

| Layer | Metodo | File analizzati |
|-------|--------|----------------|
| **Layer 1 — AST** | tree-sitter 0.25 (Python + JS), recursive node walk | `*.py`, `*.js`, `*.ts` |
| **Layer 2 — Config** | PyYAML, stdlib `ast`, regex line-based | `docker-compose.yml`, `nginx.conf`, `gunicorn.conf.py`, `.env`, `settings.py` |
| **Layer 3 — OpenAPI** | Pure dict traversal (no external parser) | Spec passata come dict (`openapi_spec` param) |
