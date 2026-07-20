# OWASP API8:2023 — Security Misconfiguration Coverage

> [!NOTE]
> *Questa tassonomia è una scomposizione interna ispirata a OWASP API8:2023 e ai CWE associati,
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
| SC-001 | CWE-942 | cors_wildcard | ✅ | ✅ | ✅ | **YES** |
| SC-002 | CWE-94 | debug_mode_enabled | ✅ | ✅ | ✅ | **YES** |
| SC-003 | CWE-209 | verbose_error_handler | ✅ | ✅ | ✅ | **YES** |
| SC-004 | CWE-693 | missing_security_headers | ✅ | ✅ | ✅ | **YES** |
| SC-005 | CWE-798 | hardcoded_secret | ✅ | ✅ | ✅ | **YES** |

---

## Registro di validazione

| Data | Fixtures testate | TPR | FPR | Note |
|------|-------------------|:---:|:---:|------|
| 2026-06-27 | vulnerable_app + secure_app + crAPI | 100.0% | 0.0% | Scaffold ed implementazione completa completati |
| 2026-06-28 | vulnerable_app + secure_app + crAPI | 100.0% | 0.0% | E2E validation complete. Fixed SC-004 global target findings format and SC-005 placeholder exclusions. |

---

## Eseguire la validazione

```bash
# Dal root del progetto:
python3 src/core/security_misconfiguration/tests/validate_ground_truth.py
```

---

## Validazione su repo_target (2026-07-20)

`test_targets/repo_target/app.py` (Flask minimale) analizzato dal detector:

| Regola | Atteso | Esito |
| :--- | :--- | :--- |
| **SC-004** (missing security headers) | TP | ✅ rilevato (nessun middleware header di sicurezza) |
| **SC-002** (debug_mode) | TN | ✅ silente (`debug=False`) |
| **SC-005** (hardcoded_secret) | TN | ✅ `KEYCLOAK_SERVER_URL/REALM` da env var non segnalati (config, non secret) |

**SC-001** (cors_wildcard): il target non configura CORS affatto; la regola cerca un wildcard
esplicito, quindi l'assenza di policy e fuori scope — limite noto documentato, non gap silenzioso.
