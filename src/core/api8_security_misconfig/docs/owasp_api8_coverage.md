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
| **SC-001** | CWE-942 | cors_wildcard | ✅ | ✅ | ✅ | **YES** |
| **SC-002** | CWE-94 | debug_mode_enabled | ✅ | ✅ | ✅ | **YES** |
| **SC-003** | CWE-209 | verbose_error_handler | ✅ | ✅ | ✅ | **YES** |
| **SC-004** | CWE-693 | missing_security_headers | ✅ | ✅ | ✅ | **YES** |
| **SC-005** | CWE-798 | hardcoded_secret | ✅ | ✅ | ✅ | **YES** |
| **SC-006** | CWE-942 | missing_cors_policy | ✅ | ✅ | ✅ | **YES** |
| **SC-007** | CWE-1395 | vulnerable_dependency | ✅ | ✅ | ✅ | **YES** |
| **SC-008** | CWE-650 | unrestricted_http_methods | ✅ | ✅ | ✅ | **YES** |
| **SC-009** | CWE-525 | missing_cache_control | ✅ | ✅ | ✅ | **YES** |

---

## Registro di validazione

| Data | Fixtures testate | TPR | FPR | Note |
|------|-------------------|:---:|:---:|------|
| 2026-06-27 | vulnerable_app + secure_app + crAPI | 100.0% | 0.0% | Scaffold ed implementazione iniziale (SC-001 - SC-005) |
| 2026-06-28 | vulnerable_app + secure_app + crAPI | 100.0% | 0.0% | E2E validation complete. Fixed SC-004 global format e SC-005 placeholder exclusions. |
| 2026-09-24 | vulnerable_app + secure_app + unit test suites | 100.0% | 0.0% | Estensione regole OWASP API8: SC-006 (missing CORS), SC-007 (SCA dep), SC-008 (metodi HTTP), SC-009 (Cache-Control no-store). |

---

## Eseguire la validazione

```bash
# Dal root del progetto:
PYTHONPATH=. python3 tests/unit/api8_security_misconfig/validate_ground_truth.py
pytest tests/unit/api8_security_misconfig/test_rules/
```
