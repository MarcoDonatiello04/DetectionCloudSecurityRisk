# OWASP API5 Coverage

This document tracks the implementation status and ground truth verification metrics for rules addressing **API5:2023 Broken Function Level Authorization**.

| Rule ID | CWE | Categoria | Implementato | Fixture TP verificato | Fixture TN verificato | Effective Coverage |
|---------|-----|-----------|:---:|:---:|:---:|:---:|
| BF-001 | CWE-285 | privileged_endpoint_no_role_check | YES | YES | YES | YES |
| BF-002 | CWE-862 | auth_without_authz | YES | YES | YES | YES |
| BF-003 | CWE-650 | http_method_override | YES | YES | YES | YES |
| BF-004 | CWE-284 | admin_path_exposure | YES | YES | YES | YES |
| BF-005 | CWE-276 | missing_deny_by_default | YES | YES | YES | YES |
| BF-006 | CWE-285 | shadow_admin_function | YES | YES | YES | YES |

## Registro di Validazione

| Data | Target | TPR | FPR | Stato |
|------|--------|-----|-----|-------|
| 2026-06-26 | vulnerable_app & secure_app | 100.0% | 0.0% | Superato ✅ |



