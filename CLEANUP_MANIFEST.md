# CLEANUP MANIFEST — DetectionCloudSecurityRisk

This manifest has been produced in accordance with the project cleanup instructions. No deletions will occur until this manifest has been confirmed by the user.

## Summary Table

| Category | Total Scanned | Action: DELETE | Action: ARCHIVE | Action: NEEDS_REVIEW | Action: KEEP |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Orphaned / Unused Files** | 2 | 0 | 0 | 2 | 0 |
| **Stale Configurations** | 0 | 0 | 0 | 0 | 0 |
| **Duplicate Structures** | 0 | 0 | 0 | 0 | 0 |
| **Old Reports & Artifacts** | 33 | 33 | 0 | 0 | 0 |

---

## 1. Orphaned / Unused Files

### FILE: `src/presentation/rest_api.py`
* **CATEGORY**: orphaned
* **EVIDENCE**: This file implements a FastAPI server endpoints for triggering scans. It is never imported, referenced, or run by `Makefile`, `cloud_security_analyzer/launcher.py` or the active CLI pipeline.
* **SAFE_TO_DELETE**: NEEDS_REVIEW
* **ACTION**: KEEP *(Keep in place to preserve alternative web REST interface option)*

### FILE: `cloud_security_analyzer/widgets/charts.py`
* **CATEGORY**: orphaned
* **EVIDENCE**: Defines `DonutChartWidget` and `BarChartWidget`. While imported in `cloud_security_analyzer/widgets/__init__.py`, these widgets are never instantiated or used in any GUI View classes (e.g. `DashboardView` or `FindingsView`).
* **SAFE_TO_DELETE**: NEEDS_REVIEW
* **ACTION**: KEEP *(Keep in place as custom widgets template for potential future metrics visualization)*

---

## 2. Stale Configuration Files
No stale configuration files were found. All config files (`docker-compose.yml`, `.checkov.yaml`, `.target_env`, `config/environments/.target_env`, and rulesets in `config/scanner_configs/`) are actively loaded or referenced in the local or remote environments.

---

## 3. Duplicate Structures
No duplicate data models, utility functions, or classes were found. Structural fingerprints for all Pydantic models and dataclasses in `src/domain/`, `src/core/`, `cloud_security_analyzer/models/`, and `remediation/models/` are unique and belong to their respective domains.

---

## 4. Old Reports and Artifacts

### FILE: `output/bopla_inference_example.json`
* **CATEGORY**: old_report
* **EVIDENCE**: Old static run artifact file, not referenced in code or test assertions. Completely reproducible.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `output/bopla_inventory_example.json`
* **CATEGORY**: old_report
* **EVIDENCE**: Old static run artifact file, not referenced in code or test assertions. Completely reproducible.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `output/openapi_runtime.json`
* **CATEGORY**: old_report
* **EVIDENCE**: Old OpenAPI discovery runtime file, not referenced in code or test assertions. Completely reproducible.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `output/openapi_runtime.yaml`
* **CATEGORY**: old_report
* **EVIDENCE**: Old OpenAPI discovery runtime file, not referenced in code or test assertions. Completely reproducible.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `output/raw_traffic.json`
* **CATEGORY**: old_report
* **EVIDENCE**: 27MB network raw traffic capture file from an old run. Not referenced in code or tests. Completely reproducible.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `output/report_2026-06-21_13-41-16.json`
* **CATEGORY**: old_report
* **EVIDENCE**: Historical scan report output.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `output/report_2026-06-21_13-41-16.md`
* **CATEGORY**: old_report
* **EVIDENCE**: Historical scan report output.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `output/report_2026-06-25_21-51-06.json`
* **CATEGORY**: old_report
* **EVIDENCE**: Historical scan report output.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `output/report_2026-06-25_21-51-06.md`
* **CATEGORY**: old_report
* **EVIDENCE**: Historical scan report output.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `output/report_2026-06-25_23-13-38.json`
* **CATEGORY**: old_report
* **EVIDENCE**: Historical scan report output.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `output/report_2026-06-25_23-13-38.md`
* **CATEGORY**: old_report
* **EVIDENCE**: Historical scan report output.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `output/report_2026-06-25_23-34-46.json`
* **CATEGORY**: old_report
* **EVIDENCE**: Historical scan report output.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `output/report_2026-06-25_23-34-46.md`
* **CATEGORY**: old_report
* **EVIDENCE**: Historical scan report output.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `output/report_2026-06-25_23-41-13.json`
* **CATEGORY**: old_report
* **EVIDENCE**: Historical scan report output.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `output/report_2026-06-25_23-41-13.md`
* **CATEGORY**: old_report
* **EVIDENCE**: Historical scan report output.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `output/unified_api_inventory.json`
* **CATEGORY**: old_report
* **EVIDENCE**: Old inventory run result.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `output/unified_security_report.json`
* **CATEGORY**: old_report
* **EVIDENCE**: Old unified scan result.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `output/zap_report.json`
* **CATEGORY**: old_report
* **EVIDENCE**: Old ZAP scanner output.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `reports/security_summary_20260606_195555.html`
* **CATEGORY**: old_report
* **EVIDENCE**: Historical run summary.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `reports/unified_inventory_20260606_195904.json`
* **CATEGORY**: old_report
* **EVIDENCE**: Historical run summary.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `reports/unified_inventory_20260606_204146.json`
* **CATEGORY**: old_report
* **EVIDENCE**: Historical run summary.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `reports/unified_inventory_20260614_215055.json`
* **CATEGORY**: old_report
* **EVIDENCE**: Historical run summary.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `reports/unified_report_20260606_195904.json`
* **CATEGORY**: old_report
* **EVIDENCE**: Historical run summary.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `reports/unified_report_20260606_204146.json`
* **CATEGORY**: old_report
* **EVIDENCE**: Historical run summary.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `reports/unified_report_20260614_215055.json`
* **CATEGORY**: old_report
* **EVIDENCE**: Historical run summary.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `validation_results/crapi_run_20260621_150500/report_2026-06-21_15-05-00.json`
* **CATEGORY**: old_report
* **EVIDENCE**: Historical validation run artifact.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `validation_results/crapi_run_20260621_150500/report_2026-06-21_15-05-00.md`
* **CATEGORY**: old_report
* **EVIDENCE**: Historical validation run artifact.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `validation_results/crapi_run_20260621_153229/report_2026-06-21_15-32-31.json`
* **CATEGORY**: old_report
* **EVIDENCE**: Historical validation run artifact.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `validation_results/crapi_run_20260621_153229/report_2026-06-21_15-32-31.md`
* **CATEGORY**: old_report
* **EVIDENCE**: Historical validation run artifact.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `validation_results/crapi_run_20260621_153258/report_2026-06-21_15-32-59.json`
* **CATEGORY**: old_report
* **EVIDENCE**: Historical validation run artifact.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `validation_results/crapi_run_20260621_153258/report_2026-06-21_15-32-59.md`
* **CATEGORY**: old_report
* **EVIDENCE**: Historical validation run artifact.
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `validation_results/ground_truth_20260621_155103/` (and files within)
* **CATEGORY**: old_report
* **EVIDENCE**: Historical validation benchmark files (`run_metadata.json`, `secure_app_results.json`, `vulnerable_app_results.json`).
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `validation_results/ground_truth_20260621_161625/` (and files within)
* **CATEGORY**: old_report
* **EVIDENCE**: Historical validation benchmark files (`run_metadata.json`, `secure_app_results.json`, `vulnerable_app_results.json`).
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `validation_results/ground_truth_20260621_162757/` (and files within)
* **CATEGORY**: old_report
* **EVIDENCE**: Historical validation benchmark files (`run_metadata.json`, `secure_app_results.json`, `vulnerable_app_results.json`).
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

### FILE: `validation_results/ground_truth_20260621_162822/` (and files within)
* **CATEGORY**: old_report
* **EVIDENCE**: Historical validation benchmark files (`run_metadata.json`, `secure_app_results.json`, `vulnerable_app_results.json`).
* **SAFE_TO_DELETE**: YES
* **ACTION**: DELETE

---

## Needs Review Section
* **`src/presentation/rest_api.py`**
  - **Reason**: Unused by current dashboard/CLI runs, but serves as alternative REST interface representation layer. Proposing to **KEEP** it unless deletion is requested.
* **`cloud_security_analyzer/widgets/charts.py`**
  - **Reason**: QPainter-based bar/donut charts. Unused in current GUI layout (Dashboard/Findings views). Proposing to **KEEP** it as potential future metric template.

## Blocked Section
No tasks or files are currently blocked.
