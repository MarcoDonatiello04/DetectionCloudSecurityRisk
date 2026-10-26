import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from loguru import logger

from src.core.api2_broken_auth.discovery import Config
from src.core.api3_bopla.discovery import PropertyDiscoveryEngine
from src.core.api3_bopla.dynamic_tester import BOPLADynamicTester
from src.core.api3_bopla.models import (
    DynamicPropertyFinding,
    PropertyAuthorizationGraph,
    PropertyEvidence,
    PropertyInventory,
    StaticPropertyFinding,
)
from src.core.api3_bopla.property_inference import (
    PropertyAuthorizationInferenceEngine,
)
from src.core.api3_bopla.static_rules import correlate_with_dynamic, run_static_rules

STATUS_LABELS = {
    "unverified": "da verificare",
    "confirmed": "confermata dinamicamente",
    "not_confirmed": "non confermata",
}
KIND_LABELS = {
    "mass_assignment": "Mass assignment",
    "excessive_exposure": "Esposizione di proprietà protette",
    "readonly_writable": "Proprietà readOnly accettata in scrittura",
    "writeonly_readable": "Proprietà writeOnly restituita in lettura",
    "undocumented_property": "Proprietà protetta non documentata",
}


def to_dashboard_items(report: dict[str, Any]) -> list[dict[str, Any]]:
    """
    BOPLA results for the dashboard: dynamic tests that confirmed a vulnerability plus every
    static finding, labelled with its verification status. Without the dynamic phase (the
    integrated platform passes no identity matrix) the static findings are what the module
    has to show.
    """
    items: list[dict[str, Any]] = []
    for f in report.get("findings", []):
        if not f.get("verified"):
            continue
        items.append(
            {
                "title": f"{f['test_id']} — prova dinamica confermata",
                "test_id": f["test_id"],
                "severity": "HIGH",
                "endpoint": f"{f['method']} {f['endpoint']}",
                "property_name": f["property_name"],
                "category": "Confermata dinamicamente",
                "evidence": "\n".join(f.get("evidence") or []),
                "verified": True,
            }
        )
    for f in report.get("static_findings", []):
        items.append(
            {
                "title": f"{f['rule_id']} — {KIND_LABELS.get(f['kind'], f['kind'])}",
                "rule_id": f["rule_id"],
                "severity": f["severity"],
                "file_path": f["file_path"],
                "line_number": f["line"] or None,
                "endpoint": f.get("endpoint"),
                "property_name": ", ".join(f["properties_at_risk"]) or None,
                "category": "Statica — " + STATUS_LABELS.get(f["status"], f["status"]),
                "evidence": "\n".join(f["evidence"]),
                "verified": f["verified"],
            }
        )
    return items


class BOPLAOrchestrator:
    """
    BOPLAOrchestrator coordinates the end-to-end BOPLA assessment pipeline.
    It manages discovery, inference, dynamic testing, risk calculation, and reporting.
    It is resilient to partial inputs (graceful degradation).
    """

    def __init__(self, config: Config):
        self.config = config

    def run_assessment(
        self,
        repo_path: str,
        openapi_spec: dict[str, Any] | None = None,
        runtime_traffic: list[dict[str, Any]] | None = None,
        headers_matrix: dict[str, dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """
        Executes the complete BOPLA assessment.
        """
        logger.info("Avvio della pipeline unificata BOPLA (API3:2023)...")

        # --- Phase 1: Property Discovery ---
        inventory = None
        objects_count = 0
        properties_count = 0
        try:
            logger.info("Inizio Fase 1: Property Discovery...")
            inventory = PropertyDiscoveryEngine.discover_properties(
                repo_path=repo_path, openapi_spec=openapi_spec, runtime_traffic=runtime_traffic
            )
            objects_count = len(inventory.root)
            properties_count = sum(len(o.properties) for o in inventory.root.values())

            logger.info(
                f"Property Discovery completato: {objects_count} oggetti scoperti, {properties_count} proprietà lette."
            )
        except Exception as e:
            logger.error(
                f"Errore durante Property Discovery: {e}. Inizializzazione inventario vuoto."
            )
            inventory = PropertyInventory({})

        # --- Phase 2: Property Inference ---
        evidences: list[PropertyEvidence] = []
        graph = PropertyAuthorizationGraph()
        protected_count = 0
        try:
            logger.info("Inizio Fase 2: Property Authorization Inference...")
            if inventory.root:
                evidences = PropertyAuthorizationInferenceEngine.run_inference(
                    repo_path=repo_path,
                    inventory=inventory,
                    openapi_spec=openapi_spec,
                    runtime_traffic=runtime_traffic,
                )
                graph = PropertyAuthorizationInferenceEngine.build_authorization_graph(evidences)
                # Protected = authorization context in the code and confidence above threshold
                protected_count = sum(
                    1
                    for ev in evidences
                    if PropertyAuthorizationInferenceEngine.is_protected_property(ev)
                )

            logger.info(
                f"Property Authorization Inference completato: {protected_count} proprietà protette inferite."
            )
        except Exception as e:
            logger.error(f"Errore durante Property Authorization Inference: {e}")

        # --- Phase 2b: Static rules (reported as "to be verified", never affect the score) ---
        static_findings: list[StaticPropertyFinding] = []
        try:
            logger.info("Inizio Fase 2b: regole statiche BOPLA-S01..S04...")
            static_findings = run_static_rules(repo_path, evidences, openapi_spec)
            logger.info(f"Regole statiche completate: {len(static_findings)} segnalazioni.")
        except Exception as e:
            logger.error(f"Errore durante le regole statiche: {e}")

        # --- Phase 3: Dynamic Testing ---
        findings: list[DynamicPropertyFinding] = []
        dynamic_executed = False
        try:
            if headers_matrix and evidences:
                dynamic_executed = True
                logger.info("Inizio Fase 3: Dynamic Property Testing...")
                logger.info("Avvio Dynamic Property Authorization Testing...")

                tester = BOPLADynamicTester(
                    target_base_url=self.config.target.base_url,
                    inventory=inventory,
                    evidences=evidences,
                    graph=graph,
                    headers_matrix=headers_matrix,
                    runtime_traffic=runtime_traffic,
                    openapi_spec=openapi_spec,
                )

                # Run each test with individual completion logs
                t01_res = tester.run_t01()
                findings.extend(t01_res)
                logger.debug("Test T01 completato.")

                t02_res = tester.run_t02()
                findings.extend(t02_res)
                logger.debug("Test T02 completato.")

                t03_res = tester.run_t03()
                findings.extend(t03_res)
                logger.debug("Test T03 completato.")

                t04_res = tester.run_t04()
                findings.extend(t04_res)
                logger.debug("Test T04 completato.")

                t05_res = tester.run_t05()
                findings.extend(t05_res)
                logger.debug("Test T05 completato.")

                t06_res = tester.run_t06()
                findings.extend(t06_res)
                logger.debug("Test T06 completato.")

                t07_res = tester.run_t07()
                findings.extend(t07_res)
                logger.debug("Test T07 completato.")
            else:
                logger.warning(
                    "Fase 3: Dynamic Property Testing saltata per assenza di credenziali o evidenze."
                )
        except Exception as e:
            logger.error(f"Errore durante il Dynamic Testing: {e}")

        # Static findings confirmed or not by the dynamic tests of the same direction
        # Credentials alone do not make a dynamic phase: if no test produced an outcome (target
        # unreachable, nothing testable) the full score still means "nothing verified".
        if dynamic_executed and not any(f.response_code for f in findings):
            logger.warning(
                "Fase 3: nessuna prova dinamica ha prodotto un esito (target raggiungibile?). "
                "Le segnalazioni statiche restano da verificare."
            )
            dynamic_executed = False
        if dynamic_executed:
            try:
                correlate_with_dynamic(static_findings, findings)
            except Exception as e:
                logger.error(f"Errore durante la correlazione statico-dinamica: {e}")

        # --- Phase 4: Risk Assessment & Reporting ---
        logger.info("Inizio Fase 4: Risk Assessment e Generazione Report...")

        # Calculate Property Authorization Score (resilience starting at 100)
        # Deduct 15 points per failed/verified test case, minimum 0.
        verified_test_ids = {f.test_id for f in findings if f.verified}
        deductions = len(verified_test_ids) * 15
        score = max(0, 100 - deductions)

        # Risk Level mapping
        if score >= 90:
            risk_level = "LOW"
        elif score >= 75:
            risk_level = "MEDIUM"
        elif score >= 50:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"

        # Generate reports
        timestamp_str = datetime.now().isoformat()
        report_data = {
            "timestamp": timestamp_str,
            "target_url": self.config.target.base_url,
            "repository": os.path.basename(os.path.abspath(repo_path)),
            "score": score,
            "risk_level": risk_level,
            "objects_discovered": objects_count,
            "properties_discovered": properties_count,
            "protected_properties": protected_count,
            # Without the dynamic phase a full score means "nothing verified", not "secure".
            "dynamic_phase_executed": dynamic_executed,
            "tests_executed": len(findings),
            "vulnerabilities_detected": len([f for f in findings if f.verified]),
            "findings": [f.model_dump() for f in findings],
            # Static findings are candidates for the dynamic phase, not confirmed vulnerabilities
            "static_findings_count": len(static_findings),
            "static_findings_confirmed": sum(1 for f in static_findings if f.verified),
            "static_findings": [f.model_dump() for f in static_findings],
            "graph": graph.model_dump(),
        }

        # Ensure output folder
        output_dir = Path(self.config.output.path) / "bopla"
        output_dir.mkdir(parents=True, exist_ok=True)

        # 1. JSON Report
        json_path = output_dir / "bopla_report.json"
        try:
            with open(json_path, "w", encoding="utf-8") as jf:
                json.dump(report_data, jf, indent=4)
        except Exception as e:
            logger.error(f"Impossibile salvare il report JSON: {e}")

        # 2. Markdown Report
        md_path = output_dir / "bopla_report.md"
        try:
            md_content = self._generate_markdown_report(report_data)
            with open(md_path, "w", encoding="utf-8") as mf:
                mf.write(md_content)
        except Exception as e:
            logger.error(f"Impossibile salvare il report Markdown: {e}")

        logger.info(f"Report BOPLA generati con successo in: {output_dir}")

        return report_data

    def _generate_markdown_report(self, data: dict[str, Any]) -> str:
        """Generates Markdown content for the report."""
        md = []
        md.append("# Broken Object Property Level Authorization (BOPLA) Security Report")
        md.append(f"- **Data Scansione**: {data['timestamp']}")
        md.append(f"- **Target Application**: {data['target_url']}")
        md.append(f"- **Repository**: {data['repository']}\n")

        md.append("## Property Authorization Resilience Score")
        md.append(f"- **Punteggio**: {data['score']}/100")
        md.append(f"- **Livello di Rischio**: **{data['risk_level']}**\n")

        md.append("## Sommario Esecuzione")
        md.append(f"- Oggetti Scoperti: {data['objects_discovered']}")
        md.append(f"- Proprietà Totali: {data['properties_discovered']}")
        md.append(f"- Proprietà Protette Rilevate: {data['protected_properties']}")
        md.append(
            f"- Fase Dinamica Eseguita: {'sì' if data['dynamic_phase_executed'] else 'no (punteggio non verificato)'}"
        )
        md.append(f"- Test Dinamici Eseguiti: {data['tests_executed']}")
        md.append(f"- Vulnerabilità Confermate (FAIL): {data['vulnerabilities_detected']}")
        md.append(f"- Segnalazioni Statiche (da verificare): {data['static_findings_count']}\n")

        md.append("## Risultati dei Test Dinamici")
        md.append("| Test ID | Proprietà | Endpoint | Metodo | Risultato | Confidenza |")
        md.append("|---|---|---|---|---|---|")

        for f in data["findings"]:
            status = "🔴 FAIL (Vulnerable)" if f["verified"] else "🟢 PASS (Secure)"
            md.append(
                f"| {f['test_id']} | `{f['property_name']}` | `{f['endpoint']}` | `{f['method']}` | {status} | {f['confidence']} |"
            )
        md.append("")

        md.append("## Segnalazioni Statiche (da verificare)")
        if not data.get("static_findings"):
            md.append("Nessuna segnalazione statica.\n")
        else:
            md.append(
                "| Regola | Severità | Stato | Entità | Dove | Proprietà a rischio | Legame |"
            )
            md.append("|---|---|---|---|---|---|---|")
            for f in data["static_findings"]:
                at_risk = ", ".join(f"`{p}`" for p in f["properties_at_risk"]) or "—"
                status = STATUS_LABELS.get(f["status"], f["status"])
                if f["confirmed_by"]:
                    status += f" ({', '.join(f['confirmed_by'])})"
                md.append(
                    f"| {f['rule_id']} | {f['severity']} | {status} | {f['entity'] or '—'} | "
                    f"`{f['file_path']}:{f['line']}` | {at_risk} | `{f['sink'][:80]}` |"
                )
            md.append("")

        md.append("## Dettaglio Findings Rilevati")
        vulnerable_findings = [f for f in data["findings"] if f["verified"]]
        if not vulnerable_findings:
            md.append("Nessuna vulnerabilità BOPLA rilevata con successo.\n")
        else:
            for f in vulnerable_findings:
                md.append(
                    f"### [{f['test_id']}] Proprietà: `{f['property_name']}` su `{f['method']} {f['endpoint']}`"
                )
                md.append(f"- **Livello Confidenza**: {f['confidence']}")
                md.append("- **Evidenze Rilevate**:")
                for ev in f["evidence"]:
                    md.append(f"  - {ev}")
                md.append("- **Richiesta**: ")
                md.append(f"```http\n{f['request']}\n```")
                md.append("- **Risposta**: ")
                md.append(f"```json\n{f['response'][:2000]}\n```\n")

        return "\n".join(md)
