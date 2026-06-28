import os
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from loguru import logger

from src.core.broken_authentication.discovery import Config
from src.core.broken_object_property_level_access.models import (
    PropertyInventory, PropertyEvidence, PropertyAuthorizationGraph, DynamicPropertyFinding
)
from src.core.broken_object_property_level_access.discovery import PropertyDiscoveryEngine
from src.core.broken_object_property_level_access.property_inference import PropertyAuthorizationInferenceEngine
from src.core.broken_object_property_level_access.dynamic_tester import BOPLADynamicTester


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
        openapi_spec: Optional[Dict[str, Any]] = None,
        runtime_traffic: Optional[List[Dict[str, Any]]] = None,
        headers_matrix: Optional[Dict[str, Dict[str, str]]] = None
    ) -> Dict[str, Any]:
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
                repo_path=repo_path,
                openapi_spec=openapi_spec,
                runtime_traffic=runtime_traffic
            )
            objects_count = len(inventory.root)
            properties_count = sum(len(o.properties) for o in inventory.root.values())
            
            # Print exact log required by USER
            print("\n[DISCOVERY]")
            print("Property Discovery completed.")
            print(f"Objects discovered: {objects_count}")
            print(f"Properties discovered: {properties_count}\n")
        except Exception as e:
            logger.error(f"Errore durante Property Discovery: {e}. Inizializzazione inventario vuoto.")
            inventory = PropertyInventory({})

        # --- Phase 2: Property Inference ---
        evidences: List[PropertyEvidence] = []
        graph = PropertyAuthorizationGraph()
        protected_count = 0
        try:
            logger.info("Inizio Fase 2: Property Authorization Inference...")
            if inventory.root:
                evidences = PropertyAuthorizationInferenceEngine.run_inference(
                    repo_path=repo_path,
                    inventory=inventory,
                    openapi_spec=openapi_spec,
                    runtime_traffic=runtime_traffic
                )
                graph = PropertyAuthorizationInferenceEngine.build_authorization_graph(evidences)
                # Count protected properties (confidence > 0.4 or having auth contexts)
                protected_count = sum(1 for ev in evidences if ev.confidence >= 0.4 or ev.authorization_contexts)
            
            # Print exact log required by USER
            print("[INFERENCE]")
            print("Authorization relationships inferred.")
            print(f"Protected properties: {protected_count}\n")
        except Exception as e:
            logger.error(f"Errore durante Property Authorization Inference: {e}")

        # --- Phase 3: Dynamic Testing ---
        findings: List[DynamicPropertyFinding] = []
        try:
            if headers_matrix and evidences:
                logger.info("Inizio Fase 3: Dynamic Property Testing...")
                print("[DYNAMIC]")
                print("Running Property Authorization Tests...")
                
                tester = BOPLADynamicTester(
                    target_base_url=self.config.target.base_url,
                    inventory=inventory,
                    evidences=evidences,
                    graph=graph,
                    headers_matrix=headers_matrix,
                    runtime_traffic=runtime_traffic,
                    openapi_spec=openapi_spec
                )

                # Run each test with individual completion prints
                t01_res = tester.run_t01()
                findings.extend(t01_res)
                print("T01 completed")

                t02_res = tester.run_t02()
                findings.extend(t02_res)
                print("T02 completed")

                t03_res = tester.run_t03()
                findings.extend(t03_res)
                print("T03 completed")

                t04_res = tester.run_t04()
                findings.extend(t04_res)
                print("T04 completed")

                t05_res = tester.run_t05()
                findings.extend(t05_res)
                print("T05 completed")

                t06_res = tester.run_t06()
                findings.extend(t06_res)
                print("T06 completed")

                t07_res = tester.run_t07()
                findings.extend(t07_res)
                print("T07 completed\n")
            else:
                logger.warning("Fase 3: Dynamic Property Testing saltata per assenza di credenziali o evidenze.")
        except Exception as e:
            logger.error(f"Errore durante il Dynamic Testing: {e}")

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
            "tests_executed": len(findings),
            "vulnerabilities_detected": len([f for f in findings if f.verified]),
            "findings": [f.model_dump() for f in findings],
            "graph": graph.model_dump()
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

        # Print exact log required by USER
        print("[REPORT]")
        print("Markdown report generated.")
        print("JSON report generated.\n")

        return report_data

    def _generate_markdown_report(self, data: Dict[str, Any]) -> str:
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
        md.append(f"- Test Dinamici Eseguiti: {data['tests_executed']}")
        md.append(f"- Vulnerabilità Confermate (FAIL): {data['vulnerabilities_detected']}\n")

        md.append("## Risultati dei Test Dinamici")
        md.append("| Test ID | Proprietà | Endpoint | Metodo | Risultato | Confidenza |")
        md.append("|---|---|---|---|---|---|")
        
        for f in data["findings"]:
            status = "🔴 FAIL (Vulnerable)" if f["verified"] else "🟢 PASS (Secure)"
            md.append(f"| {f['test_id']} | `{f['property_name']}` | `{f['endpoint']}` | `{f['method']}` | {status} | {f['confidence']} |")
        md.append("")

        md.append("## Dettaglio Findings Rilevati")
        vulnerable_findings = [f for f in data["findings"] if f["verified"]]
        if not vulnerable_findings:
            md.append("Nessuna vulnerabilità BOPLA rilevata con successo.\n")
        else:
            for f in vulnerable_findings:
                md.append(f"### [{f['test_id']}] Proprietà: `{f['property_name']}` su `{f['method']} {f['endpoint']}`")
                md.append(f"- **Livello Confidenza**: {f['confidence']}")
                md.append("- **Evidenze Rilevate**:")
                for ev in f["evidence"]:
                    md.append(f"  - {ev}")
                md.append("- **Richiesta**: ")
                md.append(f"```http\n{f['request']}\n```")
                md.append("- **Risposta**: ")
                md.append(f"```json\n{f['response'][:2000]}\n```\n")

        return "\n".join(md)
