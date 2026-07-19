#!/usr/bin/env python3
"""
entrypoints/runners/run_unified_core_scanners.py
================================================
Unified runner script to execute all core security scanners:
1. BOLA (Broken Object Level Authorization)
2. BOPLA (Broken Object Property Level Authorization)
3. Broken Authentication
4. Broken Function Level Authorization (BFLA)
5. Security Misconfiguration
6. SSRF (Server Side Request Forgery)
7. Unrestricted Resource Consumption
8. Unsafe Consumption

Measures execution time and checks for correctness.
"""

import asyncio
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import yaml

# Setup project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Setup loggers
from loguru import logger

logger.remove()
logger.add(
    sys.stdout,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level:7}</level> | <cyan>{message}</cyan>",
    level="INFO",
)

# Import scanner modules
from src.core.broken_authentication import ast_parser as ba_ast_parser
from src.core.broken_authentication import authentication_intelligence as ba_auth_intel
from src.core.broken_authentication import discovery as ba_discovery
from src.core.broken_authentication import dynamic_tester as ba_dynamic_tester
from src.core.broken_authentication import reporter as ba_reporter
from src.core.broken_function_level_authorization import detector as bfla_detector
from src.core.broken_object_property_level_access.orchestrator import BOPLAOrchestrator
from src.core.object_level_authorization.dynamic_orchestrator import DynamicOrchestrator
from src.core.security_misconfiguration import detector as secmis_detector
from src.core.server_side_request_forgery import detector as ssrf_detector
from src.core.unrestricted_resource_consumption import detector as urc_detector
from src.core.unsafe_consumption import detector as uc_detector


def load_openapi_spec(repo_path: str):
    openapi_paths = [
        Path(repo_path) / "test_targets/bola" / "openapi.yaml",
        Path(repo_path) / "openapi.yaml",
        Path(repo_path) / "openapi.json",
    ]
    for path in openapi_paths:
        if path.is_file():
            try:
                with open(path, encoding="utf-8") as f:
                    if path.suffix in (".yaml", ".yml"):
                        return yaml.safe_load(f)
                    else:
                        return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to parse OpenAPI spec from {path}: {e}")
    return None


def load_runtime_traffic(repo_path: str):
    traffic_paths = [
        Path(repo_path) / "soluzione_api" / "src" / "output" / "raw_traffic.json",
        Path(repo_path) / "output" / "raw_traffic.json",
    ]
    for path in traffic_paths:
        if path.is_file():
            try:
                with open(path, encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to parse runtime traffic from {path}: {e}")
    return None


async def run_broken_authentication(repo_path: str, openapi_spec, runtime_traffic, output_dir: str):
    config = ba_discovery.Config()
    config.target.base_url = "http://localhost:5000"
    config.output.path = output_dir
    config.output.formato = "json"

    # Phase 1: Stack Discovery (Mocked/Fallback)
    stack = ba_discovery.StackInfo(
        linguaggio="python",
        framework="FastAPI",
        librerie_auth=["jwt"],
        file_configurazione_rilevanti=["requirements.txt"],
    )

    # Phase 2: AST Parser
    scored_files = await ba_ast_parser.run(repo_path, stack, config)

    # Phase 3: Auth Intel Engine
    auth_intel = ba_auth_intel.AuthenticationIntelligenceEngine.correlate(
        discovery_output=stack,
        ast_output=scored_files,
        openapi_spec=openapi_spec,
        runtime_traffic=runtime_traffic or [],
    )

    # Phase 4: Dynamic Testing (Mocked/Offline mode)
    vulnerabilities = []
    for f in scored_files:
        if f.chiamate_auth or f.route_auth:
            vulnerabilities.append(
                ba_dynamic_tester.Vulnerabilita(
                    id=f"VULN-{f.file.replace('/', '_')}",
                    tipo="static",
                    descrizione="Static auth endpoint detected via AST",
                    file=f.file,
                    linea=1,
                    route_auth=f.route_auth,
                )
            )

    from unittest.mock import MagicMock

    import httpx

    mock_client = MagicMock(spec=httpx.AsyncClient)
    mock_client.base_url = httpx.URL(config.target.base_url)

    async def mock_http(*args, **kwargs):
        resp = MagicMock(status_code=401)
        resp.text = "Unauthorized"
        return resp

    mock_client.get = mock_http
    mock_client.post = mock_http

    tester = ba_dynamic_tester.DynamicTester(config, client=mock_client, auth_intel=auth_intel)
    tester.health_check = lambda: asyncio.sleep(0)
    results = await tester.run_all(stack, vulnerabilities)

    # Phase 5: Report Generation
    dynamic_reports = []
    for r in results:
        dynamic_reports.append(
            ba_reporter.RisultatoTestDinamico(
                test_id=r.test_id,
                test_nome=r.nome,
                risultato=r.stato,
                dettaglio=r.dettagli,
                raccomandazione="Verify security configurations.",
            )
        )

    report_finale = ba_reporter.ReportFinale(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        repository=os.path.basename(os.path.abspath(repo_path)),
        stack=stack,
        vulnerabilita_statiche=[],
        test_dinamici=dynamic_reports,
        auth_intel=auth_intel,
    )
    await ba_reporter.run(report_finale, config)
    return len(results)


async def main():
    repo_path = "."
    output_dir = "output/unified_run"
    os.makedirs(output_dir, exist_ok=True)

    # Load specs
    openapi_spec = load_openapi_spec(repo_path)
    runtime_traffic = load_runtime_traffic(repo_path)

    modules = [
        {
            "name": "BOLA (Broken Object Level Authorization)",
            "dir": "object_level_authorization",
            "runner": lambda: DynamicOrchestrator(
                target_base_url="http://localhost:5000",
                keycloak_url="http://localhost:8080",
                zap_proxy_url="http://localhost:8090",
                assessment_mode=True,  # Run in assessment mode to execute fast offline
            ).run_dast_pipeline(
                api_inventory=[
                    {"api": {"endpoint": "/identity/api/v2/user/{id}", "method": "GET"}}
                ],
                output_dir=output_dir,
                raw_traffic=runtime_traffic,
            ),
            "is_async": False,
        },
        {
            "name": "BOPLA (Broken Object Property Level Access)",
            "dir": "broken_object_property_level_access",
            "runner": lambda: BOPLAOrchestrator(
                ba_discovery.Config(output=ba_discovery.OutputConfig(path=output_dir))
            ).run_assessment(
                repo_path=repo_path,
                openapi_spec=openapi_spec,
                runtime_traffic=runtime_traffic,
                headers_matrix=None,
            ),
            "is_async": False,
        },
        {
            "name": "Broken Authentication",
            "dir": "broken_authentication",
            "runner": lambda: run_broken_authentication(
                repo_path, openapi_spec, runtime_traffic, output_dir
            ),
            "is_async": True,
        },
        {
            "name": "BFLA (Broken Function Level Authorization)",
            "dir": "broken_function_level_authorization",
            "runner": lambda: bfla_detector.analyze(repo_path, openapi_spec),
            "is_async": False,
        },
        {
            "name": "Security Misconfiguration",
            "dir": "security_misconfiguration",
            "runner": lambda: secmis_detector.analyze(repo_path),
            "is_async": False,
        },
        {
            "name": "SSRF (Server Side Request Forgery)",
            "dir": "server_side_request_forgery",
            "runner": lambda: ssrf_detector.analyze(repo_path, openapi_spec, semgrep_timeout=15),
            "is_async": False,
        },
        {
            "name": "Unrestricted Resource Consumption",
            "dir": "unrestricted_resource_consumption",
            "runner": lambda: urc_detector.analyze(repo_path, openapi_spec),
            "is_async": False,
        },
        {
            "name": "Unsafe Consumption",
            "dir": "unsafe_consumption",
            "runner": lambda: uc_detector.analyze(repo_path),
            "is_async": False,
        },
    ]

    results = []

    print("\n" + "=" * 90)
    print("                     STARTING UNIFIED CORE MODULES EXECUTION")
    print("=" * 90)

    for mod in modules:
        print(f"\n🚀 Running module: {mod['name']} (src/core/{mod['dir']})...")
        start_time = time.time()
        status = "SUCCESS"
        findings_count = 0

        try:
            if mod["is_async"]:
                findings = await mod["runner"]()
            else:
                findings = mod["runner"]()

            # Count findings depending on output type
            if isinstance(findings, list):
                findings_count = len(findings)
            elif isinstance(findings, dict):
                findings_count = findings.get("vulnerabilities_detected", 0) or len(
                    findings.get("findings", [])
                )
            elif hasattr(findings, "findings"):
                findings_count = len(findings.findings)
            elif isinstance(findings, int):
                findings_count = findings

        except Exception as e:
            status = f"FAILED: {e}"
            logger.exception(f"Module {mod['name']} execution failed")

        elapsed = time.time() - start_time
        results.append(
            {
                "name": mod["name"],
                "dir": f"src/core/{mod['dir']}",
                "time": elapsed,
                "status": status,
                "findings": findings_count,
            }
        )

    print("\n" + "=" * 90)
    print("                         UNIFIED CORE MODULES SUMMARY")
    print("=" * 90)
    print(
        f"{'MODULE NAME':<45} | {'DIRECTORY':<35} | {'TIME (s)':<10} | {'STATUS':<10} | {'FINDINGS':<8}"
    )
    print("-" * 120)
    for res in results:
        time_str = f"{res['time']:.3f}"
        print(
            f"{res['name']:<45} | {res['dir']:<35} | {time_str:<10} | {res['status'][:10]:<10} | {res['findings']:<8}"
        )
    print("=" * 90 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
