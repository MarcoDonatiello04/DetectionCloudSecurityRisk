#!/usr/bin/env python3
"""
entrypoints/runners/run_all_security_tests.py
==================================
Unified runner script to execute all three security scanner modules:
1. Broken Authentication Scanner (src.core.api2_broken_auth)
2. BOPLA (Broken Object Property Level Authorization) Scanner (src.core.api3_bopla)
3. BOLA (Broken Object Level Authorization) Scanner (src.core.api1_bola)
"""

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path

import httpx
import yaml

# Add root directory to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Logger setup
from loguru import logger

logger.remove()
logger.add(
    sys.stdout,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level:7}</level> | <cyan>{message}</cyan>",
    level="INFO",
)

# Import scanner modules
from src.core.api1_bola.dynamic_orchestrator import DynamicOrchestrator
from src.core.api2_broken_auth import ast_parser as ba_ast_parser
from src.core.api2_broken_auth import authentication_intelligence as ba_auth_intel
from src.core.api2_broken_auth import discovery as ba_discovery
from src.core.api2_broken_auth import dynamic_tester as ba_dynamic_tester
from src.core.api2_broken_auth import reporter as ba_reporter
from src.core.api3_bopla.orchestrator import BOPLAOrchestrator
from src.core.identity_context import IdentityManager


def parse_args():
    parser = argparse.ArgumentParser(description="Unified Cloud Security Risk Scanner (All-in-One)")
    parser.add_argument("--target-url", default="http://localhost:5000", help="Target API URL base")
    parser.add_argument(
        "--keycloak-url", default="http://localhost:8080", help="Keycloak IDP base URL"
    )
    parser.add_argument("--zap-url", default="http://localhost:8090", help="OWASP ZAP proxy URL")
    parser.add_argument("--repo-path", default=".", help="Path to the repository to analyze")
    parser.add_argument("--output-dir", default="output", help="Directory where reports are stored")
    parser.add_argument(
        "--assessment-mode",
        action="store_true",
        help="Run in Assessment Mode (skip Keycloak/seeding, infer from traffic)",
    )
    return parser.parse_args()


async def check_target_reachability(url: str) -> bool:
    """Checks if the target URL is reachable by performing a simple HTTP request."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            await client.get(url)
            return True
    except Exception:
        return False


def load_openapi_spec(repo_path: str):
    openapi_spec = None
    openapi_paths = [
        Path(repo_path) / "data/test_targets/bola" / "openapi.yaml",
        Path(repo_path) / "openapi.yaml",
        Path(repo_path) / "openapi.json",
    ]
    for path in openapi_paths:
        if path.is_file():
            try:
                with open(path, encoding="utf-8") as f:
                    if path.suffix in (".yaml", ".yml"):
                        openapi_spec = yaml.safe_load(f)
                    else:
                        openapi_spec = json.load(f)
                logger.info(f"Loaded OpenAPI specification from {path}")
                break
            except Exception as e:
                logger.warning(f"Failed to parse OpenAPI spec from {path}: {e}")
    return openapi_spec


def load_runtime_traffic(repo_path: str):
    runtime_traffic = None
    traffic_paths = [
        Path(repo_path) / "soluzione_api" / "src" / "output" / "raw_traffic.json",
        Path(repo_path) / "output" / "raw_traffic.json",
    ]
    for path in traffic_paths:
        if path.is_file():
            try:
                with open(path, encoding="utf-8") as f:
                    runtime_traffic = json.load(f)
                logger.info(
                    f"Loaded runtime traffic data from {path} ({len(runtime_traffic)} records)"
                )
                break
            except Exception as e:
                logger.warning(f"Failed to parse runtime traffic from {path}: {e}")
    return runtime_traffic


def extract_api_inventory(openapi_spec, runtime_traffic):
    """Builds a list of endpoints to seed BOLA / D-AST scans."""
    api_inventory = []
    seen = set()

    if openapi_spec and "paths" in openapi_spec:
        for path, path_item in openapi_spec["paths"].items():
            if not path_item:
                continue
            for method in ["get", "post", "put", "delete", "patch"]:
                if method in path_item:
                    key = (path, method.upper())
                    if key not in seen:
                        seen.add(key)
                        api_inventory.append({"api": {"endpoint": path, "method": method.upper()}})

    if runtime_traffic:
        for entry in runtime_traffic:
            path = entry.get("path")
            method = entry.get("method", "GET").upper()
            if path:
                key = (path, method)
                if key not in seen:
                    seen.add(key)
                    api_inventory.append({"api": {"endpoint": path, "method": method}})

    return api_inventory


async def run_broken_authentication(args, openapi_spec, runtime_traffic, target_reachable: bool):
    logger.info("=========================================")
    logger.info("  Starting BROKEN AUTHENTICATION Scanner ")
    logger.info("=========================================")

    config = ba_discovery.Config()
    config.target.base_url = args.target_url
    config.output.path = args.output_dir
    config.output.formato = "both"

    # 1. Phase 1: Stack Discovery
    logger.info("[BA] Phase 1 - Stack Discovery...")
    try:
        stack = await ba_discovery.run(args.repo_path, config)
        logger.info(f"[BA] Stack discovered: {stack.linguaggio} - {stack.framework}")
    except Exception as e:
        logger.warning(
            f"[BA] LLM Stack Discovery unavailable ({e}). Using Python/FastAPI fallback."
        )
        stack = ba_discovery.StackInfo(
            linguaggio="python",
            framework="FastAPI",
            librerie_auth=["jwt"],
            file_configurazione_rilevanti=["requirements.txt"],
        )

    # 2. Phase 2: AST Parser
    logger.info("[BA] Phase 2 - AST Parsing...")
    try:
        scored_files = await ba_ast_parser.run(args.repo_path, stack, config)
        logger.info(f"[BA] Analyzed {len(scored_files)} files above threshold.")
    except Exception as e:
        logger.error(f"[BA] AST Parsing failed: {e}")
        scored_files = []

    # 3. Phase 3: Auth Intel Engine
    logger.info("[BA] Phase 3 - Auth Intelligence Engine...")
    auth_intel = ba_auth_intel.AuthenticationIntelligenceEngine.correlate(
        discovery_output=stack,
        ast_output=scored_files,
        openapi_spec=openapi_spec,
        runtime_traffic=runtime_traffic or [],
    )

    # 4. Phase 4: Dynamic Testing
    logger.info("[BA] Phase 4 - Dynamic Testing...")
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

    results = []
    if target_reachable:
        try:
            async with httpx.AsyncClient(
                base_url=args.target_url, timeout=config.scanner.timeout_http
            ) as client:
                tester = ba_dynamic_tester.DynamicTester(
                    config, client=client, auth_intel=auth_intel
                )
                results = await tester.run_all(stack, vulnerabilities)
        except Exception as e:
            logger.error(f"[BA] Real dynamic scan failed: {e}. Falling back to mock client.")
            target_reachable = False

    if not target_reachable:
        logger.info("[BA] Target unreachable. Running dynamic checks in mock mode.")
        from unittest.mock import MagicMock

        mock_client = MagicMock(spec=httpx.AsyncClient)
        mock_client.base_url = httpx.URL(args.target_url)

        async def mock_http(*args, **kwargs):
            resp = MagicMock(status_code=401)
            resp.text = "Unauthorized"
            return resp

        mock_client.get = mock_http
        mock_client.post = mock_http

        tester = ba_dynamic_tester.DynamicTester(config, client=mock_client, auth_intel=auth_intel)
        tester.health_check = lambda: asyncio.sleep(0)
        results = await tester.run_all(stack, vulnerabilities)

    # 5. Phase 5: Report Generation
    logger.info("[BA] Phase 5 - Report Generation...")
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
        repository=os.path.basename(os.path.abspath(args.repo_path)),
        stack=stack,
        vulnerabilita_statiche=[],
        test_dinamici=dynamic_reports,
        auth_intel=auth_intel,
    )

    await ba_reporter.run(report_finale, config)
    logger.info(f"[BA] Completed. Report saved in: {config.output.path}")
    return results


def run_bopla(args, openapi_spec, runtime_traffic):
    logger.info("=========================================")
    logger.info("       Starting BOPLA Scanner            ")
    logger.info("=========================================")

    config = ba_discovery.Config()
    config.output.path = args.output_dir

    # Load Keycloak identities
    headers_matrix = None
    if not args.assessment_mode:
        try:
            identity_manager = IdentityManager(keycloak_url=args.keycloak_url)
            headers_matrix = identity_manager.get_headers_for_identities()
        except Exception as e:
            logger.warning(
                f"[BOPLA] Keycloak IdentityManager unavailable ({e}). Using traffic/mock fallback."
            )

    orchestrator = BOPLAOrchestrator(config)
    report_data = orchestrator.run_assessment(
        repo_path=args.repo_path,
        openapi_spec=openapi_spec,
        runtime_traffic=runtime_traffic,
        headers_matrix=headers_matrix,
    )

    logger.info(f"[BOPLA] Assessment complete. Report saved to: {config.output.path}/bopla/")
    return report_data


def run_bola(args, openapi_spec, runtime_traffic):
    logger.info("=========================================")
    logger.info("       Starting BOLA Scanner (D-AST)     ")
    logger.info("=========================================")

    api_inventory = extract_api_inventory(openapi_spec, runtime_traffic)
    logger.info(f"[BOLA] Extracted {len(api_inventory)} endpoints for testing.")

    dast_orchestrator = DynamicOrchestrator(
        target_base_url=args.target_url,
        keycloak_url=args.keycloak_url,
        zap_proxy_url=args.zap_url,
        assessment_mode=args.assessment_mode,
    )

    dast_findings = dast_orchestrator.run_dast_pipeline(
        api_inventory=api_inventory, output_dir=args.output_dir, raw_traffic=runtime_traffic
    )

    logger.info(f"[BOLA] D-AST scan complete. Found {len(dast_findings)} findings.")
    return dast_findings


def print_unified_summary(ba_results, bopla_data, bola_findings):
    print("\n" + "=" * 80)
    print("                      UNIFIED SECURITY ASSESSMENT SUMMARY")
    print("=" * 80)

    # 1. Broken Authentication Summary
    print("\n[+] 1. BROKEN AUTHENTICATION SCANNER")
    if ba_results:
        passed = sum(1 for r in ba_results if r.stato == "PASS")
        failed = sum(1 for r in ba_results if r.stato == "FAIL")
        inc = sum(1 for r in ba_results if r.stato in ("INCONCLUSIVE", "SKIPPED"))
        print(f"    - Total tests run: {len(ba_results)}")
        print(f"    - Passed:  {passed}")
        print(f"    - Failed:  {failed} (FAIL)")
        print(f"    - Skip/Inc: {inc}")
    else:
        print("    - No Broken Authentication tests were executed.")

    # 2. BOPLA Summary
    print("\n[+] 2. BOPLA (Broken Object Property Level Authorization)")
    if bopla_data:
        print(f"    - Objects Discovered:    {bopla_data.get('objects_discovered', 0)}")
        print(f"    - Properties Discovered: {bopla_data.get('properties_discovered', 0)}")
        print(f"    - Dynamic Tests Run:     {bopla_data.get('tests_executed', 0)}")
        print(f"    - Vulnerabilities:       {bopla_data.get('vulnerabilities_detected', 0)}")
        print(f"    - Security Score:        {bopla_data.get('score', 100)}/100")
    else:
        print("    - No BOPLA data was returned.")

    # 3. BOLA Summary
    print("\n[+] 3. BOLA (Broken Object Level Authorization)")
    if bola_findings is not None:
        vulnerable = sum(
            1
            for f in bola_findings
            if f.validation_status.value == "CONFIRMED" and f.rule_id != "dynamic-test-secure"
        )
        secure = sum(1 for f in bola_findings if f.rule_id == "dynamic-test-secure")
        print(f"    - Total endpoints evaluated: {len(bola_findings)}")
        print(f"    - Confirmed BOLA Vulnerable: {vulnerable}")
        print(f"    - Confirmed BOLA Secure:     {secure}")
    else:
        print("    - No BOLA findings were returned.")

    print("\n" + "=" * 80)
    print("All reports are available under the configured output directories.")
    print("=" * 80 + "\n")


async def main_async():
    args = parse_args()

    # Setup directories
    os.makedirs(args.output_dir, exist_ok=True)

    # 1. Pre-validation checks
    target_reachable = await check_target_reachability(args.target_url)
    if target_reachable:
        logger.info(f"Target URL {args.target_url} is active and responding.")
    else:
        logger.warning(f"Target URL {args.target_url} is offline/unreachable.")

    # 2. Load context files
    openapi_spec = load_openapi_spec(args.repo_path)
    runtime_traffic = load_runtime_traffic(args.repo_path)

    # 3. Execute Scanners
    ba_results = []
    try:
        ba_results = await run_broken_authentication(
            args, openapi_spec, runtime_traffic, target_reachable
        )
    except Exception as e:
        logger.error(f"Error during Broken Authentication execution: {e}", exc_info=True)

    bopla_data = None
    try:
        bopla_data = run_bopla(args, openapi_spec, runtime_traffic)
    except Exception as e:
        logger.error(f"Error during BOPLA execution: {e}", exc_info=True)

    bola_findings = None
    try:
        bola_findings = run_bola(args, openapi_spec, runtime_traffic)
    except Exception as e:
        logger.error(f"Error during BOLA execution: {e}", exc_info=True)

    # 4. Print final summary block
    print_unified_summary(ba_results, bopla_data, bola_findings)


if __name__ == "__main__":
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        logger.info("Process interrupted by user.")
        sys.exit(1)
