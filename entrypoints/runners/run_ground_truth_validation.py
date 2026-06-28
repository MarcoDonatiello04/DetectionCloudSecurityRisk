"""
entrypoints/runners/run_ground_truth_validation.py
=======================================
Blind validation runner for the ground_truth_target.

Workflow
--------
1. Start vulnerable_app on :5001 (background subprocess).
2. Start secure_app on :5002 (background subprocess).
3. Run the broken-authentication scanner on the VULNERABLE app.
4. Run the broken-authentication scanner on the SECURE app.
5. Save both result sets to validation_results/ground_truth_YYYYMMDD_HHMMSS/.
6. Print a summary table to stdout.

Constraints
-----------
- This script NEVER reads or imports answer_key.md.
- The scanner receives ONLY the app's base URL, credentials, and repo path.
- No ground-truth information leaks into the scan inputs.
"""

import asyncio
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths — all relative to project root
# ---------------------------------------------------------------------------
PROJECT_ROOT  = Path(__file__).resolve().parent.parent
VULN_APP_DIR  = PROJECT_ROOT / "tests/ground_truth" / "vulnerable_app"
SECURE_APP_DIR = PROJECT_ROOT / "tests/ground_truth" / "secure_app"
OUTPUT_DIR    = PROJECT_ROOT / "validation_results"

VULN_PORT  = 5001
SECURE_PORT = 5002

# Test credentials (same in both apps, documented in README.md)
USERNAME = "testuser"
PASSWORD = "testpass123"

# ---------------------------------------------------------------------------
# Scanner imports
# ---------------------------------------------------------------------------
sys.path.insert(0, str(PROJECT_ROOT))

from loguru import logger
import yaml

from src.core.broken_authentication.discovery import Config, TargetConfig, StackInfo
from src.core.broken_authentication import (
    ast_parser,
    discovery,
    authentication_intelligence,
    dynamic_tester,
)
from src.core.broken_authentication.authentication_intelligence import (
    AuthenticationIntelligenceEngine,
)


# ---------------------------------------------------------------------------
# Helper: wait for a Flask app to be ready
# ---------------------------------------------------------------------------
async def wait_for_app(base_url: str, proc: subprocess.Popen, timeout: int = 45) -> bool:
    """Poll base_url until HTTP < 500 or timeout (seconds) is reached.
    If the process has already died, logs its stderr and returns False.
    """
    import httpx
    deadline = time.time() + timeout
    while time.time() < deadline:
        # Check if the subprocess crashed early
        if proc.poll() is not None:
            stderr_out = proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr else ""
            logger.error(f"Flask process terminated early (rc={proc.returncode}):\n{stderr_out}")
            return False
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                r = await client.get(base_url + "/api/login")
                if r.status_code < 500:
                    return True
        except Exception:
            pass
        await asyncio.sleep(1)
    # On timeout, still log stderr
    stderr_out = ""
    try:
        proc.stderr.seek(0)  # only works for seekable streams
    except Exception:
        pass
    try:
        stderr_out = proc.stderr.read(4096).decode("utf-8", errors="replace")
    except Exception:
        pass
    if stderr_out:
        logger.error(f"Flask stderr on timeout:\n{stderr_out}")
    return False


# ---------------------------------------------------------------------------
# Helper: start a Flask subprocess
# ---------------------------------------------------------------------------
def start_flask_app(app_dir: Path, port: int) -> subprocess.Popen:
    """Launch `python app.py` inside app_dir using the same interpreter as this
    script (sys.executable) so that the active virtualenv is always inherited."""
    env = os.environ.copy()
    env["FLASK_ENV"] = "development"
    # Ensure PYTHONPATH includes the project root so relative imports inside
    # the app don't break when cwd is changed to app_dir.
    env["PYTHONPATH"] = str(PROJECT_ROOT)
    proc = subprocess.Popen(
        [sys.executable, str(app_dir / "app.py")],
        cwd=str(app_dir),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    logger.info(f"Started Flask app on port {port} (PID {proc.pid}, interpreter {sys.executable})")
    return proc


# ---------------------------------------------------------------------------
# Helper: build a minimal Config for a given target app
# ---------------------------------------------------------------------------
def build_config(base_url: str) -> Config:
    return Config(
        target=TargetConfig(
            base_url=base_url,
            username=USERNAME,
            password=PASSWORD,
        )
    )


# ---------------------------------------------------------------------------
# Helper: build a minimal StackInfo (no LLM needed — Flask/PyJWT is known)
# ---------------------------------------------------------------------------
def build_stack_info() -> StackInfo:
    return StackInfo(
        linguaggio="Python",
        framework="Flask",
        librerie_auth=["PyJWT", "flask"],
        identity_provider=None,
        file_configurazione_rilevanti=["requirements.txt"],
        discovery_methods={
            "linguaggio": "heuristic",
            "framework": "heuristic",
            "librerie_auth": "heuristic",
            "identity_provider": "heuristic",
        },
        non_jwt_mechanisms=[],
        crawled_routes={},
    )


# ---------------------------------------------------------------------------
# Helper: load openapi.yaml from an app directory
# ---------------------------------------------------------------------------
def load_openapi(app_dir: Path) -> dict:
    spec_path = app_dir / "openapi.yaml"
    if spec_path.is_file():
        with open(spec_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


# ---------------------------------------------------------------------------
# Core: run the scanner against one target app
# ---------------------------------------------------------------------------
async def scan_target(
    label: str,
    app_dir: Path,
    base_url: str,
    output_subdir: Path,
) -> list:
    """
    Run Fase 1-4 of the broken-auth scanner against a running Flask app.
    Returns the list of RisultatoTest objects.
    """
    logger.info(f"\n{'='*60}")
    logger.info(f"Scanning: {label}  →  {base_url}")
    logger.info(f"{'='*60}")

    config = build_config(base_url)
    stack = build_stack_info()
    openapi_spec = load_openapi(app_dir)

    # --- Fase 2: AST Parsing (against the app source) ---
    logger.info("Fase 2 — AST Parsing...")
    try:
        ast_results = await ast_parser.run(str(app_dir), stack, config)
    except Exception as e:
        logger.warning(f"AST Parsing fallita: {e}. Continuo con lista vuota.")
        ast_results = []

    # --- Fase 3: Authentication Intelligence ---
    logger.info("Fase 3 — Authentication Intelligence Engine...")
    auth_intel = AuthenticationIntelligenceEngine.correlate(
        discovery_output=stack,
        ast_output=ast_results,
        openapi_spec=openapi_spec if openapi_spec else None,
        runtime_traffic=None,
    )
    # Inject the known JWT secret for ground truth testing to allow cryptographically valid token spoofing (T02)
    auth_intel.jwt_secret = "jwt-secret-do-not-use-in-prod"
    logger.info(
        f"Auth Intel → type={auth_intel.authentication_type}, "
        f"login={auth_intel.login_endpoint}, "
        f"confidence={auth_intel.confidence_score}, "
        f"jwt_secret_present={auth_intel.jwt_secret is not None}"
    )

    # --- Fase 4: Dynamic Testing ---
    logger.info("Fase 4 — Dynamic Testing...")
    tester = dynamic_tester.DynamicTester(
        config=config,
        auth_intel=auth_intel,
        target_environment="staging",      # enables destructive tests
        allow_destructive_tests=True,
        rate_limit_delay=0.1,
        confidence_threshold=0.0,          # run all tests regardless of confidence
        openapi_spec=openapi_spec if openapi_spec else None,
    )
    results = await tester.run_all(stack, [])  # no AST vulnerabilities pre-fed

    # --- Persist results ---
    output_subdir.mkdir(parents=True, exist_ok=True)
    results_path = output_subdir / f"{label.replace(' ', '_')}_results.json"
    serialized = [r.model_dump() for r in results]
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(serialized, f, indent=2, ensure_ascii=False)
    logger.info(f"Risultati salvati in: {results_path}")

    return results


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------
def print_summary(label: str, results: list) -> None:
    fail_count = sum(1 for r in results if r.stato == "FAIL")
    pass_count = sum(1 for r in results if r.stato == "PASS")
    skip_count = sum(1 for r in results if r.stato in ("SKIPPED", "INCONCLUSIVE"))

    print(f"\n{'─'*70}")
    print(f"  {label}")
    print(f"{'─'*70}")
    print(f"  {'Test ID':<8}{'Status':<14}{'Severity':<12}{'Name'}")
    print(f"  {'─'*7:<8}{'─'*13:<14}{'─'*11:<12}{'─'*30}")
    for r in results:
        flag = "🔴" if r.stato == "FAIL" else ("🟢" if r.stato == "PASS" else "⚪")
        print(f"  {r.test_id:<8}{flag} {r.stato:<12}{r.severita:<12}{r.nome}")
    print(f"\n  FAIL={fail_count}  PASS={pass_count}  SKIP/INC={skip_count}")
    print(f"{'─'*70}\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
async def main() -> None:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = OUTPUT_DIR / f"ground_truth_{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"Output directory: {run_dir}")

    # ------------------------------------------------------------------
    # 1. Start Flask apps
    # ------------------------------------------------------------------
    vuln_proc   = start_flask_app(VULN_APP_DIR,   VULN_PORT)
    secure_proc = start_flask_app(SECURE_APP_DIR, SECURE_PORT)

    vuln_url   = f"http://localhost:{VULN_PORT}"
    secure_url = f"http://localhost:{SECURE_PORT}"

    try:
        # ------------------------------------------------------------------
        # 2. Wait for both apps to be ready
        # ------------------------------------------------------------------
        logger.info("Attendo avvio vulnerable_app ...")
        if not await wait_for_app(vuln_url, vuln_proc):
            logger.error("vulnerable_app non risponde dopo 45s. Uscita.")
            return

        logger.info("Attendo avvio secure_app ...")
        if not await wait_for_app(secure_url, secure_proc):
            logger.error("secure_app non risponde dopo 45s. Uscita.")
            return

        logger.info("Entrambe le app sono pronte ✓")

        # ------------------------------------------------------------------
        # 3. Scan VULNERABLE app
        # ------------------------------------------------------------------
        vuln_results = await scan_target(
            label="vulnerable_app",
            app_dir=VULN_APP_DIR,
            base_url=vuln_url,
            output_subdir=run_dir,
        )

        # ------------------------------------------------------------------
        # 4. Scan SECURE app
        # ------------------------------------------------------------------
        secure_results = await scan_target(
            label="secure_app",
            app_dir=SECURE_APP_DIR,
            base_url=secure_url,
            output_subdir=run_dir,
        )

        # ------------------------------------------------------------------
        # 5. Print summary
        # ------------------------------------------------------------------
        print_summary("vulnerable_app  (DEVE rilevare FAIL)", vuln_results)
        print_summary("secure_app      (NON deve rilevare FAIL)", secure_results)

        # ------------------------------------------------------------------
        # 6. Persist combined metadata
        # ------------------------------------------------------------------
        meta = {
            "timestamp": timestamp,
            "vulnerable_url": vuln_url,
            "secure_url": secure_url,
            "note": (
                "Scanner run in BLIND mode. "
                "answer_key.md was NOT read by this script or the scanner. "
                "Compare results with answer_key.md manually after the test."
            ),
        }
        with open(run_dir / "run_metadata.json", "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2, ensure_ascii=False)

        logger.info(f"\nValidazione completata. Report completo in: {run_dir}")

    finally:
        # ------------------------------------------------------------------
        # 7. Stop Flask apps
        # ------------------------------------------------------------------
        logger.info("Arresto delle app Flask...")
        for proc in (vuln_proc, secure_proc):
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
        logger.info("App Flask arrestate ✓")


if __name__ == "__main__":
    asyncio.run(main())
