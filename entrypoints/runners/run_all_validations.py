#!/usr/bin/env python3
"""
entrypoints/runners/run_all_validations.py
==========================================
Unified validation runner that runs:
1. Main CLI Pipeline on `bola` (test_targets/bola)
2. Broken Authentication Ground Truth Validation
3. API8 (Security Misconfiguration) Ground Truth Validation
4. API5 (Broken Function Level Authorization) Ground Truth Validation
5. API4 (Unrestricted Resource Consumption) Ground Truth Validation
6. (Optional) crAPI Validation
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

# Add root directory to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Color codes for stdout
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
NC = "\033[0m"


def run_step(name: str, cmd: list, cwd: Path = PROJECT_ROOT) -> bool:
    print(f"\n{BLUE}================================================================{NC}")
    print(f"{BLUE}⏳ Running Step: {name}{NC}")
    print(f"{BLUE}Command: {' '.join(cmd)}{NC}")
    print(f"{BLUE}================================================================{NC}\n")

    # Inherit current environment and set PYTHONPATH
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT)

    try:
        subprocess.run(cmd, cwd=str(cwd), env=env, stdout=sys.stdout, stderr=sys.stderr, check=True)
        print(f"\n{GREEN}✅ Step '{name}' completed successfully!{NC}\n")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n{RED}❌ Step '{name}' failed with exit code {e.returncode}.{NC}\n")
        return False
    except Exception as e:
        print(f"\n{RED}❌ Unexpected error running step '{name}': {e}{NC}\n")
        return False


def main():
    parser = argparse.ArgumentParser(description="Unified Security Validation Runner")
    parser.add_argument(
        "--include-crapi",
        action="store_true",
        help="Include supplemental crAPI dynamic validation (slower)",
    )
    args = parser.parse_args()

    steps = [
        (
            "Main CLI Pipeline (BOLA/bola)",
            [
                sys.executable,
                "-m",
                "src.presentation.cli.main",
                "--target-dir",
                ".",
                "--target-base-url",
                "http://localhost:5000",
                "--assessment-mode",
            ],
        ),
        (
            "Broken Authentication Ground Truth",
            [sys.executable, "entrypoints/runners/run_ground_truth_validation.py"],
        ),
        (
            "API8 Security Misconfiguration Ground Truth",
            [sys.executable, "src/core/security_misconfiguration/tests/validate_ground_truth.py"],
        ),
        (
            "API5 Broken Function Level Authorization Ground Truth",
            [
                sys.executable,
                "src/core/broken_function_level_authorization/tests/validate_ground_truth.py",
            ],
        ),
        (
            "API4 Unrestricted Resource Consumption Ground Truth",
            [
                sys.executable,
                "src/core/unrestricted_resource_consumption/tests/validate_ground_truth.py",
            ],
        ),
    ]

    if args.include_crapi:
        steps.append(
            (
                "crAPI Supplemental Validation",
                [sys.executable, "entrypoints/runners/run_crapi_validation.py"],
            )
        )

    failed_steps = []

    for name, cmd in steps:
        success = run_step(name, cmd)
        if not success:
            failed_steps.append(name)

    print(f"\n{BLUE}================================================================{NC}")
    print(f"{BLUE}🏁 VALIDATION RUN SUMMARY{NC}")
    print(f"{BLUE}================================================================{NC}")
    if not failed_steps:
        print(f"{GREEN}🎉 All checks passed!{NC}")
        sys.exit(0)
    else:
        print(f"{RED}⚠️ The following steps failed:{NC}")
        for step in failed_steps:
            print(f"  - {step}")
        sys.exit(1)


if __name__ == "__main__":
    main()
