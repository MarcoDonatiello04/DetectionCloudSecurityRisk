#!/usr/bin/env python3
"""
Validazione blind API4 detector contro fixture ground truth.

Eseguire dopo ogni ciclo di implementazione:
    python3 -m src.core.api4_unrestricted_resource_consumption.tests.validate_ground_truth
    oppure:
    python3 src/core/api4_unrestricted_resource_consumption/tests/validate_ground_truth.py

Output:
  - Per ogni rule: TP, TN, FP, FN
  - TPR / FPR complessivi
  - Lista finding inattesi (potenziali FP)
  - Tabella riassuntiva per coverage doc
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# Allow running as a script from the project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.core.api4_unrestricted_resource_consumption import detector  # noqa: E402

# ---------------------------------------------------------------------------
# Ground truth
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"

# RC-004 is intentionally absent from vulnerable_app: the fixture uses
# FastAPI/Flask (no GraphQL), so absence is "not applicable" not FN.
# RC-006 is tracked as a known false-negative due to a tree-sitter 0.25
# API issue (redis substring match) — documented in the skip reason.
GROUND_TRUTH: dict[str, dict[str, Any]] = {
    "vulnerable_app": {
        "expected_findings": [
            {"rule_id": "RC-001", "must_find": True,  "note": "Unbounded pagination param"},
            {"rule_id": "RC-002", "must_find": True,  "note": "Upload without size check"},
            {"rule_id": "RC-003", "must_find": True,  "note": "HTTP call without timeout"},
            {"rule_id": "RC-004", "must_find": False, "note": "No GraphQL in fixture — N/A"},
            {"rule_id": "RC-005", "must_find": True,  "note": "For-loop on user input"},
            {"rule_id": "RC-006", "must_find": True,  "note": "Twilio client call without throttle"},
            {"rule_id": "RC-007", "must_find": True,  "note": "docker-compose: no memory limits"},
            {"rule_id": "RC-008", "must_find": True,  "note": "nginx + .env: no body size limit"},
            {"rule_id": "RC-009", "must_find": True,  "note": "gunicorn timeout=0 + nginx no proxy timeouts"},
        ]
    },
    "secure_app": {
        "expected_findings": [],  # zero findings expected (FPR test)
    },
}

# ---------------------------------------------------------------------------
# Per-rule result tracking
# ---------------------------------------------------------------------------

def _run_validation(verbose: bool = True) -> dict[str, Any]:
    results: dict[str, int] = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
    per_rule: dict[str, str] = {}
    false_positives: list[str] = []
    missed: list[str] = []

    for app_name, ground_truth in GROUND_TRUTH.items():
        fixture_path = FIXTURES_DIR / app_name
        if not fixture_path.exists():
            print(f"[ERROR] Fixture not found: {fixture_path}")
            continue

        report = detector.analyze(str(fixture_path))
        found_rule_ids = {f.rule_id for f in report.findings}

        if verbose:
            print(f"\n{'='*60}")
            print(f"Fixture: {app_name}")
            print(f"Found:   {sorted(found_rule_ids)}")

        expected = ground_truth["expected_findings"]

        if not expected:
            # Secure app — nothing should fire
            if found_rule_ids:
                for rid in sorted(found_rule_ids):
                    results["FP"] += 1
                    false_positives.append(f"{app_name}/{rid}")
                    if verbose:
                        print(f"  [FP] Unexpected finding: {rid}")
            else:
                results["TN"] += 1
                if verbose:
                    print(f"  [TN] Secure app clean — correct")
        else:
            for exp in expected:
                rule_id = exp["rule_id"]
                must_find = exp["must_find"]
                note = exp.get("note", "")

                if not must_find:
                    if verbose:
                        print(f"  [N/A] {rule_id}: {note}")
                    per_rule[rule_id] = "N/A"
                    continue

                if rule_id in found_rule_ids:
                    results["TP"] += 1
                    per_rule[rule_id] = "TP"
                    if verbose:
                        print(f"  [TP]  {rule_id}: detected ✓")
                else:
                    results["FN"] += 1
                    per_rule[rule_id] = "FN"
                    missed.append(f"{app_name}/{rule_id}")
                    if verbose:
                        print(f"  [FN]  {rule_id}: MISSED — {note}")

    # Summary metrics
    tp = results["TP"]
    fn = results["FN"]
    fp = results["FP"]
    tn = results["TN"]
    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    if verbose:
        print(f"\n{'='*60}")
        print(f"=== Validation Results ===")
        print(f"TP: {tp} | TN: {tn} | FP: {fp} | FN: {fn}")
        print(f"TPR: {tpr:.1%} | FPR: {fpr:.1%}")
        if missed:
            print(f"\nMissed rules: {missed}")
        if false_positives:
            print(f"False positives: {false_positives}")

        print(f"\n=== Per-Rule Summary ===")
        for rule_id in sorted(per_rule):
            status = per_rule[rule_id]
            icon = {"TP": "✓", "FN": "✗", "N/A": "-"}.get(status, "?")
            print(f"  {icon} {rule_id}: {status}")

    return {
        "TP": tp, "TN": tn, "FP": fp, "FN": fn,
        "TPR": tpr, "FPR": fpr,
        "per_rule": per_rule,
        "missed": missed,
        "false_positives": false_positives,
    }


# ---------------------------------------------------------------------------
# Optional: crAPI validation (no strict ground truth, report-only)
# ---------------------------------------------------------------------------

def run_crapi_validation(crapi_path: str) -> None:
    """
    Run detector against crAPI codebase.
    No exact ground truth — produces a report for manual review.
    Only high-confidence findings (>= 0.8) are shown.
    """
    report = detector.analyze(crapi_path)
    high_confidence = [f for f in report.findings if f.confidence >= 0.8]

    print(f"\n=== crAPI Findings (confidence >= 0.8) ===")
    if not high_confidence:
        print("  No high-confidence findings.")
        return
    for f in high_confidence:
        fname = f.file_path.split("/")[-1] if f.file_path else "?"
        print(f"  [{f.rule_id}] {f.category} @ {fname}:{f.line_number}")
        print(f"    Evidence: {f.evidence[:100]}")
        print(f"    Missing:  {f.missing_guard[:80]}")


# ---------------------------------------------------------------------------
# Acceptance criteria check
# ---------------------------------------------------------------------------

def check_acceptance_criteria(results: dict[str, Any]) -> bool:
    """
    Returns True if the module meets the acceptance criteria for API5 readiness:
      1. TPR >= 80%
      2. FPR = 0%
    """
    tpr = results["TPR"]
    fpr = results["FPR"]

    print(f"\n=== Acceptance Criteria ===")
    criteria = [
        (tpr >= 0.80, f"TPR >= 80% → {tpr:.1%}"),
        (fpr == 0.0,  f"FPR = 0%  → {fpr:.1%}"),
    ]
    all_pass = True
    for passed, label in criteria:
        icon = "✓" if passed else "✗"
        print(f"  {icon} {label}")
        if not passed:
            all_pass = False

    if all_pass:
        print("\n✅ API4 module READY — acceptance criteria met.")
    else:
        print("\n⚠️  API4 module NOT YET READY — fix failures above.")

    return all_pass


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_validation(verbose: bool = True) -> dict[str, Any]:
    return _run_validation(verbose=verbose)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="API4 ground truth validator")
    parser.add_argument("--crapi", metavar="PATH", help="Path to crAPI codebase for supplemental analysis")
    parser.add_argument("--quiet", action="store_true", help="Suppress per-fixture output")
    args = parser.parse_args()

    results = run_validation(verbose=not args.quiet)
    check_acceptance_criteria(results)

    if args.crapi:
        run_crapi_validation(args.crapi)

    # Exit with non-zero if acceptance criteria not met
    passed = check_acceptance_criteria(results)
    sys.exit(0 if passed else 1)
