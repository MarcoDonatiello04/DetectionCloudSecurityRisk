#!/usr/bin/env python3
"""
Validazione blind API5 detector contro fixture ground truth.
"""

import sys
from pathlib import Path
from typing import Any

# Allow running as a script from the project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core.broken_function_level_authorization import detector

FIXTURES_DIR = PROJECT_ROOT / "test_targets" / "broken_function_level_authorization"

GROUND_TRUTH: dict[str, dict[str, Any]] = {
    "vulnerable_app": {
        "expected_findings": [
            {"rule_id": "BF-001", "must_find": True},
            {"rule_id": "BF-002", "must_find": True},
            {"rule_id": "BF-003", "must_find": True},
            {"rule_id": "BF-004", "must_find": True},
            {"rule_id": "BF-005", "must_find": True},
            {"rule_id": "BF-006", "must_find": True},
        ]
    },
    "secure_app": {
        "expected_findings": []  # FPR = 0% richiesto
    },
}


def _run_validation(verbose: bool = True) -> dict[str, Any]:
    results = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
    false_positives = []
    missed = []

    for app_name, ground_truth in GROUND_TRUTH.items():
        fixture_path = FIXTURES_DIR / app_name
        report = detector.analyze(str(fixture_path))
        found_rule_ids = {f.rule_id for f in report.findings}

        if verbose:
            print(f"\n{'=' * 60}")
            print(f"Fixture: {app_name}")
            print(f"Found:   {sorted(found_rule_ids)}")

        for expected in ground_truth["expected_findings"]:
            rid = expected["rule_id"]
            if expected["must_find"]:
                if rid in found_rule_ids:
                    results["TP"] += 1
                    if verbose:
                        print(f"  [TP]  {rid}: detected ✓")
                else:
                    results["FN"] += 1
                    missed.append(rid)
                    if verbose:
                        print(f"  [FN]  {rid}: MISSED ✗")

        if not ground_truth["expected_findings"]:
            if found_rule_ids:
                results["FP"] += len(found_rule_ids)
                for fid in found_rule_ids:
                    false_positives.append(f"{app_name}/{fid}")
                    if verbose:
                        print(f"  [FP]  {fid}: false positive ✗")
            else:
                results["TN"] += 1
                if verbose:
                    print("  [TN] Secure app clean — correct")

    tpr = (
        (results["TP"] / (results["TP"] + results["FN"])) * 100
        if (results["TP"] + results["FN"]) > 0
        else 0.0
    )
    fpr = (
        (results["FP"] / (results["FP"] + results["TN"])) * 100
        if (results["FP"] + results["TN"]) > 0
        else 0.0
    )

    if verbose:
        print(f"\n{'=' * 60}")
        print("=== Validation Results ===")
        print(
            f"TP: {results['TP']} | TN: {results['TN']} | FP: {results['FP']} | FN: {results['FN']}"
        )
        print(f"TPR: {tpr:.1f}% | FPR: {fpr:.1f}%")

        print("\n=== Acceptance Criteria ===")
        tpr_ok = tpr >= 80.0
        fpr_ok = fpr == 0.0
        print(f"  {'✓' if tpr_ok else '✗'} TPR >= 80% → {tpr:.1f}%")
        print(f"  {'✓' if fpr_ok else '✗'} FPR = 0%  → {fpr:.1f}%")

        if tpr_ok and fpr_ok:
            print("\n✅ API5 module READY — acceptance criteria met.")
        else:
            print("\n❌ API5 module NOT READY — gaps remain.")

    return {
        "tpr": tpr,
        "fpr": fpr,
        "results": results,
        "missed": missed,
        "false_positives": false_positives,
    }


def run_validation(crapi_path: str | None = None):
    _run_validation(verbose=True)
    if crapi_path:
        print("\n=== crAPI Findings (confidence >= 0.8) ===")
        crapi_report = detector.analyze(crapi_path)
        high_conf = [f for f in crapi_report.findings if f.confidence >= 0.8]
        if not high_conf:
            print("  No high-confidence findings.")
        for f in high_conf:
            print(f"  [{f.rule_id}] {f.category} @ {f.file_path}:{f.line_number}")
            print(f"    Evidence: {f.evidence}")
            print(f"    Missing:  {f.missing_guard}")


if __name__ == "__main__":
    import sys

    crapi = None
    if "--crapi" in sys.argv:
        idx = sys.argv.index("--crapi")
        crapi = sys.argv[idx + 1]
    run_validation(crapi_path=crapi)
