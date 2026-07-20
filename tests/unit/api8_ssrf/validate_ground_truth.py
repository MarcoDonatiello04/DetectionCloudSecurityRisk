#!/usr/bin/env python3
import sys
from pathlib import Path

# Allow running as a script from the project root
PROJECT_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists())
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core.api8_ssrf import detector

GROUND_TRUTH = {
    "vulnerable_app": {
        "expected_findings": [
            {"rule_id": "SS-001", "must_find": True},  # requests + URL da input
            {"rule_id": "SS-002", "must_find": True},  # urllib + URL da input
            {"rule_id": "SS-004", "must_find": True},  # allow_redirects=True
        ]
    },
    "secure_app": {"expected_findings": []},
}


def run_validation(crapi_path: str | None = None):
    results = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}

    for app_name, ground_truth in GROUND_TRUTH.items():
        fixture_path = PROJECT_ROOT / "src" / "core" / "server_side_request_forgery" / "fixtures" / app_name
        report = detector.analyze(str(fixture_path))
        found_rule_ids = {f.rule_id for f in report.findings}

        print(f"\n{'=' * 60}")
        print(f"Fixture: {app_name}")
        print(f"Found:   {sorted(found_rule_ids)}")

        for expected in ground_truth["expected_findings"]:
            rid = expected["rule_id"]
            if rid in found_rule_ids:
                results["TP"] += 1
                print(f"  [TP]  {rid}: detected ✓")
            else:
                results["FN"] += 1
                print(f"  [FN]  {rid}: MISSED ✗")

        if not ground_truth["expected_findings"]:
            if found_rule_ids:
                results["FP"] += len(found_rule_ids)
                for fid in found_rule_ids:
                    print(f"  [FP]  {fid}: false positive ✗")
            else:
                results["TN"] += 1
                print("  [TN] Secure app clean — correct")

    tpr = (
        results["TP"] / (results["TP"] + results["FN"])
        if (results["TP"] + results["FN"]) > 0
        else 0
    )
    fpr = (
        results["FP"] / (results["FP"] + results["TN"])
        if (results["FP"] + results["TN"]) > 0
        else 0
    )

    print(f"\n{'=' * 60}")
    print("=== Validation Results ===")
    print(f"TP: {results['TP']} | TN: {results['TN']} | FP: {results['FP']} | FN: {results['FN']}")
    print(f"TPR: {tpr:.1%} | FPR: {fpr:.1%}")
    print("\n=== Acceptance Criteria ===")
    print(f"  {'✓' if tpr >= 0.8 else '✗'} TPR >= 80% → {tpr:.1%}")
    print(f"  {'✓' if fpr == 0 else '✗'} FPR = 0%  → {fpr:.1%}")

    if tpr >= 0.8 and fpr == 0:
        print("\n✅ API7 module READY — acceptance criteria met.")
    else:
        print("\n❌ API7 module NOT READY — gaps remain.")

    if crapi_path:
        print("\n=== crAPI Findings (confidence >= 0.8) ===")
        crapi_report = detector.analyze(crapi_path)
        high_conf = [f for f in crapi_report.findings if f.confidence >= 0.8]
        if not high_conf:
            print("  No high-confidence findings.")
        for f in high_conf:
            print(f"  [{f.rule_id}] {f.category} @ {f.file_path}:{f.line_number}")
            print(f"    Source:  {f.source}")
            print(f"    Sink:    {f.sink}")
            print(f"    Evidence: {f.evidence}")


if __name__ == "__main__":
    import sys

    crapi = None
    if "--crapi" in sys.argv:
        idx = sys.argv.index("--crapi")
        crapi = sys.argv[idx + 1]
    run_validation(crapi_path=crapi)
