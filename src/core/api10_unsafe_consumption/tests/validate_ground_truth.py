import sys
import argparse
from pathlib import Path
from src.core.api10_unsafe_consumption import detector

GROUND_TRUTH = {
    "vulnerable_app": {
        "expected_findings": [
            {"rule_id": "UC-001", "must_find": True},
            {"rule_id": "UC-002", "must_find": True},
            {"rule_id": "UC-003", "must_find": True},
        ]
    },
    "secure_app": {
        "expected_findings": []
    }
}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--crapi", type=str, help="Path to crAPI repo")
    args = parser.parse_args()

    if args.crapi:
        print("=== Scanning crAPI Repository ===")
        crapi_path = Path(args.crapi)
        if not crapi_path.exists():
            print(f"Error: path {args.crapi} does not exist.")
            sys.exit(1)
        report = detector.analyze(str(crapi_path))
        print(f"Total findings on crAPI: {len(report.findings)}")
        for f in report.findings:
            print(f"  [{f.rule_id}] {f.category} @ {f.file_path}:{f.line_number}")
            print(f"    Evidence: {f.evidence}")
            print(f"    Missing:  {f.missing_guard}")
            print(f"    Confidence: {f.confidence}")
        return

    fixtures_dir = Path(__file__).parent.parent / "fixtures"
    tp_count = 0
    fn_count = 0
    tn_count = 0
    fp_count = 0

    for app_name, info in GROUND_TRUTH.items():
        print("=" * 60)
        print(f"Fixture: {app_name}")
        app_path = fixtures_dir / app_name
        report = detector.analyze(str(app_path))
        found_ids = [f.rule_id for f in report.findings]
        print(f"Found:   {found_ids}")

        expected = info["expected_findings"]
        if expected:
            for rule_info in expected:
                rid = rule_info["rule_id"]
                if rid in found_ids:
                    print(f"  [TP]  {rid}: detected ✓")
                    tp_count += 1
                else:
                    print(f"  [FN]  {rid}: MISSED ✗")
                    fn_count += 1
        else:
            if found_ids:
                print(f"  [FP]  Secure app had findings: {found_ids} ✗")
                fp_count += len(found_ids)
            else:
                print("  [TN] Secure app clean — correct")
                tn_count += 1

    print("=" * 60)
    print("=== Validation Results ===")
    print(f"TP: {tp_count} | TN: {tn_count} | FP: {fp_count} | FN: {fn_count}")
    
    total_positives = tp_count + fn_count
    tpr = (tp_count / total_positives * 100.0) if total_positives > 0 else 100.0
    fpr = (fp_count / (fp_count + tn_count) * 100.0) if (fp_count + tn_count) > 0 else 0.0
    
    print(f"TPR: {tpr:.1f}% | FPR: {fpr:.1f}%")
    print("\n=== Acceptance Criteria ===")
    
    ok = True
    if tpr >= 80.0:
        print(f"  ✓ TPR >= 80% → {tpr:.1f}%")
    else:
        print(f"  ✗ TPR >= 80% → {tpr:.1f}%")
        ok = False
        
    if fpr == 0.0:
        print(f"  ✓ FPR = 0%  → {fpr:.1f}%")
    else:
        print(f"  ✗ FPR = 0%  → {fpr:.1f}%")
        ok = False

    if ok:
        print("\n✅ API10 module READY — acceptance criteria met.\n")
    else:
        print("\n❌ API10 module NOT READY — gaps remain.\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
