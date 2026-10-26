#!/usr/bin/env python3
"""
Validazione del rilevatore statico API1 (BOLA) contro le fixture di ground truth.

A differenza di una verifica per insieme di regole, ogni atteso è una tupla
(file, regola, metodo, path normalizzato): un finding giusto sull'endpoint sbagliato
conta come FP + FN. L'app sicura deve risultare pulita (FPR = 0%).

Uso: PYTHONPATH=. python tests/unit/api1_bola/validate_static_ground_truth.py
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists())
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core.api1_bola import detector

FIXTURES_DIR = PROJECT_ROOT / "data/test_targets" / "broken_object_level_authorization"

Expected = tuple[str, str, str, str]  # (file, rule_id, METHOD, correlation path)

GROUND_TRUTH: dict[str, list[Expected]] = {
    "vulnerable_app": [
        ("app.py", "OA-001", "GET", "/api/orders/{id}"),
        ("app.py", "OA-002", "GET", "/api/invoices/{id}"),
        ("app.py", "OA-003", "DELETE", "/api/documents/{id}"),
        ("app.py", "OA-004", "GET", "/api/projects/{id}/tasks/{id}"),
        ("app.py", "OA-002", "GET", "/api/receipts/{id}"),
        ("app.py", "OA-005", "GET", "/api/receipts/{id}"),
        ("server.js", "OA-001", "GET", "/api/orders/{id}"),
        ("server.js", "OA-002", "GET", "/api/invoices/{id}"),
        ("server.js", "OA-003", "PUT", "/api/documents/{id}"),
        ("server.js", "OA-004", "GET", "/api/projects/{id}/tasks/{id}"),
        ("server.js", "OA-002", "GET", "/api/receipts/{id}"),
        ("server.js", "OA-005", "GET", "/api/receipts/{id}"),
    ],
    "secure_app": [],
}


def _key(finding) -> Expected:
    method = (finding.http_methods or ["GET"])[0]
    path = (finding.correlation_key or "").split(":", 2)[-1]
    return (Path(finding.file_path).name, finding.rule_id, method, path)


def run_validation(verbose: bool = True) -> dict[str, Any]:
    results = {"TP": 0, "FN": 0, "FP": 0, "TN": 0}
    details: dict[str, dict[str, list[Expected]]] = {}

    for app_name, expected in GROUND_TRUTH.items():
        app_dir = FIXTURES_DIR / app_name
        spec = detector.load_spec(app_dir / "openapi.yaml")
        report = detector.analyze(str(app_dir), openapi_spec=spec)
        found = {_key(f) for f in report.findings}
        wanted = set(expected)

        tp, fn, fp = sorted(wanted & found), sorted(wanted - found), sorted(found - wanted)
        results["TP"] += len(tp)
        results["FN"] += len(fn)
        results["FP"] += len(fp)
        if not expected and not found:
            results["TN"] += 1
        details[app_name] = {"tp": tp, "fn": fn, "fp": fp}

        if verbose:
            print(
                f"\n{'=' * 70}\nFixture: {app_name}  (handler analizzati: {report.handlers_analyzed})"
            )
            for item in tp:
                print(f"  [TP] {item}")
            for item in fn:
                print(f"  [FN] {item}  MISSED")
            for item in fp:
                print(f"  [FP] {item}  FALSE POSITIVE")
            if not expected and not found:
                print("  [TN] Secure app clean — correct")

    positives = results["TP"] + results["FN"]
    flagged = results["TP"] + results["FP"]
    tpr = results["TP"] / positives * 100 if positives else 0.0
    precision = results["TP"] / flagged * 100 if flagged else 0.0
    secure_fp = len(details["secure_app"]["fp"])
    if verbose:
        print(f"\n{'=' * 70}")
        print(f"TP={results['TP']} FN={results['FN']} FP={results['FP']} TN={results['TN']}")
        print(f"TPR={tpr:.1f}%  Precision={precision:.1f}%  FP su app sicura={secure_fp}")
    return {
        "results": results,
        "tpr": tpr,
        "precision": precision,
        "secure_fp": secure_fp,
        "details": details,
    }


if __name__ == "__main__":
    outcome = run_validation(verbose=True)
    ok = outcome["results"]["FN"] == 0 and outcome["results"]["FP"] == 0
    sys.exit(0 if ok else 1)
