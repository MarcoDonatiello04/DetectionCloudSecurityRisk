"""
Runner Semgrep su una repository target cooperante.

Esegue lo stesso SemgrepScannerAdapter usato dalla pipeline della dashboard, ma
puntato specificamente alla repo target: ne estrae l'inventario degli endpoint
API (metodo, path normalizzato, autenticazione rilevata staticamente) a partire
dal codice sorgente della repo. E la controparte statica del runner BOLA
(run_bola_repo_target.py): le rotte scoperte qui sono quelle che l'analisi
dinamica va poi ad attaccare, e ora combaciano con l'OpenAPI del target.

Esempio:
  PYTHONPATH=. .venv/bin/python entrypoints/runners/run_semgrep_repo_target.py \
      --target data/test_targets/repo_target
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))


def main() -> int:
    parser = argparse.ArgumentParser(description="Runner Semgrep su repository target cooperante")
    parser.add_argument("--target", default="data/test_targets/repo_target")
    parser.add_argument(
        "--output", default="output/repo_target/semgrep_endpoints.json", help="Report JSON"
    )
    args = parser.parse_args()

    from src.infrastructure.adapters.semgrep_adapter import SemgrepScannerAdapter

    if not os.path.isdir(args.target):
        print(f"[-] Directory target inesistente: {args.target}")
        return 1

    findings = SemgrepScannerAdapter().scan(args.target)

    endpoints = []
    for f in findings:
        api = getattr(f, "api", None)
        if not api:
            continue
        endpoints.append(
            {
                "method": getattr(api, "method", ""),
                "endpoint": getattr(api, "endpoint", ""),
                "requires_authentication": getattr(api, "requires_authentication", False),
            }
        )
    endpoints.sort(key=lambda e: (e["endpoint"], e["method"]))

    print(f"[+] Endpoint scoperti in '{args.target}': {len(endpoints)}")
    for e in endpoints:
        auth = "auth" if e["requires_authentication"] else "NO-AUTH"
        print(f"  {e['method']:6} {e['endpoint']:30} [{auth}]")

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(endpoints, fh, indent=2, ensure_ascii=False)
    print(f"[+] Inventario salvato in: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
