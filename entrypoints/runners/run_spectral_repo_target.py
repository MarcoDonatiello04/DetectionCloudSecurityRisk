"""
Runner Spectral sul contratto OpenAPI di una repository target cooperante.

Esegue lo stesso SpectralScannerAdapter della pipeline della dashboard, ma
puntato al contratto OpenAPI della repo target, valutandolo rispetto al ruleset
OWASP API Security (config/scanner_configs/spectral-owasp.yaml). Completa la
copertura statica del target: lo stesso openapi.yaml e discoverato da Semgrep,
analizzato qui da Spectral e usato da BOLA come mappa degli endpoint da attaccare.

Prerequisito: Node.js/npx (per @stoplight/spectral-cli via npx).

Esempio:
  PYTHONPATH=. .venv/bin/python entrypoints/runners/run_spectral_repo_target.py \
      --openapi data/test_targets/repo_target/openapi.yaml
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))


def main() -> int:
    parser = argparse.ArgumentParser(description="Runner Spectral su repository target cooperante")
    parser.add_argument("--openapi", default="data/test_targets/repo_target/openapi.yaml")
    parser.add_argument("--output", default="output/repo_target/spectral_findings.json")
    args = parser.parse_args()

    from src.infrastructure.adapters.spectral_adapter import SpectralScannerAdapter

    if not os.path.isfile(args.openapi):
        print(f"[-] Contratto OpenAPI inesistente: {args.openapi}")
        return 1

    findings = SpectralScannerAdapter().scan(args.openapi)

    print(f"[+] Findings Spectral su '{args.openapi}': {len(findings)}")
    by_rule = Counter(getattr(f, "rule_id", "?") for f in findings)
    for rule_id, count in by_rule.most_common():
        marker = "OWASP" if "owasp" in rule_id.lower() else "  oas"
        print(f"  [{marker}] {count:3}  {rule_id}")

    serialized = [f.to_dict() if hasattr(f, "to_dict") else str(f) for f in findings]
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(serialized, fh, indent=2, ensure_ascii=False, default=str)
    print(f"[+] Report salvato in: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
