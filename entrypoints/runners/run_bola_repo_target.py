"""
Runner BOLA su una repository target cooperante.

Esegue lo stesso orchestratore D-AST usato per `data/test_targets/bola`, ma puntato a
un target arbitrario che rispetti il contratto cooperante (endpoint
/test/seed, /test/snapshot, /test/rollback e fiducia nell'identity provider
Keycloak condiviso). Gli endpoint da attaccare sono ricavati dalla specifica
OpenAPI del target, non dal codice del framework: e questo che rende il runner
indipendente dalla singola repository.

Prerequisiti a runtime (come per il BOLA classico):
  - il target in ascolto su --target-url, con gli endpoint /test/* montati;
  - Keycloak attivo su --keycloak-url con gli utenti user_a/user_b/admin_user;
  - OWASP ZAP raggiungibile su --zap-url (salvo --assessment-mode).

Esempio:
  PYTHONPATH=. .venv/bin/python entrypoints/runners/run_bola_repo_target.py \
      --target-url http://localhost:5000 \
      --openapi data/test_targets/repo_target/openapi.yaml
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any

import yaml

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

_HTTP_METHODS = {"get", "post", "put", "patch", "delete"}


def build_inventory_from_openapi(spec: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Converte una specifica OpenAPI nell'inventario atteso dall'orchestratore:
    una lista di voci `{"api": {"endpoint": <path>, "method": <METHOD>}}`.
    """
    inventory: list[dict[str, Any]] = []
    for path, path_item in (spec.get("paths") or {}).items():
        if not isinstance(path_item, dict):
            continue
        for method, _operation in path_item.items():
            if method.lower() not in _HTTP_METHODS:
                continue
            inventory.append({"api": {"endpoint": path, "method": method.upper()}})
    return inventory


def _load_openapi(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def main() -> int:
    parser = argparse.ArgumentParser(description="Runner BOLA su repository target cooperante")
    parser.add_argument("--target-url", default="http://localhost:5000")
    parser.add_argument("--keycloak-url", default="http://localhost:8080")
    parser.add_argument("--zap-url", default="http://localhost:8090")
    parser.add_argument("--openapi", default="data/test_targets/repo_target/openapi.yaml")
    parser.add_argument("--output-dir", default="output/repo_target")
    parser.add_argument(
        "--assessment-mode",
        action="store_true",
        help="Esegue senza seeding/snapshot/rollback (analisi statica del traffico).",
    )
    args = parser.parse_args()

    from src.core.api1_bola.dynamic_orchestrator import DynamicOrchestrator

    spec = _load_openapi(args.openapi)
    inventory = build_inventory_from_openapi(spec)
    if not inventory:
        print(f"[-] Nessun endpoint trovato nella specifica OpenAPI '{args.openapi}'.")
        return 1

    print(f"[+] Inventario costruito: {len(inventory)} operazioni da '{args.openapi}'.")
    print(f"[+] Target: {args.target_url}  |  Keycloak: {args.keycloak_url}")

    orchestrator = DynamicOrchestrator(
        target_base_url=args.target_url,
        keycloak_url=args.keycloak_url,
        zap_proxy_url=args.zap_url,
        assessment_mode=args.assessment_mode,
    )
    findings = orchestrator.run_dast_pipeline(
        api_inventory=inventory,
        output_dir=args.output_dir,
        raw_traffic=None,
    )

    print("=========================================")
    print("BOLA Repo-Target Assessment Completato")
    print(f"Endpoint analizzati: {len(inventory)}")
    print(f"Findings: {len(findings)}")
    print(f"Report in: {args.output_dir}/")
    print("=========================================")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
