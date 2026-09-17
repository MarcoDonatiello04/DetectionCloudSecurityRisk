"""
Runner BOLA su una repository target cooperante.

Esegue lo stesso orchestratore D-AST usato per `data/test_targets/bola`, ma puntato a
un target arbitrario che rispetti il contratto cooperante descritto in
`config/bola_target.yaml` (endpoint di seed/snapshot/rollback, identity provider e
identità di test). Gli endpoint da attaccare sono ricavati dalla specifica
OpenAPI del target, non dal codice del framework: e questo che rende il runner
indipendente dalla singola repository.

Prerequisiti a runtime (come per il BOLA classico):
  - il target in ascolto su --target-url, con gli endpoint dell'harness montati;
  - l'identity provider del contratto: Keycloak con le tre identità configurate,
    oppure `static_tokens` con i JWT nelle variabili d'ambiente indicate;
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
    parser.add_argument("--target-url", default=None, help="Default: target.base_url del contratto")
    parser.add_argument(
        "--keycloak-url", default=None, help="Default: identities.url del contratto"
    )
    parser.add_argument(
        "--target-config",
        default=None,
        help="Contratto del bersaglio (default: BOLA_TARGET_CONFIG o config/bola_target.yaml)",
    )
    parser.add_argument("--zap-url", default="http://localhost:8090")
    parser.add_argument("--openapi", default="data/test_targets/repo_target/openapi.yaml")
    parser.add_argument("--output-dir", default="output/repo_target")
    parser.add_argument(
        "--assessment-mode",
        action="store_true",
        help="Esegue senza seeding/snapshot/rollback (analisi statica del traffico).",
    )
    parser.add_argument(
        "--all-methods",
        action="store_true",
        help=(
            "Esercita GET/POST/PUT/PATCH/DELETE su ogni endpoint invece dei soli metodi "
            "dichiarati dalla specifica OpenAPI (esaustivo, 3-5x piu lento)."
        ),
    )
    parser.add_argument(
        "--allow-mutations",
        action="store_true",
        help=(
            "In Assessment Mode riabilita PUT/PATCH/DELETE (esclusi di default perche' "
            "senza snapshot/rollback alterano risorse reali)"
        ),
    )
    args = parser.parse_args()

    from src.core.api1_bola.dynamic_orchestrator import DynamicOrchestrator
    from src.core.api1_bola.target_config import load_bola_target_config

    target_config = load_bola_target_config(args.target_config)
    target_url = args.target_url or target_config.base_url
    keycloak_url = args.keycloak_url or target_config.keycloak_url

    spec = _load_openapi(args.openapi)
    inventory = build_inventory_from_openapi(spec)
    if not inventory:
        print(f"[-] Nessun endpoint trovato nella specifica OpenAPI '{args.openapi}'.")
        return 1

    print(f"[+] Inventario costruito: {len(inventory)} operazioni da '{args.openapi}'.")
    print(
        f"[+] Target: {target_url}  |  Identity provider: {target_config.identity_provider} "
        f"({keycloak_url})"
    )

    orchestrator = DynamicOrchestrator(
        target_base_url=target_url,
        keycloak_url=keycloak_url,
        zap_proxy_url=args.zap_url,
        assessment_mode=args.assessment_mode,
        test_all_methods=args.all_methods,
        target_config=target_config,
        allow_mutations=True if args.allow_mutations else None,
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
