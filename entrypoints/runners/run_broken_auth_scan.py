import asyncio
import json
import os
import sys
from datetime import datetime

# Add root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.api2_broken_auth import (
    ast_parser,
    authentication_intelligence,
    discovery,
    dynamic_tester,
    reporter,
)


async def main():
    repo_path = "."
    config = discovery.Config()

    # 1. Phase 1: Discovery
    print("\n=== FASE 1: Stack Discovery ===")
    try:
        stack = await discovery.run(repo_path, config)
        print(f"Stack rilevato: {stack.linguaggio} - {stack.framework}")
        print(f"Librerie Auth: {stack.librerie_auth}")
        print(f"IDP: {stack.identity_provider}")
    except Exception as e:
        print(f"Ollama non disponibile ({e}). Utilizzo stack configurato per procedere...")
        stack = discovery.StackInfo(
            linguaggio="python",
            framework="FastAPI",
            librerie_auth=["jwt"],
            file_configurazione_rilevanti=["requirements.txt"],
        )
        print(f"Stack caricato: {stack.linguaggio} - {stack.framework}")

    # 2. Phase 2: AST Parser
    print("\n=== FASE 2: AST Analysis ===")
    try:
        scored_files = await ast_parser.run(repo_path, stack, config)
        print(f"File analizzati sopra soglia: {len(scored_files)}")
        for f in scored_files[:3]:
            print(f"  - {f.file} (Score: {f.score})")
    except Exception as e:
        print(f"Errore nella Fase 2: {e}")
        return

    # 3. Phase 3: Authentication Intelligence Engine
    print("\n=== FASE 3: Authentication Intelligence Engine ===")
    # Load openapi.yaml if available
    openapi_spec = None
    openapi_paths = ["test_targets/bola/openapi.yaml", "openapi.json", "swagger.json"]
    for path in openapi_paths:
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    if path.endswith(".yaml") or path.endswith(".yml"):
                        import yaml

                        openapi_spec = yaml.safe_load(f)
                    else:
                        openapi_spec = json.load(f)
                print(f"Caricate specifiche OpenAPI da: {path}")
                break
            except Exception as e:
                print(f"Impossibile leggere OpenAPI da {path}: {e}")

    # Simulated runtime traffic logs
    runtime_traffic = [
        {"method": "POST", "path": "/login", "headers": {}, "body_params": {}},
        {
            "method": "GET",
            "path": "/api/profile",
            "headers": {
                "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6ImFkbWluIiwiZXhwIjoxOTk5OTk5OTk5fQ.signature"
            },
        },
    ]

    try:
        auth_intel = authentication_intelligence.AuthenticationIntelligenceEngine.correlate(
            discovery_output=stack,
            ast_output=scored_files,
            openapi_spec=openapi_spec,
            runtime_traffic=runtime_traffic,
        )
        print(
            f"Modello Autenticazione consolidato (Score Confidenza: {auth_intel.confidence_score}):"
        )
        print(f"  - Tipo Auth: {auth_intel.authentication_type}")
        print(f"  - Login: {auth_intel.login_endpoint}")
        print(f"  - Claims: {auth_intel.jwt_claims}")
        print(f"  - Ruoli: {auth_intel.roles}")
    except Exception as e:
        print(f"Errore nella Fase 3: {e}")
        return

    # 4. Phase 4: Dynamic Testing
    print("\n=== FASE 4: Dynamic Testing ===")
    vulnerabilities = []
    for f in scored_files:
        if f.chiamate_auth or f.route_auth:
            vulnerabilities.append(
                dynamic_tester.Vulnerabilita(
                    id=f"VULN-{f.file.replace('/', '_')}",
                    tipo="static",
                    descrizione="Rilevata rotta o chiamata auth via AST",
                    file=f.file,
                    linea=1,
                    route_auth=f.route_auth,
                )
            )

    try:
        # Mock client to avoid needing a live active target server for standalone checks
        from unittest.mock import MagicMock

        import httpx

        mock_client = MagicMock(spec=httpx.AsyncClient)
        mock_client.base_url = httpx.URL("http://localhost:5000")

        async def mock_get(*args, **kwargs):
            resp = MagicMock(status_code=401)
            resp.text = "Unauthorized"
            return resp

        async def mock_post(*args, **kwargs):
            resp = MagicMock(status_code=401)
            resp.text = "Unauthorized"
            return resp

        mock_client.get = mock_get
        mock_client.post = mock_post

        tester = dynamic_tester.DynamicTester(config, client=mock_client, auth_intel=auth_intel)

        async def mock_health():
            return None

        tester.health_check = mock_health

        results = await tester.run_all(stack, vulnerabilities)
        print(f"Eseguiti {len(results)} test dinamici:")
        for r in results:
            print(f"  - {r.test_id} - {r.nome}: {r.stato} ({r.dettagli})")
    except Exception as e:
        print(f"Errore nella Fase 4: {e}")
        return

    # 5. Phase 5: Reporting
    print("\n=== FASE 5: Reporter ===")
    try:
        dynamic_reports = []
        for r in results:
            dynamic_reports.append(
                reporter.RisultatoTestDinamico(
                    test_id=r.test_id,
                    test_nome=r.nome,
                    risultato=r.stato,
                    dettaglio=r.dettagli,
                    raccomandazione="Verificare la configurazione di sicurezza.",
                )
            )

        report_finale = reporter.ReportFinale(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            repository=os.path.basename(os.path.abspath(repo_path)),
            stack=stack,
            vulnerabilita_statiche=[],
            test_dinamici=dynamic_reports,
            auth_intel=auth_intel,
        )

        config.output.path = "output"
        config.output.formato = "both"
        await reporter.run(report_finale, config)
        print("\n[+] Successo: Report JSON e Markdown generati in 'output/'!")
    except Exception as e:
        print(f"Errore nella Fase 5: {e}")


if __name__ == "__main__":
    asyncio.run(main())
