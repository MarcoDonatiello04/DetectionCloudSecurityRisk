import asyncio
import json
import os
import sys
from datetime import datetime

import httpx

# Add root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.broken_authentication import (
    ast_parser,
    authentication_intelligence,
    discovery,
    dynamic_tester,
    reporter,
)


async def main():
    repo_path = "crapi_repo"
    config = discovery.Config()

    # Configure base target URL to crAPI ingress gateway
    config.target.base_url = "http://localhost:8888"
    config.scanner.timeout_http = 15.0

    print("\n=== [1] FASE 1: Stack Discovery ===")
    try:
        stack = await discovery.run(repo_path, config)
        print(f"Stack rilevato: {stack.linguaggio} - {stack.framework}")
        print(f"Librerie Auth: {stack.librerie_auth}")
        print(f"IDP: {stack.identity_provider}")
    except Exception as e:
        print(
            f"Ollama non disponibile o errore Discovery: {e}. Utilizzo stack euristico fallback..."
        )
        stack = discovery.StackInfo(
            linguaggio="java",
            framework="Spring",
            librerie_auth=["jwt", "spring-security"],
            file_configurazione_rilevanti=["pom.xml"],
        )
        print(f"Stack caricato: {stack.linguaggio} - {stack.framework}")

    print("\n=== [2] FASE 2: AST Analysis ===")
    try:
        scored_files = await ast_parser.run(repo_path, stack, config)
        print(f"File analizzati sopra soglia: {len(scored_files)}")
        for f in scored_files[:5]:
            print(f"  - {f.file} (Score: {f.score})")
    except Exception as e:
        print(f"Errore nella Fase 2: {e}")
        scored_files = []

    print("\n=== [3] FASE 3: Authentication Intelligence Engine ===")
    openapi_spec = None
    openapi_path = "crapi_repo/openapi-spec/crapi-openapi-spec.json"
    if os.path.exists(openapi_path):
        try:
            with open(openapi_path, encoding="utf-8") as f:
                openapi_spec = json.load(f)
            print(f"Caricate specifiche OpenAPI da: {openapi_path}")
        except Exception as e:
            print(f"Impossibile leggere OpenAPI da {openapi_path}: {e}")

    # Simulated traffic representing the discovery context
    runtime_traffic = [
        {"method": "POST", "path": "/identity/api/auth/login", "headers": {}, "body_params": {}},
        {
            "method": "GET",
            "path": "/identity/api/v2/user/dashboard",
            "headers": {
                "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjo0Mn0.signature"
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
        print(f"  - Logout: {auth_intel.logout_endpoint}")
        print(f"  - Reset: {auth_intel.refresh_endpoint}")
        print(f"  - Claims: {auth_intel.jwt_claims}")
    except Exception as e:
        print(f"Errore nella Fase 3: {e}")
        return

    print("\n=== [4] FASE 4: Dynamic Testing ===")
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

    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = f"validation_results/crapi_run_{timestamp_str}"
    os.makedirs(output_dir, exist_ok=True)

    try:
        # Construct real HTTP client pointing to crAPI Ingress
        async with httpx.AsyncClient(
            base_url=config.target.base_url, timeout=config.scanner.timeout_http
        ) as real_client:
            tester = dynamic_tester.DynamicTester(
                config=config,
                client=real_client,
                auth_intel=auth_intel,
                target_environment="staging",
                allow_destructive_tests=True,
                openapi_spec=openapi_spec,
            )

            # Run all dynamic tests T01-T20
            results = await tester.run_all(stack, vulnerabilities)
            print(f"Eseguiti {len(results)} test dinamici:")
            for r in results:
                print(f"  - {r.test_id} - {r.nome}: {r.stato} ({r.dettagli})")

            # Perform Guardrail checks and log information
            print("\n=== Sanity Check sui Guardrail ===")
            t19_results = [r for r in results if r.test_id == "T19"]
            if t19_results:
                print(f"T19 (MFA Bypass) Stato: {t19_results[0].stato}")

            # Count MFA/OTP attempts
            otp_reqs = [req for req in tester.request_audit_log if "check-otp" in req["url"]]
            print(f"Numero totale di tentativi OTP generati: {len(otp_reqs)}")
            if len(otp_reqs) <= 10:
                print("✅ Guardrail T19 rispetta il limite massimo di 10 tentativi OTP.")
            else:
                print(f"❌ Guardrail T19 VIOLATO: inviati {len(otp_reqs)} tentativi OTP.")

            # Brute Force Request Log check
            brute_reqs = [req for req in tester.request_audit_log if "login" in req["url"]]
            print(f"Numero totale di tentativi brute-force generati: {len(brute_reqs)}")

            # Destructive Operations check
            non_auth_reqs = [
                req
                for req in tester.request_audit_log
                if not any(
                    x in req["url"].lower()
                    for x in ["login", "otp", "token", "password", "reset", "health"]
                )
            ]
            print(
                f"Richieste esterne ad auth/reset (escluse le chiamate di health check): {len(non_auth_reqs)}"
            )

            destructive_attempt = any(
                req["method"] in ["DELETE", "PUT"] for req in tester.request_audit_log
            )
            if not destructive_attempt:
                print("✅ Nessuna operazione distruttiva non prevista rilevata.")
            else:
                print("⚠️ Attenzione: Rilevate chiamate PUT/DELETE durante il run.")

    except Exception as e:
        print(f"Errore nella Fase 4: {e}")
        return

    print("\n=== [5] FASE 5: Reporter ===")
    try:
        dynamic_reports = []
        for r in results:
            dynamic_reports.append(
                reporter.RisultatoTestDinamico(
                    test_id=r.test_id,
                    test_nome=r.nome,
                    risultato=r.stato,
                    dettaglio=r.dettagli,
                    raccomandazione=getattr(r, "raccomandazione", None)
                    or "Verificare la configurazione di sicurezza.",
                )
            )

        report_finale = reporter.ReportFinale(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            repository=os.path.basename(os.path.abspath(repo_path)),
            stack=stack,
            vulnerabilita_statiche=[],
            test_dinamici=dynamic_reports,
            auth_intel=auth_intel,
            auth_strategy=tester.auth_strategy,
        )

        config.output.path = output_dir
        config.output.formato = "both"
        await reporter.run(report_finale, config)
        print(f"\n[+] Successo: Report JSON e Markdown generati in '{output_dir}/'!")
    except Exception as e:
        print(f"Errore nella Fase 5: {e}")


if __name__ == "__main__":
    asyncio.run(main())
