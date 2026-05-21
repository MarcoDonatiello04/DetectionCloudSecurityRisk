import os
import sys
import json
import time

# Aggiungiamo la root del progetto al PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.static_analysis.scanner import StaticAPIScanner
from src.runtime.zap.client import ZAPRuntimeClient
from src.normalization.normalizer import APIEndpointNormalizer
from src.correlation.engine import APICorrelationEngine
from src.openapi.generator import OpenAPISpecGenerator
from src.scanners.spectral_runner import run_spectral
from src.openapi.dashboard_generator import APIDashboardGenerator

def load_target_env() -> tuple:
    """Carica gli URL target da config/environments/.target_env se disponibile."""
    target_host = "http://localhost:5000"
    zap_target = "http://host.docker.internal:5000"
    env_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../config/environments/.target_env"))
    
    if not os.path.exists(env_file):
        env_file = os.path.abspath("config/environments/.target_env")
        
    if os.path.exists(env_file):
        try:
            with open(env_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("TARGET_URL="):
                        target_host = line.split("=", 1)[1]
                    elif line.startswith("ZAP_TARGET_URL="):
                        zap_target = line.split("=", 1)[1]
            print(f"🌲 Rilevato ambiente LocalStack attivo (.target_env):")
            print(f"   - Target Locale (Python): {target_host}")
            print(f"   - Target ZAP (Docker): {zap_target}")
        except Exception as e:
            print(f"⚠️ Errore caricamento .target_env: {e}")
    else:
        print(f"ℹ️ File .target_env non trovato. Uso di default localhost:5000.")
        
    return target_host, zap_target

def generate_live_api_traffic(target_host: str):
    """Invia richieste HTTP reali (GET, POST) verso l'host live facendole passare per Mitmproxy."""
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    print(f"\n🔥 [Dynamic Generator] Generazione attiva di traffico API reale verso: {target_host}")
    
    proxies = {
        "http": "http://localhost:8081",
        "https": "http://localhost:8081"
    }

    endpoints_to_call = [
        {"path": "/users", "method": "GET"},
        {"path": "/users/1", "method": "GET"},
        {"path": "/users/10", "method": "GET"},
        {"path": "/login", "method": "POST", "body": {"username": "admin", "password": "supersecretpassword123"}},
        {"path": "/admin", "method": "GET", "headers": {"Authorization": "Bearer fake-jwt-token-12345"}},
        {"path": "/upload", "method": "POST", "body": {"filename": "thesis_report.txt", "content": "Dynamic Cloud Security Audit 2026"}},
        {"path": "/search", "method": "GET", "query": "q=cross-site-scripting-test"},
        {"path": "/debug", "method": "GET"},
        {"path": "/notes", "method": "POST", "body": {"id": "100", "content": "Active learning with dynamic API discovery"}}
    ]

    for ep in endpoints_to_call:
        path = ep["path"]
        method = ep["method"]
        query = ep.get("query", "")
        
        # Costruiamo l'URL assoluto per il proxy
        url = f"{target_host.rstrip('/')}{path}"
        if query:
            url += f"?{query}"
            
        headers = ep.get("headers", {})
        headers["User-Agent"] = "DynamicTrafficGenerator/1.0"
        
        body_data = ep.get("body")
        
        try:
            if method == "GET":
                response = requests.get(url, headers=headers, proxies=proxies, verify=False, timeout=5)
            elif method == "POST":
                # Utilizziamo json=body_data se il corpo è presente, per impostare automaticamente Content-Type: application/json
                response = requests.post(url, json=body_data, headers=headers, proxies=proxies, verify=False, timeout=5)
            else:
                continue
                
            status = response.status_code
            if status >= 400 and status != 502:
                print(f"   🟢 [DYNAMIC CALL] {method} {path} ➡️ Status: {status}")
            elif status == 502:
                print(f"   🟢 [DYNAMIC CALL] {method} {path} ➡️ Status: {status} (Gateway Mock/Bypassed)")
            else:
                print(f"   🟢 [DYNAMIC CALL] {method} {path} ➡️ Status: {status}")
        except Exception as e:
            print(f"   🔴 [DYNAMIC CALL FAILURE] {method} {path} ➡️ {e}")
    print("✅ Generazione traffico attivo completata!\n")

def run_pipeline(target_dir: str = ".", target_host: str = None):
    print("="*80)
    print("🚀 AVVIO PIPELINE API DISCOVERY & RUNTIME TRAFFIC EXTRACTION")
    print("="*80)
    
    # Carica la configurazione del target attivo da .target_env
    env_target, env_zap_target = load_target_env()
    if not target_host:
        target_host = env_target
        
    # --------------------------------------------------------------------------
    # FASE 1: Static API Discovery
    # --------------------------------------------------------------------------
    print("\n🔍 [FASE 1] Avvio Static API Discovery (Semgrep / Heuristic AST)...")
    static_scanner = StaticAPIScanner(target_dir)
    static_endpoints = static_scanner.scan()
    print(f"✅ Static API Discovery completata: trovati {len(static_endpoints)} endpoint statici.")
    
    # --------------------------------------------------------------------------
    # FASE 2 & 3: Runtime Traffic Generation (ZAP) & Extraction (Mitmproxy)
    # --------------------------------------------------------------------------
    print("\n🌐 [FASE 2 & 3] Runtime Traffic Generation & Traffic Interception (Mitmproxy)...")
    
    zap_client = ZAPRuntimeClient()
    zap_online = zap_client.is_alive()
    
    raw_traffic = []
    traffic_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "output/raw_traffic.json"))
    
    # 1. Se il proxy mitmproxy locale è attivo (porta 8081), avviamo la generazione attiva di chiamate
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        mitm_active = s.connect_ex(('localhost', 8081)) == 0
        s.close()
    except Exception:
        mitm_active = False

    if mitm_active:
        print("🔗 Mitmproxy Central Proxy (8081) rilevato attivo.")
        # Generiamo le chiamate API dinamiche reali tramite il proxy
        generate_live_api_traffic(target_host)
    else:
        print("⚠️ Mitmproxy Central Proxy (8081) non raggiungibile.")

    # 2. Se ZAP è online, stimoliamo l'API anche con lo scanner DAST
    if zap_online:
        print("🔗 OWASP ZAP Daemon rilevato su localhost:8080. Inizio scansione DAST...")
        test_urls = []
        for se in static_endpoints:
            path = se["path"]
            call_path = path.replace("{id}", "1").replace("{uuid}", "1")
            full_url = f"{env_zap_target.rstrip('/')}{call_path}"
            if full_url not in test_urls:
                test_urls.append(full_url)
                
        # Avviamo spider e scansioni su ZAP
        zap_client.scan_all_targets(test_urls)
        
        # Lasciamo a Mitmproxy il tempo di scrivere i log su disco
        time.sleep(2)
        
        # Leggiamo il traffico reale intercettato
        if os.path.exists(traffic_file):
            with open(traffic_file, 'r', encoding='utf-8') as f:
                raw_traffic = json.load(f)
            print(f"✅ Traffico reale intercettato da Mitmproxy caricato con successo: {len(raw_traffic)} richieste.")
    elif mitm_active:
        # Se ZAP non è attivo ma mitmproxy sì, leggiamo le chiamate dinamiche reali appena fatte!
        time.sleep(1)
        if os.path.exists(traffic_file):
            with open(traffic_file, 'r', encoding='utf-8') as f:
                raw_traffic = json.load(f)
            print(f"✅ Traffico reale delle chiamate dinamiche caricato con successo: {len(raw_traffic)} richieste.")
    else:
        print("⚠️ OWASP ZAP e Mitmproxy non rilevati localmente (offline).")
        print("➡️ Attivazione Runtime Extraction Simulator (Tesi Demo Mode) per garantire la generazione dei report...")
        raw_traffic = simulate_runtime_traffic(static_endpoints, target_host)
        
        # Scriviamo il traffico simulato nel file per coerenza architettonica
        os.makedirs(os.path.dirname(traffic_file), exist_ok=True)
        with open(traffic_file, 'w', encoding='utf-8') as f:
            json.dump(raw_traffic, f, indent=2)
        print(f"✅ Traffico simulato registrato in {traffic_file}: {len(raw_traffic)} richieste simulate.")

    # --------------------------------------------------------------------------
    # FASE 4, 5 & 6: Normalization, Correlation & OpenAPI Generation
    # --------------------------------------------------------------------------
    print("\n⚙️ [FASE 4 & 5] Endpoint Normalization & Correlation Engine...")
    correlator = APICorrelationEngine()
    unified_inventory = correlator.correlate(static_endpoints, raw_traffic)
    
    # Mostriamo a schermo il report di correlazione unificato
    print(correlator.generate_report())

    print("\n📄 [FASE 6] Generazione automatica contratti OpenAPI 3.0.0...")
    output_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "output"))
    generator = OpenAPISpecGenerator(unified_inventory, base_url=target_host)
    generator.save_specifications(output_dir)

    # Cerca ed arricchisce un file OpenAPI pre-esistente nella cartella target
    existing_spec_path = None
    for root, _, files in os.walk(target_dir):
        if any(ignored in root for ignored in ('.venv', 'venv', 'node_modules', 'output', 'src/output')):
            continue
        for file in files:
            if file in ("openapi.yaml", "openapi.yml", "openapi.json"):
                existing_spec_path = os.path.join(root, file)
                break
        if existing_spec_path:
            break
            
    if existing_spec_path:
        generator.enrich_existing_spec(existing_spec_path)

    # Scriviamo l'Unified Inventory completo in formato JSON
    inventory_file = os.path.join(output_dir, "unified_api_inventory.json")
    with open(inventory_file, 'w', encoding='utf-8') as f:
        json.dump(unified_inventory, f, indent=2, ensure_ascii=False)
        
    # Copiamo i file finali anche in una cartella root 'output' per comodità di accesso per l'utente
    root_output = os.path.abspath(os.path.join(os.path.dirname(__file__), "../output"))
    os.makedirs(root_output, exist_ok=True)
    
    # Salviamo le copie nella cartella root
    with open(os.path.join(root_output, "unified_api_inventory.json"), 'w', encoding='utf-8') as f:
        json.dump(unified_inventory, f, indent=2, ensure_ascii=False)
        
    # Generiamo specifiche anche in root
    generator.save_specifications(root_output)

    print("\n" + "="*80)
    print("🛡️ AVVIO DI SPECTRAL (API CONTRACT CONFORMANCE SCAN)...")
    print("="*80)
    target_spec_file = os.path.join(root_output, "openapi_runtime.yaml")
    spectral_findings = run_spectral(target_spec_file)
    
    # Rimuove il file temporaneo del report spettrale se creato per pulizia
    if os.path.exists("spectral_report.json"):
        os.remove("spectral_report.json")
        
    print("\n" + "="*80)
    print("🛡️ REPORT DI CONFORMITÀ CONTRATTO API (SPECTRAL LINTING)")
    print("="*80)
    if not spectral_findings:
        print("  🟢 Complimenti! Nessuna violazione contrattuale rilevata da Spectral.")
        print("     Il contratto OpenAPI 3.0 è conforme alle linee guida di sicurezza OWASP.")
    else:
        # Raggruppiamo i findings: globali vs endpoint-specifici
        global_findings = []
        endpoint_findings = {} # (endpoint, method) -> list of findings
        
        for f in spectral_findings:
            if f.api and f.api.endpoint:
                key = (f.api.endpoint, f.api.method or "GET")
                if key not in endpoint_findings:
                    endpoint_findings[key] = []
                endpoint_findings[key].append(f)
            else:
                global_findings.append(f)
                
        print(f"  Trovate {len(spectral_findings)} violazioni nel contratto OpenAPI:")
        print(f"   🌐 Violazioni Generali/Globali: {len(global_findings)}")
        print(f"   📍 Endpoint Interessati: {len(endpoint_findings)}\n")
        
        if global_findings:
            print("  🌐 VIOLAZIONI GLOBALI DELLA SPECIFICA:")
            for idx, f in enumerate(global_findings, 1):
                severity_icon = "🔴" if f.severity.name == "HIGH" else "🟡"
                line_num = (f.location.start_line + 1) if f.location.start_line is not None else "N/D"
                print(f"    {idx}. {severity_icon} [{f.rule_id}]: {f.description}")
                print(f"       ↳ Locazione: {f.location.file_path} | Linea {line_num}")
                print("    " + "-"*50)
                
        if endpoint_findings:
            print("  📍 VIOLAZIONI DETTAGLIATE PER ENDPOINT:")
            for (endpoint, method), findings in sorted(endpoint_findings.items()):
                print(f"\n    🔹 Endpoint: {method} {endpoint}")
                
                # Dividiamo in Errors (HIGH) e Warnings (MEDIUM/LOW)
                errors = [f for f in findings if f.severity.name == "HIGH"]
                warnings = [f for f in findings if f.severity.name in ("MEDIUM", "LOW")]
                
                if errors:
                    print("      🔴 ERRORI DI SICUREZZA CONTRATTUALE:")
                    for err in errors:
                        line_num = (err.location.start_line + 1) if err.location.start_line is not None else "N/D"
                        print(f"        - [{err.rule_id}]: {err.description} (Linea {line_num})")
                        
                if warnings:
                    print("      🟡 WARNING DI DOCUMENTAZIONE & QUALITÀ:")
                    for warn in warnings:
                        line_num = (warn.location.start_line + 1) if warn.location.start_line is not None else "N/D"
                        print(f"        - [{warn.rule_id}]: {warn.description} (Linea {line_num})")
                print("    " + "-"*60)

    # Genera la dashboard interattiva HTML/CSS/JS premium
    print("\n📊 GENERAZIONE DASHBOARD INTERATTIVA PREMIUM...")
    dashboard_generator = APIDashboardGenerator(unified_inventory, spectral_findings)
    
    # Salviamo in entrambe le cartelle per consistenza e facilità d'uso
    dashboard_path_1 = os.path.join(output_dir, "dashboard.html")
    dashboard_path_2 = os.path.join(root_output, "dashboard.html")
    
    dashboard_generator.generate(dashboard_path_1)
    if dashboard_path_1 != dashboard_path_2:
        dashboard_generator.generate(dashboard_path_2)

    # --------------------------------------------------------------------------
    # FASE 7: BOLA Detection & Authentication Bypass (Post-Pipeline)
    # --------------------------------------------------------------------------
    print("\n🕵️‍♂️ [FASE 7] Analisi di Sicurezza BOLA (Broken Object Level Authorization)...")
    try:
        from src.detectors.bola_analyzer import BOLAAnalyzer
        bola_analyzer = BOLAAnalyzer(traffic_file)
        bola_findings = bola_analyzer.run_analysis()
        
        if bola_findings:
            bola_report_path = os.path.join(os.path.dirname(traffic_file), "bola_report.json")
            with open(bola_report_path, 'w', encoding='utf-8') as f:
                json.dump(bola_findings, f, indent=2)
            print(f"✅ Report BOLA salvato in {bola_report_path}")
    except Exception as e:
        print(f"⚠️ Errore durante l'esecuzione dell'analisi BOLA: {e}")

    print("\n" + "="*80)
    print("🏆 PIPELINE COMPLETATA CON SUCCESSO!")
    print(f"Tutti i report ed i contratti OpenAPI sono disponibili in:\n - {output_dir}/\n - {root_output}/")
    print(f"🖥️  Dashboard Interattiva: {dashboard_path_1}")
    print("="*80)

def simulate_runtime_traffic(static_endpoints: list, target_host: str) -> list:
    """Genera traffico realistico per testare la pipeline a scopo dimostrativo."""
    traffic = []
    
    # 1. Simuliamo chiamate per gli endpoint trovati staticamente (CONFIRMED)
    for se in static_endpoints:
        path = se["path"]
        method = se["method"]
        
        # Simuliamo diverse risposte reali con parametri concreti
        dynamic_path = path.replace("{id}", "42").replace("{uuid}", "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d")
        
        # Chiamata di successo
        traffic.append({
            "source": "runtime",
            "method": method,
            "path": dynamic_path,
            "full_url": f"{target_host.rstrip('/')}{dynamic_path}",
            "status": 200,
            "query_params": {"v": "1.0"},
            "body_params": {"username": "tesi_user"} if method == "POST" else {},
            "headers": {
                "Host": "localhost:5000",
                "User-Agent": "Mozilla/5.0 (OWASP ZAP)",
                "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            },
            "response_headers": {"Content-Type": "application/json"},
            "content_type": "application/json",
            "auth_header": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        })
        
    # 2. Simuliamo una Shadow API critica / Undocumented endpoint (RUNTIME_ONLY)
    # Questa rotta NON esiste nel codice statico ed è un alert elevato di sicurezza!
    shadow_path = "/api/v1/debug/dump-database"
    traffic.append({
        "source": "runtime",
        "method": "POST",
        "path": shadow_path,
        "full_url": f"{target_host.rstrip('/')}{shadow_path}",
        "status": 200,
        "query_params": {"token": "backdoor_token"},
        "body_params": {"raw_sql": "SELECT * FROM users"},
        "headers": {
            "Host": "localhost:5000",
            "User-Agent": "Mozilla/5.0 (OWASP ZAP)"
        },
        "response_headers": {"Content-Type": "application/json"},
        "content_type": "application/json",
        "auth_header": ""
    })
    
    return traffic

if __name__ == "__main__":
    import sys
    target_dir = "."
    if len(sys.argv) > 1:
        target_dir = sys.argv[1]
        
    run_pipeline(target_dir)
