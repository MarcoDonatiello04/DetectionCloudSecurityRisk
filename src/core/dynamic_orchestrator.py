"""
Modulo Orchestratore D-AST (Dynamic Application Security Testing) per API Security Posture Management.
Implementa un flusso deterministico di validazione delle vulnerabilità BOLA (API1:2023)
e Broken Authentication (API2:2023) tramite l'integrazione di Keycloak, OWASP ZAP e Seeding Dinamico.

Architettura D-AST DevSecOps: "Discovery -> Seeding -> Attack"
------------------------------------------------------------
Nelle pipeline CI/CD tradizionali, i test DAST e i test di autorizzazione logica falliscono o producono
numerosi Falsi Negativi (FN) e Falsi Positivi (FP) a causa della mancanza di stato o di dati.
Questo approccio risolve il problema tramite tre fasi logiche:
1. DISCOVERY: Identificazione automatica degli endpoint esposti e delle rotte dinamiche (Resource-based).
   In questa fase, l'unificazione del path sotto lo standard '{id}' evita i falsi negativi nel Correlation Engine.
2. SEEDING: Popolamento deterministico dello stato in memoria dell'applicazione con risorse note
   assegnate specificamente alla vittima (User A) e all'attaccante (User B).
3. ATTACK: Esecuzione di scansioni differenziali inviando traffico reale tramite il proxy di ZAP
   e valutandone lo stato di risposta (200 OK indica vulnerabilità BOLA o Broken Auth).

Questo garantisce la replicabilità scientifica del test, azzerando le corse critiche (race conditions)
sul database di test e massimizzando la precisione di ZAP.
"""

import os
import re
import json
import logging
import base64
import time
import requests
from typing import List, Dict, Any, Tuple
from zapv2 import ZAPv2

# Allineamento con il sistema di Discovery centralizzato della Core Pipeline
from src.normalization.normalizer import APIEndpointNormalizer

# Disabilita gli alert SSL di urllib3 per le richieste passanti dal proxy di ZAP
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Configurazione logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("SecurityPlatform.DynamicAST")


# Rimosso RouteParser isolato in favore dell'integrazione diretta con l'inventario unificato.


class IdentityManager:
    """
    Gestisce la generazione e l'ottenimento dei token di sessione da Keycloak
    per impostare le identità di test deterministiche.
    """

    def __init__(self, keycloak_url: str = "http://localhost:8080", realm: str = "myrealm"):
        self.token_url = f"{keycloak_url}/realms/{realm}/protocol/openid-connect/token"
        self.client_id = "security-platform-client"

    def get_headers_for_identities(self) -> Dict[str, Dict[str, str]]:
        """
        Interagisce con Keycloak per acquisire i token per User A e User B.
        Implementa un fallback robusto con JWT fittizi se il server Keycloak locale è offline.
        """
        identities = {
            "user_a": {"username": "user_a", "password": "Password123!"},
            "user_b": {"username": "user_b", "password": "Password123!"}
        }
        
        headers_matrix = {
            "userA": {},
            "userB": {},
            "anonymous": {} # Intenzionalmente privo di header Authorization per Broken Auth
        }

        for identity_key, credentials in identities.items():
            matrix_key = "userA" if identity_key == "user_a" else "userB"
            token = self._fetch_token(credentials["username"], credentials["password"])
            
            if token:
                headers_matrix[matrix_key] = {"Authorization": f"Bearer {token}"}
            else:
                logger.warning(f"Keycloak offline o non configurato per {identity_key}. Utilizzo di un JWT di fallback.")
                mock_jwt = self._generate_mock_jwt(credentials["username"])
                headers_matrix[matrix_key] = {"Authorization": f"Bearer {mock_jwt}"}

        logger.info("Matrice degli Header delle Identità configurata con successo.")
        return headers_matrix

    def _fetch_token(self, username: str, password: str) -> str:
        """Esegue una chiamata POST standard (Resource Owner Password Credentials Grant) a Keycloak."""
        payload = {
            "client_id": self.client_id,
            "grant_type": "password",
            "username": username,
            "password": password,
            "scope": "openid"
        }
        try:
            response = requests.post(self.token_url, data=payload, timeout=3)
            if response.status_code == 200:
                return response.json().get("access_token")
        except Exception as e:
            logger.debug(f"Impossibile connettersi a Keycloak ({self.token_url}): {e}")
        return ""

    def _generate_mock_jwt(self, username: str) -> str:
        """Genera un token JWT mock base64-encoded deterministico per scopi di fallback."""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": username, 
            "name": username, 
            "preferred_username": username, 
            "roles": ["user"]
        }
        h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        signature = "mocksignature"
        return f"{h_b64}.{p_b64}.{signature}"


class DatabaseSeeder:
    """
    Componente di Automated Dynamic Seeding.
    Inietta dati dinamici nell'applicazione target prima della scansione.
    """

    def __init__(self, seed_url: str = "http://localhost:5000/test/seed"):
        self.seed_url = seed_url

    def seed_target_application(self, dynamic_endpoints: List[Dict[str, Any]]) -> bool:
        """
        Estrae le risorse dagli endpoint dinamici, genera il dataset strutturato per risorsa
        e lo inietta tramite chiamata POST all'endpoint di debug dell'applicazione target.
        """
        if not dynamic_endpoints:
            logger.info("Nessuna rotta dinamica rilevata. Seeding non necessario.")
            return True

        # Raccogliamo tutte le risorse distinte
        resources = {ep["resource_name"] for ep in dynamic_endpoints}
        
        # Generiamo il payload JSON strutturato per risorsa richiesto
        seed_payload = {}
        for res in resources:
            seed_payload[res] = {}
            # Assegna gli ID da 100 a 110 a user_a (vittima)
            for idx in range(100, 111):
                seed_payload[res][str(idx)] = "user_a"
            # Assegna gli ID da 200 a 210 a user_b (attaccante)
            for idx in range(200, 211):
                seed_payload[res][str(idx)] = "user_b"

        logger.info(f"Generato dataset sintetico strutturato per: {list(resources)}")
        
        try:
            response = requests.post(self.seed_url, json=seed_payload, timeout=5)
            if response.status_code == 200:
                logger.info("✅ Database Seeding completato con successo sull'API target.")
                return True
            else:
                logger.warning(f"⚠️ Chiamata di seeding restituita con stato {response.status_code}.")
        except Exception as e:
            logger.error(f"❌ Errore durante la chiamata di seeding a {self.seed_url}: {e}")
            
        return False


class ZapController:
    """
    Gestore per il pilotaggio programmato di OWASP ZAP (Differential Authorization Testing).
    Configura le sessioni e invia traffico tramite il proxy per la scansione differenziale.
    """

    def __init__(self, zap_proxy_url: str = "http://localhost:8090"):
        self.zap_proxy_url = zap_proxy_url
        self.zap = ZAPv2(proxies={"http": zap_proxy_url, "https": zap_proxy_url})

    def run_differential_scan(
        self, 
        target_base_url: str, 
        dynamic_endpoints: List[Dict[str, Any]], 
        headers_matrix: Dict[str, Dict[str, str]],
        output_dir: str = "output"
    ):
        """
        Pianifica ed esegue gli attacchi differenziali reali inviando traffico
        tramite il proxy di OWASP ZAP.
        """
        logger.info("🔥 Avvio test differenziale con traffico reale proxato su OWASP ZAP...")
        
        proxies = {
            "http": self.zap_proxy_url,
            "https": self.zap_proxy_url
        }

        # Configurazione contesto ZAP
        context_name = "API_Security_Context"
        try:
            self.zap.context.new_context(context_name)
            self.zap.context.include_in_context(context_name, f"{target_base_url}.*")
        except Exception as e:
            logger.debug(f"Errore creazione contesto ZAP: {e}")

        for ep in dynamic_endpoints:
            path = ep["path"]
            # Sostituiamo il parametro {id} con l'ID deterministico '100' di User A
            test_path = path.replace("{id}", "100")
            target_url = f"{target_base_url.rstrip('/')}{test_path}"

            # Convertiamo localhost in api-server (il nome del container Flask nella rete Docker compose)
            zap_target_url = target_url.replace("localhost", "api-server").replace("127.0.0.1", "api-server")

            # ------------------------------------------------------------------
            # 1. TEST BOLA: Richiesta con token di User B (Attaccante) per la risorsa di User A
            # ------------------------------------------------------------------
            logger.info(f"🧪 [BOLA Test] Invio richiesta a {zap_target_url} con token User B (Attaccante) tramite ZAP...")
            headers_b = headers_matrix["userB"]
            
            try:
                resp_b = requests.get(zap_target_url, headers=headers_b, proxies=proxies, verify=False, timeout=5)
                logger.info(f"   ↳ Risposta User B: Status={resp_b.status_code}")
                
                if resp_b.status_code == 200:
                    logger.error(f"🚨 [ALERT CRITICAL] BOLA RILEVATO SU: {target_url}")
                    logger.info("   ↳ Inoltro istruzione di Active Scan a ZAP per consolidare il finding...")
                    try:
                        self.zap.ascan.scan(url=zap_target_url, recurse="false")
                    except Exception as ze:
                        logger.debug(f"ZAP ascan fallito: {ze}")
            except Exception as e:
                logger.error(f"Errore durante il test BOLA su {target_url}: {e}")

            # ------------------------------------------------------------------
            # 2. TEST BROKEN AUTHENTICATION: Richiesta senza token (Anonymous)
            # ------------------------------------------------------------------
            logger.info(f"🧪 [Broken Auth Test] Invio richiesta a {zap_target_url} senza token (Anonymous) tramite ZAP...")
            try:
                resp_anon = requests.get(zap_target_url, proxies=proxies, verify=False, timeout=5)
                logger.info(f"   ↳ Risposta Anonymous: Status={resp_anon.status_code}")
                
                if resp_anon.status_code == 200:
                    logger.error(f"🚨 [ALERT CRITICAL] BROKEN AUTHENTICATION RILEVATA SU: {target_url}")
                    logger.info("   ↳ Inoltro istruzione di Active Scan a ZAP per consolidare il finding...")
                    try:
                        self.zap.ascan.scan(url=zap_target_url, recurse="false")
                    except Exception as ze:
                        logger.debug(f"ZAP ascan fallito: {ze}")
            except Exception as e:
                logger.error(f"Errore durante il test Broken Auth su {target_url}: {e}")

        # Attendi la conclusione degli active scan
        self._wait_for_scan_completion()
        
        # Salvataggio del report ZAP nella cartella output configurata
        report_path = os.path.join(output_dir, "zap_report.json")
        self._export_report(report_path)

    def _wait_for_scan_completion(self):
        while True:
            try:
                status = int(self.zap.ascan.status())
                logger.info(f"ZAP Active Scan in corso: {status}%")
                if status >= 100 or status < 0:
                    break
            except Exception:
                break
            time.sleep(2)
        logger.info("ZAP Active Scan completato!")

    def _export_report(self, report_path: str):
        try:
            report_data = self.zap.core.jsonreport()
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(json.dumps(report_data, indent=2, ensure_ascii=False))
            logger.info(f"✅ Report finale di ZAP salvato con successo in: {report_path}")
        except Exception as e:
            logger.error(f"Errore durante l'esportazione del report di ZAP: {e}")


class DynamicOrchestrator:
    """
    Orchestratore D-AST Principale.
    Inizializza la pipeline e coordina i moduli IdentityManager, Seeder e ZapController
    consumando direttamente l'inventario dei findings generato dalla Core Pipeline.
    """

    def __init__(
        self, 
        target_base_url: str = "http://localhost:5000",
        keycloak_url: str = "http://localhost:8080",
        zap_proxy_url: str = "http://localhost:8090"
    ):
        self.target_base_url = target_base_url
        self.identity_manager = IdentityManager(keycloak_url=keycloak_url)
        self.seeder = DatabaseSeeder(seed_url=f"{target_base_url}/test/seed")
        self.zap_controller = ZapController(zap_proxy_url=zap_proxy_url)

    def _extract_endpoints_from_inventory(self, api_inventory: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Estrae le rotte dall'inventario dei findings della pipeline,
        dividendole in dinamiche (con parametri {id}) e statiche.
        Raggruppa i metodi per ciascun percorso normalizzato.
        """
        path_to_methods = {}
        for finding in api_inventory:
            api_ctx = finding.get("api")
            if not api_ctx or not api_ctx.get("endpoint"):
                continue
                
            path = api_ctx["endpoint"]
            method = api_ctx.get("method") or "GET"
            
            # Normalizziamo il path usando lo standard centralizzato del Core
            normalized_path = APIEndpointNormalizer.normalize_path(path)
            
            if normalized_path not in path_to_methods:
                path_to_methods[normalized_path] = set()
            path_to_methods[normalized_path].add(method.upper())
            
        dynamic_endpoints = []
        static_endpoints = []
        
        for path, methods in path_to_methods.items():
            methods_list = list(methods)
            if "{id}" in path:
                # Estrae il nome logico della risorsa che precede {id}
                segments = [s for s in path.split("/") if s]
                resource_name = "generic_resource"
                for i, segment in enumerate(segments):
                    if segment == "{id}":
                        resource_name = segments[i - 1] if i > 0 else "generic_resource"
                        break
                
                dynamic_endpoints.append({
                    "path": path,
                    "methods": methods_list,
                    "resource_name": resource_name
                })
            else:
                static_endpoints.append({
                    "path": path,
                    "methods": methods_list
                })
                
        logger.info(f"Filtro endpoint da inventario completato. Trovati {len(dynamic_endpoints)} endpoint dinamici e {len(static_endpoints)} statici.")
        return dynamic_endpoints, static_endpoints

    def run_dast_pipeline(self, api_inventory: List[Dict[str, Any]], output_dir: str = "output"):
        logger.info("🚀 Avvio Pipeline di Automazione D-AST...")

        # 1. Estrazione & Raggruppamento Endpoint da Inventario Pipeline
        dynamic_eps, static_eps = self._extract_endpoints_from_inventory(api_inventory)

        # 2. Identity Provisioning (Keycloak)
        headers_matrix = self.identity_manager.get_headers_for_identities()

        # 3. Dynamic Database Seeding
        seeding_success = self.seeder.seed_target_application(dynamic_eps)
        if not seeding_success:
            logger.warning("Procedo con il test DAST anche se il seeding dinamico ha rilevato degli avvisi.")

        # 4. Differential Scan & Authorization Testing
        self.zap_controller.run_differential_scan(
            target_base_url=self.target_base_url,
            dynamic_endpoints=dynamic_eps,
            headers_matrix=headers_matrix,
            output_dir=output_dir
        )

        logger.info("🏆 Pipeline D-AST completata con successo!")


if __name__ == "__main__":
    # Esempio di esecuzione manuale standalone o caricamento dell'ultimo inventario
    import os
    inventory_path = "output/unified_api_inventory.json"
    if os.path.exists(inventory_path):
        logger.info(f"Caricamento inventario esistente da {inventory_path} per esecuzione standalone...")
        with open(inventory_path, "r", encoding="utf-8") as f:
            api_inventory = json.load(f)
    else:
        logger.info("Nessun inventario trovato. Utilizzo di un inventario mock per test standalone...")
        # Generiamo dei mock findings che assomigliano alla struttura reale dei findings della pipeline
        api_inventory = [
            {
                "api": {"endpoint": "/api/orders/<order_id>", "method": "GET"}
            },
            {
                "api": {"endpoint": "/api/orders/<order_id>", "method": "POST"}
            },
            {
                "api": {"endpoint": "/api/profile", "method": "GET"}
            },
            {
                "api": {"endpoint": "/api/invoices/{invoice_id}", "method": "GET"}
            }
        ]
    
    orchestrator = DynamicOrchestrator()
    orchestrator.run_dast_pipeline(api_inventory)
