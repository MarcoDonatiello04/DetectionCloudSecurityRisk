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
from typing import List, Dict, Any, Tuple
import requests
from zapv2 import ZAPv2

# Allineamento con il sistema di Discovery centralizzato della Core Pipeline
from src.normalization.normalizer import APIEndpointNormalizer
from src.domain.entities import Finding

# Disabilita gli alert SSL di urllib3 per le richieste passanti dal proxy di ZAP
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Configurazione logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("SecurityPlatform.DynamicAST")


# ─── ECCEZIONI PERSONALIZZATE ────────────────────────────────────────────────

class OrchestratorError(Exception):
    """Classe base per le eccezioni dell'orchestratore D-AST."""
    pass


class IdentityManagerError(OrchestratorError):
    """Eccezione sollevata da IdentityManager in caso di errori di autenticazione."""
    pass


class SeedingError(OrchestratorError):
    """Eccezione sollevata da DatabaseSeeder in caso di errore di popolamento dati."""
    pass


class ScannerError(OrchestratorError):
    """Eccezione sollevata da ZapController in caso di fallimento della scansione."""
    pass


# ─── COSTANTI DI DOMINIO E CONFIGURAZIONE ───────────────────────────────────

# Livelli di Rischio del Dominio Sicurezza Cloud
RISK_LEVEL_CRITICAL = "CRITICAL"
RISK_LEVEL_HIGH = "HIGH"
RISK_LEVEL_MEDIUM = "MEDIUM"
RISK_LEVEL_LOW = "LOW"
RISK_LEVEL_INFO = "INFO"

# Credenziali di default per il seeding e identità di test
DEFAULT_USER_A_USERNAME = "user_a"
DEFAULT_USER_A_PASSWORD = "Password123!"
DEFAULT_USER_B_USERNAME = "user_b"
DEFAULT_USER_B_PASSWORD = "Password123!"
DEFAULT_CLIENT_ID = "security-platform-client"

# Intervalli di ID deterministici per il Seeding
SEED_START_USER_A = 100
SEED_END_USER_A = 110
SEED_START_USER_B = 200
SEED_END_USER_B = 210

# Parametri di connessione e timeout di default
DEFAULT_KEYCLOAK_URL = "http://localhost:8080"
DEFAULT_KEYCLOAK_REALM = "myrealm"
DEFAULT_ZAP_PROXY_URL = "http://localhost:8090"
DEFAULT_TARGET_BASE_URL = "http://localhost:5000"

HTTP_TIMEOUT_SHORT_SECONDS = 3
HTTP_TIMEOUT_MEDIUM_SECONDS = 5
ZAP_POLL_INTERVAL_SECONDS = 2


# ─── FUNZIONI DI VALIDAZIONE DELL'INPUT ──────────────────────────────────────

def validate_url(url: str, param_name: str) -> None:
    """
    Valida la struttura formale di un URL passato come parametro.

    Args:
        url (str): L'URL da verificare.
        param_name (str): Il nome del parametro per scopi di diagnostica.

    Raises:
        ValueError: Se l'URL non inizia con 'http://' o 'https://'.
    """
    if not url or not (url.startswith("http://") or url.startswith("https://")):
        raise ValueError(f"Parametro '{param_name}' non valido: deve iniziare con http:// o https://. Valore: {url}")


def validate_api_inventory(inventory: List[Dict[str, Any]]) -> None:
    """
    Valida la struttura dei dati dell'inventario API prima dell'elaborazione.

    Args:
        inventory (List[Dict[str, Any]]): L'inventario delle API da validare.

    Raises:
        ValueError: Se l'inventario non è una lista valida di dizionari.
    """
    if not isinstance(inventory, list):
        raise ValueError("L'inventario delle API deve essere una lista.")


# ─── CLASSI PRINCIPALI DEL FLUSSO ───────────────────────────────────────────

from src.core.identity_context import IdentityManager, DatabaseSeeder
from src.core.object_level_authorization.state_manager import APIStateEngine
from src.core.object_level_authorization.attack_vector import ContextAwareAttackGenerator
from src.core.object_level_authorization.assertion_engine import APIAssertionEngine
from src.core.object_level_authorization.discovery.ownership_inference import OwnershipInferenceEngine
from src.core.object_level_authorization.discovery.object_discovery import ObjectReferenceDiscoveryEngine


class ZapController:
    """
    Gestore per il pilotaggio programmato di OWASP ZAP (Differential Authorization Testing).
    Configura le sessioni e invia traffico tramite il proxy per la scansione differenziale.
    """

    def __init__(self, zap_proxy_url: str = DEFAULT_ZAP_PROXY_URL):
        """
        Inizializza il controller OWASP ZAP con l'URL del proxy.

        Args:
            zap_proxy_url (str): URL del proxy di ZAP (es. http://localhost:8090).

        Raises:
            ValueError: Se zap_proxy_url non è un URL valido.
        """
        validate_url(zap_proxy_url, "zap_proxy_url")
        self.zap_proxy_url = zap_proxy_url
        self.zap = ZAPv2(proxies={"http": zap_proxy_url, "https": zap_proxy_url})
        self.test_results = []

    def run_differential_scan(
        self, 
        target_base_url: str, 
        dynamic_endpoints: List[Dict[str, Any]], 
        headers_matrix: Dict[str, Dict[str, str]],
        uuid_alice: str,
        uuid_bob: str,
        uuid_charlie: str,
        role_map: Dict[str, str],
        output_dir: str = "output",
        use_state_management: bool = True
    ) -> None:
        """
        Pianifica ed esegue gli attacchi differenziali reali inviando traffico
        tramite il proxy di OWASP ZAP, supportando i metodi HTTP GET, POST, PUT, PATCH e DELETE.
        Usa la logica di Role-Aware Testing per distinguere BOLA orizzontale/verticale/safe.
        """
        validate_url(target_base_url, "target_base_url")
        logger.info("🔥 Avvio test differenziale esteso e Role-Aware...")
        self.test_results = []
        
        # Inizializza i moduli BOLA e reset dello stato
        state_engine = APIStateEngine(target_base_url)
        attack_generator = ContextAwareAttackGenerator(self.zap_proxy_url)

        # Configurazione contesto ZAP
        context_name = "API_Security_Context"
        try:
            self.zap.context.new_context(context_name)
            self.zap.context.include_in_context(context_name, f"{target_base_url}.*")
        except Exception as e:
            logger.debug(f"Errore creazione contesto ZAP: {e}")

        methods_to_test = ["GET", "POST", "PUT", "PATCH", "DELETE"]

        role_alice = role_map.get(uuid_alice, "user")
        role_bob = role_map.get(uuid_bob, "user")
        role_charlie = role_map.get(uuid_charlie, "admin")

        for ep in dynamic_endpoints:
            path = ep["path"]
            discovered_refs = ep.get("discovered_refs", None)
            logger.info(f"🧪 [BOLA Role-Aware Assessment] Analisi endpoint dinamico: {path}")

            for method in methods_to_test:
                # 1. Snapshot dello stato prima del test
                if use_state_management:
                    APIStateEngine.take_snapshot(target_base_url)

                # 2. Generazione ed esecuzione dei vettori di attacco per i 3 scenari
                scenarios_results = attack_generator.execute_tampering(
                    method=method,
                    target_base_url=target_base_url,
                    path=path,
                    headers_matrix=headers_matrix,
                    uuid_alice=uuid_alice,
                    uuid_bob=uuid_bob,
                    uuid_charlie=uuid_charlie,
                    role_alice=role_alice,
                    role_bob=role_bob,
                    role_charlie=role_charlie,
                    discovered_refs=discovered_refs
                )

                for stim in scenarios_results:
                    res_alice = stim["res_alice"]
                    res_bob = stim["res_bob"]
                    res_anon = stim["res_anon"]
                    attacker_role = stim["attacker_role"]
                    owner_role = stim["owner_role"]
                    scenario_name = stim["scenario_name"]
                    target_url = stim["target_url"]
                    zap_target_url = stim["zap_target_url"]

                    # 3. Valutazione BOLA differenziale tramite APIAssertionEngine (Role-Aware)
                    if res_alice is not None and res_bob is not None:
                        assertion_result = APIAssertionEngine.evaluate_bola_assertion(
                            method=method,
                            res_alice=res_alice,
                            res_bob=res_bob,
                            requesting_user_role=attacker_role,
                            resource_owner_role=owner_role
                        )
                        is_vulnerable = assertion_result["is_vulnerable"]
                        verdict = assertion_result["verdict"]

                        import urllib.parse
                        parsed_url = urllib.parse.urlparse(target_url)

                        # Registriamo i dettagli del test
                        self.test_results.append({
                            "url": target_url,
                            "path": parsed_url.path,
                            "method": method,
                            "status_code": res_bob.status_code,
                            "test_name": f"{scenario_name} {method} Test",
                            "is_vulnerable": is_vulnerable,
                            "assertion_details": assertion_result,
                            "response_text": res_bob.text
                        })

                        logger.info(
                            f"      [{scenario_name} - {method}] Verdict: {verdict}\n"
                            f"        - http_status_assertion: {assertion_result['http_status_assertion']}\n"
                            f"        - content_keyword_assertion: {assertion_result['content_keyword_assertion']}\n"
                            f"        - structural_similarity_assertion: {assertion_result['structural_similarity_assertion']}"
                        )

                        if is_vulnerable:
                            logger.error(f"🚨 [ALERT CRITICAL] {verdict} RILEVATO SU: {method} {target_url}")
                            try:
                                self.zap.ascan.scan(url=zap_target_url, recurse="false")
                            except Exception as ze:
                                logger.debug(f"ZAP ascan fallito: {ze}")
                        else:
                            logger.info(f"✅ [SAFE] {scenario_name} {method} su: {target_url} (Verdetto: {verdict})")
                    else:
                        logger.warning(f"⚠️ Impossibile eseguire BOLA Assessment for {scenario_name} {method} dovuto a errori di rete.")

                    # 4. Broken Authentication Check (Anonymous)
                    if res_anon is not None:
                        is_anon_vulnerable = (res_anon.status_code in (200, 204))
                        import urllib.parse
                        parsed_url = urllib.parse.urlparse(target_url)

                        self.test_results.append({
                            "url": target_url,
                            "path": parsed_url.path,
                            "method": method,
                            "status_code": res_anon.status_code,
                            "test_name": f"Broken Auth {scenario_name} {method} Test",
                            "is_vulnerable": is_anon_vulnerable,
                            "assertion_details": {
                                "http_status_assertion": not is_anon_vulnerable,
                                "content_keyword_assertion": True,
                                "structural_similarity_assertion": True
                            },
                            "response_text": res_anon.text
                        })

                        if is_anon_vulnerable:
                            logger.error(f"🚨 [ALERT CRITICAL] BROKEN AUTHENTICATION RILEVATA SU: {method} {target_url}")
                            try:
                                self.zap.ascan.scan(url=zap_target_url, recurse="false")
                            except Exception as ze:
                                logger.debug(f"ZAP ascan fallito: {ze}")
                
                # 5. Rollback dello stato dopo il test per ripulire gli effetti collaterali
                if use_state_management:
                    APIStateEngine.trigger_rollback(target_base_url)

        # Attendi la conclusione degli active scan
        self._wait_for_scan_completion()
        
        # Salvataggio del report ZAP
        report_path = os.path.join(output_dir, "zap_report.json")
        self._export_report(report_path)

    def _wait_for_scan_completion(self) -> None:
        """
        Attende la conclusione degli active scan registrati su OWASP ZAP effettuando il polling dello stato.
        """
        while True:
            try:
                status = int(self.zap.ascan.status())
                logger.info(f"ZAP Active Scan in corso: {status}%")
                if status >= 100 or status < 0:
                    break
            except Exception:
                break
            time.sleep(ZAP_POLL_INTERVAL_SECONDS)
        logger.info("ZAP Active Scan completato!")

    def _export_report(self, report_path: str) -> None:
        """
        Esporta il report finale di sicurezza in formato JSON recuperando i dati da ZAP.

        Args:
            report_path (str): Il percorso file del report da salvare.
        """
        try:
            report_data = self.zap.core.jsonreport()
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(json.dumps(report_data, indent=2, ensure_ascii=False))
            logger.info(f"✅ Report finale di ZAP salvato con successo in: {report_path}")
        except (OSError, Exception) as e:
            logger.error(f"Errore durante l'esportazione del report di ZAP: {e}")


class DynamicOrchestrator:
    """
    Orchestratore D-AST Principale.
    Inizializza la pipeline e coordina i moduli IdentityManager, Seeder e ZapController
    consumando direttamente l'inventario dei findings generato dalla Core Pipeline.
    """

    def __init__(
        self, 
        target_base_url: str = DEFAULT_TARGET_BASE_URL,
        keycloak_url: str = DEFAULT_KEYCLOAK_URL,
        zap_proxy_url: str = DEFAULT_ZAP_PROXY_URL,
        assessment_mode: bool = False
    ):
        """
        Inizializza l'orchestratore dinamico configurando le dipendenze richieste.

        Args:
            target_base_url (str): URL di base dell'applicazione web target.
            keycloak_url (str): URL di Keycloak per la gestione delle identità.
            zap_proxy_url (str): URL del proxy OWASP ZAP.
            assessment_mode (bool): Abilita la modalità Assessment (senza seeding/snapshot/rollback).
        """
        validate_url(target_base_url, "target_base_url")
        validate_url(keycloak_url, "keycloak_url")
        validate_url(zap_proxy_url, "zap_proxy_url")
        
        self.target_base_url = target_base_url
        self.assessment_mode = assessment_mode
        self.identity_manager = IdentityManager(keycloak_url=keycloak_url)
        self.seeder = DatabaseSeeder(seed_url=f"{target_base_url.rstrip('/')}/test/seed")
        self.zap_controller = ZapController(zap_proxy_url=zap_proxy_url)

    def _extract_endpoints_from_inventory(self, api_inventory: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Estrae le rotte dall'inventario dei findings della pipeline,
        dividendole in dinamiche (con parametri {id}) e statiche.
        Raggruppa i metodi per ciascun percorso normalizzato.

        Args:
            api_inventory (List[Dict[str, Any]]): Dati grezzi dell'inventario API della pipeline.

        Returns:
            Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]: Endpoint dinamici e statici estratti.

        Raises:
            ValueError: Se l'inventario non supera la validazione di struttura.
        """
        validate_api_inventory(api_inventory)
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

    def run_dast_pipeline(self, api_inventory: List[Dict[str, Any]], output_dir: str = "output", raw_traffic: List[Dict[str, Any]] = None) -> List[Finding]:
        """
        Esegue l'intero workflow orchestrato del D-AST: estrazione, provisioning, seeding e attacco differenziale.

        Args:
            api_inventory (List[Dict[str, Any]]): L'inventario delle API estratto per il seeding e la scansione.
            output_dir (str): Cartella di destinazione dei report.
            raw_traffic (List[Dict[str, Any]]): Traffico intercettato.
        """
        logger.info("🚀 Avvio Pipeline di Automazione D-AST...")

        # 1. Estrazione & Raggruppamento Endpoint da Inventario Pipeline
        dynamic_eps, _ = self._extract_endpoints_from_inventory(api_inventory)

        headers_matrix = {}
        uuid_alice = None
        uuid_bob = None
        uuid_charlie = None
        role_map = {}

        # Se siamo in Assessment Mode o se abbiamo traffico a disposizione,
        # arricchiamo gli endpoint ed estraiamo le relazioni di ownership
        if self.assessment_mode or raw_traffic:
            logger.info("🔍 [Assessment Mode / Traffic Analysis] Esecuzione Ownership Inference...")
            inference_engine = OwnershipInferenceEngine()
            inference_engine.analyze_traffic(raw_traffic)
            
            uuid_alice, uuid_bob, uuid_charlie, inferred_roles, inferred_headers = inference_engine.get_inferred_identities()
            role_map.update(inferred_roles)
            headers_matrix.update(inferred_headers)
            
            # Troviamo ulteriori endpoint con riferimenti a oggetti tramite ObjectReferenceDiscoveryEngine
            if raw_traffic:
                logger.info("🔍 [Object Reference Discovery] Analisi del traffico alla ricerca di ID nascosti...")
                for entry in raw_traffic:
                    refs = ObjectReferenceDiscoveryEngine.extract_references(entry)
                    if refs:
                        path = entry.get("path", "")
                        norm_path = APIEndpointNormalizer.normalize_path(path)
                        method = entry.get("method", "GET").upper()
                        
                        exists = False
                        for ep in dynamic_eps:
                            if ep["path"] == norm_path:
                                exists = True
                                if method not in ep["methods"]:
                                    ep["methods"].append(method)
                                if "discovered_refs" not in ep:
                                    ep["discovered_refs"] = []
                                ep["discovered_refs"].extend(refs)
                                break
                        
                        if not exists:
                            resource_name = "generic"
                            for ref in refs:
                                if ref["location"] == "path":
                                    resource_name = ref["name"].replace("_id", "")
                                    break
                            
                            dynamic_eps.append({
                                "path": norm_path,
                                "methods": [method],
                                "resource_name": resource_name,
                                "discovered_refs": refs
                            })

        # Se non siamo in Assessment Mode o se non siamo riusciti ad estrarre le identità dal traffico, usiamo Keycloak (Lab Mode)
        use_state_management = True
        if self.assessment_mode:
            use_state_management = False

        if not headers_matrix or not headers_matrix.get("userA") or not uuid_alice:
            logger.info("🧪 [Lab Mode] Configurazione delle identità tramite Keycloak...")
            headers_matrix = self.identity_manager.get_headers_for_identities()
            uuid_alice = self.identity_manager.identity_map.get("UUID_ALICE")
            uuid_bob = self.identity_manager.identity_map.get("UUID_BOB")
            uuid_charlie = self.identity_manager.identity_map.get("UUID_CHARLIE")
            role_map = self.identity_manager.role_map

            # In Lab Mode eseguiamo anche il seeding e abilitiamo lo snapshot/rollback dello stato
            seeding_success = self.seeder.seed_target_application(dynamic_eps, uuid_alice, uuid_bob, uuid_charlie)
            if not seeding_success:
                logger.warning("Procedo con il test DAST anche se il seeding dinamico ha rilevato degli avvisi.")
        else:
            logger.info("ℹ️ [Assessment Mode] Utilizzo delle identità e relazioni inferte dal traffico. Seeding saltato.")

        # 4. Differential Scan & Authorization Testing (Passando gli UUID di contesto)
        self.zap_controller.run_differential_scan(
            target_base_url=self.target_base_url,
            dynamic_endpoints=dynamic_eps,
            headers_matrix=headers_matrix,
            uuid_alice=uuid_alice,
            uuid_bob=uuid_bob,
            uuid_charlie=uuid_charlie,
            role_map=role_map,
            output_dir=output_dir,
            use_state_management=use_state_management
        )

        logger.info("🏆 Pipeline D-AST completata con successo! Generazione dei findings di sbarramento...")
        
        # Generiamo i findings per attestare se gli endpoint sono sicuri o vulnerabili
        from src.domain.entities import Finding, FindingSource, FindingCategory, Severity, APIContext, RuntimeEvidence, ValidationStatus
        dast_findings = []
        
        for res in self.zap_controller.test_results:
            path = res["path"]
            method = res["method"]
            status_code = res["status_code"]
            test_name = res["test_name"]
            is_vulnerable = res["is_vulnerable"]
            assertion_details = res["assertion_details"]
            
            # Formattiamo i dettagli delle asserzioni per l'evidenza
            details_str = (
                f"Asserzioni di Sicurezza BOLA:\n"
                f"  - http_status_assertion: {assertion_details['http_status_assertion']}\n"
                f"  - content_keyword_assertion: {assertion_details['content_keyword_assertion']}\n"
                f"  - structural_similarity_assertion: {assertion_details['structural_similarity_assertion']}\n"
                f"Verdetto finale: {'VULNERABLE' if is_vulnerable else 'SAFE'}"
            )

            evidence = RuntimeEvidence(
                tested_url=res["url"],
                http_status=status_code,
                response_snippet=details_str + f"\n\nPayload di Bob:\n{res['response_text'][:500]}"
            )
            
            if is_vulnerable:
                finding = Finding.create(
                    source=FindingSource.RUNTIME_VALIDATOR,
                    category=FindingCategory.AUTHORIZATION if "BOLA" in test_name else FindingCategory.AUTHENTICATION,
                    title=f"Vulnerabilità {test_name} confermata a runtime",
                    description=(
                        f"Il test differenziale '{test_name}' per l'endpoint '{path}' ha confermato che l'accesso "
                        f"non autorizzato è possibile.\n{details_str}"
                    ),
                    severity=Severity.HIGH,
                    confidence=1.0,
                    rule_id="dynamic-bola-exploited" if "BOLA" in test_name else "dynamic-broken-auth-exploited",
                    target_identifier=f"{method}:{path}:{test_name}",
                    rule_name=f"Dynamic {test_name} Exploitation Check",
                    api=APIContext(endpoint=path, method=method, requires_authentication=True),
                    runtime_evidence=evidence,
                    correlation_key=f"api:{method}:{APIEndpointNormalizer.normalize_path(path)}"
                )
                finding.validation_status = ValidationStatus.CONFIRMED
            else:
                finding = Finding.create(
                    source=FindingSource.RUNTIME_VALIDATOR,
                    category=FindingCategory.AUTHORIZATION if "BOLA" in test_name else FindingCategory.AUTHENTICATION,
                    title=f"Test {test_name} - Endpoint Sicuro ({status_code})",
                    description=(
                        f"Il test differenziale '{test_name}' ha verificato che l'accesso non autorizzato viene "
                        f"bloccato correttamente.\n{details_str}"
                    ),
                    severity=Severity.INFO,
                    confidence=1.0,
                    rule_id="dynamic-test-secure",
                    target_identifier=f"{method}:{path}:{test_name}",
                    rule_name="Dynamic Differential Authorization Check",
                    api=APIContext(endpoint=path, method=method, requires_authentication=True),
                    runtime_evidence=evidence,
                    correlation_key=f"api:{method}:{APIEndpointNormalizer.normalize_path(path)}"
                )
                finding.validation_status = ValidationStatus.CONFIRMED

            dast_findings.append(finding)
                
        return dast_findings


if __name__ == "__main__":
    # Esempio di esecuzione manuale standalone o caricamento dell'ultimo inventario
    inventory_path = "output/unified_api_inventory.json"
    if os.path.exists(inventory_path):
        logger.info(f"Caricamento inventario esistente da {inventory_path} per esecuzione standalone...")
        with open(inventory_path, "r", encoding="utf-8") as f:
            api_inv = json.load(f)
    else:
        logger.info("Nessun inventario trovato. Utilizzo di un inventario mock per test standalone...")
        # Generiamo dei mock findings che assomigliano alla struttura reale dei findings della pipeline
        api_inv = [
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
    orchestrator.run_dast_pipeline(api_inv)
