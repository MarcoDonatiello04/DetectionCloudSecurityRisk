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

import json
import logging
import os
import threading
import time
from typing import Any

import requests
from zapv2 import ZAPv2

from src.core.api1_bola.assertion_engine import APIAssertionEngine
from src.core.api1_bola.attack_vector import ContextAwareAttackGenerator, IdentityProfile
from src.core.api1_bola.discovery.object_discovery import (
    ObjectReferenceDiscoveryEngine,
)
from src.core.api1_bola.discovery.ownership_inference import (
    OwnershipInferenceEngine,
)
from src.core.api1_bola.state_manager import APIStateEngine
from src.core.api1_bola.target_config import (
    DEFAULT_HARNESS_ROLLBACK_PATH,
    DEFAULT_HARNESS_SNAPSHOT_PATH,
    DEFAULT_ZAP_INTERNAL_HOST,
    IDENTITY_KEYS,
    IDENTITY_PEER,
    IDENTITY_PRIVILEGED,
    IDENTITY_VICTIM,
    BolaTargetConfig,
    get_bola_target_config,
)
from src.core.config import (
    DEFAULT_ZAP_URL as DEFAULT_ZAP_PROXY_URL,
)
from src.core.config import (
    ZAP_ACTIVE_SCAN_TIMEOUT_SECONDS,
    ZAP_POLL_INTERVAL_SECONDS,
)
from src.core.identity_context import DatabaseSeeder, IdentityManager
from src.domain.entities import Finding
from src.normalization.normalizer import APIEndpointNormalizer

# Allineamento con il sistema di Discovery centralizzato della Core Pipeline

# Disabilita gli alert SSL di urllib3 per le richieste passanti dal proxy di ZAP
requests.packages.urllib3.disable_warnings(  # type: ignore[attr-defined]
    requests.packages.urllib3.exceptions.InsecureRequestWarning  # type: ignore[attr-defined]
)

# Configurazione logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)-35s: %(message)s",
    datefmt="%H:%M:%S",
)
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


class TargetUnreachableError(OrchestratorError):
    """Il target cooperante non risponde su /test/snapshot: la fase D-AST non puo' partire."""

    pass


# ─── COSTANTI DI DOMINIO E CONFIGURAZIONE ───────────────────────────────────

# Livelli di Rischio del Dominio Sicurezza Cloud
RISK_LEVEL_CRITICAL = "CRITICAL"
RISK_LEVEL_HIGH = "HIGH"
RISK_LEVEL_MEDIUM = "MEDIUM"
RISK_LEVEL_LOW = "LOW"
RISK_LEVEL_INFO = "INFO"

# Metodi HTTP supportati dal test differenziale, nell'ordine in cui vengono esercitati.
ALL_HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
# Metodi che possono alterare lo stato del target: solo per questi ha senso lo snapshot/rollback.
STATE_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
# Metodi esclusi di default in Assessment Mode (nessun rollback possibile): modificano o
# distruggono risorse reali. `--allow-mutations` li riabilita esplicitamente.
ASSESSMENT_EXCLUDED_METHODS = frozenset({"PUT", "PATCH", "DELETE"})
# Placeholder dei parametri di path nell'inventario normalizzato
ID_PLACEHOLDER = "{id}"


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
        raise ValueError(
            f"Parametro '{param_name}' non valido: deve iniziare con http:// o https://. Valore: {url}"
        )


def ensure_target_reachable(
    target_base_url: str,
    timeout: float = 5.0,
    snapshot_path: str = DEFAULT_HARNESS_SNAPSHOT_PATH,
) -> None:
    """
    Verifica che il target cooperante sia raggiungibile PRIMA di avviare la fase D-AST.

    L'endpoint di snapshot e' il contratto minimo dell'harness cooperante (seeding,
    snapshot e rollback): se non risponde 200 gli attacchi differenziali produrrebbero
    solo errori di connessione silenziosi, spacciati per "endpoint sicuri".

    Args:
        target_base_url (str): URL di base dell'applicazione target.
        timeout (float): Timeout in secondi della richiesta di verifica.
        snapshot_path (str): Path dell'endpoint di snapshot (``harness.snapshot`` del contratto).

    Raises:
        TargetUnreachableError: Se il target non risponde o risponde con status != 200.
    """
    snapshot_url = f"{target_base_url.rstrip('/')}/{snapshot_path.lstrip('/')}"
    try:
        response = requests.get(snapshot_url, timeout=timeout)
    except requests.RequestException as exc:
        raise TargetUnreachableError(
            f"Target non raggiungibile su {snapshot_url}: {exc}. "
            "Verifica che il container api-server sia attivo (docker compose up -d api-server) "
            "e che TARGET_DIR punti a una repo cooperante che espone /test/snapshot."
        ) from exc
    if response.status_code != 200:
        raise TargetUnreachableError(
            f"Target su {snapshot_url} ha risposto HTTP {response.status_code} (atteso 200): "
            "la repo montata in api-server non espone l'harness cooperante "
            "(/test/seed, /test/snapshot, /test/rollback)."
        )
    logger.info(f"✅ Target cooperante raggiungibile: {snapshot_url}")


def validate_api_inventory(inventory: list[dict[str, Any]]) -> None:
    """
    Valida la struttura dei dati dell'inventario API prima dell'elaborazione.

    Args:
        inventory (List[Dict[str, Any]]): L'inventario delle API da validare.

    Raises:
        ValueError: Se l'inventario non è una lista valida di dizionari.
    """
    if not isinstance(inventory, list):
        raise ValueError("L'inventario delle API deve essere una lista.")


def describe_dynamic_path(path: str) -> dict[str, Any]:
    """
    Descrive un path normalizzato con parametri ``{id}``: la risorsa bersaglio è quella
    che precede l'ULTIMO placeholder (nei path annidati l'oggetto attaccato è il figlio).

    Args:
        path (str): Path normalizzato, es. ``/api/users/{id}/projects/{id}``.

    Returns:
        dict: ``resource_name`` (``projects``), ``nested`` (True se più di un ``{id}``)
            e ``id_params`` (numero di placeholder).
    """
    segments = [s for s in path.split("/") if s]
    id_positions = [i for i, seg in enumerate(segments) if seg == ID_PLACEHOLDER]
    resource_name = "generic_resource"
    if id_positions and id_positions[-1] > 0:
        resource_name = segments[id_positions[-1] - 1]
    return {
        "resource_name": resource_name,
        "nested": len(id_positions) > 1,
        "id_params": len(id_positions),
    }


# ─── CLASSI PRINCIPALI DEL FLUSSO ───────────────────────────────────────────


class ZapController:
    """
    Gestore per il pilotaggio programmato di OWASP ZAP (Differential Authorization Testing).
    Configura le sessioni e invia traffico tramite il proxy per la scansione differenziale.
    """

    def __init__(
        self,
        zap_proxy_url: str = DEFAULT_ZAP_PROXY_URL,
        cancel_event: threading.Event | None = None,
        zap_internal_host: str = DEFAULT_ZAP_INTERNAL_HOST,
        snapshot_path: str = DEFAULT_HARNESS_SNAPSHOT_PATH,
        rollback_path: str = DEFAULT_HARNESS_ROLLBACK_PATH,
    ):
        """
        Inizializza il controller OWASP ZAP con l'URL del proxy.

        Args:
            zap_proxy_url (str): URL del proxy di ZAP (es. http://localhost:8090).
            cancel_event (threading.Event | None): Segnale di cancellazione proprio di questa
                istanza. Se assente ne viene creato uno nuovo: due scansioni concorrenti non
                condividono mai lo stato di cancellazione.
            zap_internal_host (str): Host con cui il container di ZAP raggiunge il bersaglio.
            snapshot_path (str): Path dell'endpoint di snapshot dell'harness cooperante.
            rollback_path (str): Path dell'endpoint di rollback dell'harness cooperante.

        Raises:
            ValueError: Se zap_proxy_url non è un URL valido.
        """
        validate_url(zap_proxy_url, "zap_proxy_url")
        self.zap_proxy_url = zap_proxy_url
        self.zap_internal_host = zap_internal_host
        self.snapshot_path = snapshot_path
        self.rollback_path = rollback_path
        self.zap = ZAPv2(proxies={"http": zap_proxy_url, "https": zap_proxy_url})
        self.test_results = []
        self.cancel_event = cancel_event or threading.Event()

    def cancel(self) -> None:
        """Richiede l'interruzione cooperativa della scansione in corso su questa istanza."""
        self.cancel_event.set()

    @property
    def is_cancelled(self) -> bool:
        return self.cancel_event.is_set()

    @staticmethod
    def _select_methods(endpoint: dict[str, Any], test_all_methods: bool) -> list[str]:
        """
        Sceglie i metodi HTTP da esercitare su un endpoint: quelli dichiarati dall'inventario
        (fallback GET) oppure, se richiesto, l'intero set supportato. L'ordine segue
        ALL_HTTP_METHODS per rendere deterministica la sequenza dei test.
        """
        if test_all_methods:
            return list(ALL_HTTP_METHODS)
        declared = {str(m).upper() for m in (endpoint.get("methods") or [])}
        selected = [m for m in ALL_HTTP_METHODS if m in declared]
        return selected or ["GET"]

    @staticmethod
    def _without_mutations(methods: list[str], state_managed: bool, allow: bool) -> list[str]:
        """
        Senza snapshot/rollback (Assessment Mode) i metodi che alterano risorse reali
        vengono esclusi, salvo consenso esplicito (`allow_mutations`).
        """
        if state_managed or allow:
            return methods
        return [m for m in methods if m not in ASSESSMENT_EXCLUDED_METHODS]

    @staticmethod
    def _build_profiles(
        identity_uuids: dict[str, str | None],
        role_map: dict[str, str],
        usernames: dict[str, str] | None,
    ) -> dict[str, IdentityProfile]:
        """Profilo (ruolo, username, uuid) di ciascuna identità logica per il generatore."""
        default_roles = {
            IDENTITY_VICTIM: "user",
            IDENTITY_PEER: "user",
            IDENTITY_PRIVILEGED: "admin",
        }
        usernames = usernames or {}
        profiles = {}
        for key in IDENTITY_KEYS:
            uid = identity_uuids.get(key) or ""
            profiles[key] = IdentityProfile(
                role=role_map.get(uid, default_roles[key]),
                username=usernames.get(key, ""),
                uuid=uid,
            )
        return profiles

    def run_differential_scan(
        self,
        target_base_url: str,
        dynamic_endpoints: list[dict[str, Any]],
        headers_matrix: dict[str, dict[str, str]],
        identity_uuids: dict[str, str | None],
        role_map: dict[str, str],
        output_dir: str = "output",
        use_state_management: bool = True,
        test_all_methods: bool = False,
        resource_ids: dict[str, dict[str, str]] | None = None,
        usernames: dict[str, str] | None = None,
        allow_mutations: bool = True,
    ) -> None:
        """
        Pianifica ed esegue gli attacchi differenziali reali inviando traffico
        tramite il proxy di OWASP ZAP, supportando i metodi HTTP GET, POST, PUT, PATCH e DELETE.
        Usa la logica di Role-Aware Testing per distinguere BOLA orizzontale/verticale/safe.

        Per ogni endpoint vengono esercitati solo i metodi dichiarati dall'inventario
        (`test_all_methods=True` forza l'intero set); lo snapshot/rollback dello stato viene
        eseguito solo per i metodi che possono mutarlo (vedi STATE_MUTATING_METHODS). Senza
        gestione dello stato, PUT/PATCH/DELETE sono esclusi salvo `allow_mutations`.

        Args:
            identity_uuids (dict): Ruolo logico (victim/peer/privileged) -> claim ``sub``.
            resource_ids (dict | None): ``{resource_name: {ruolo_logico: id}}`` degli ID creati
                dal seeding (o osservati nel traffico); in assenza si usa l'UUID dell'identità.
            usernames (dict | None): Ruolo logico -> username (owner nei payload di scrittura).
            allow_mutations (bool): Se False e senza stato gestito, salta PUT/PATCH/DELETE.
        """
        validate_url(target_base_url, "target_base_url")
        logger.info("🔥 Avvio test differenziale esteso e Role-Aware...")
        self.test_results = []

        # Inizializza i moduli BOLA e reset dello stato
        APIStateEngine(target_base_url, self.snapshot_path, self.rollback_path)
        attack_generator = ContextAwareAttackGenerator(
            self.zap_proxy_url, zap_internal_host=self.zap_internal_host
        )
        profiles = self._build_profiles(identity_uuids, role_map, usernames)
        seeded_ids = resource_ids or {}

        # Configurazione contesto ZAP
        context_name = "API_Security_Context"
        try:
            self.zap.context.new_context(context_name)
            self.zap.context.include_in_context(context_name, f"{target_base_url}.*")
        except Exception as e:
            logger.debug(f"Errore creazione contesto ZAP: {e}")

        for ep in dynamic_endpoints:
            if self.cancel_event.is_set():
                logger.info("🛑 Scansione BOLA cancellata su richiesta dell'utente.")
                break
            path = ep["path"]
            discovered_refs = ep.get("discovered_refs", None)
            nested = bool(ep.get("nested", False))
            selected = self._select_methods(ep, test_all_methods)
            methods_to_test = self._without_mutations(
                selected, use_state_management, allow_mutations
            )
            skipped = [m for m in selected if m not in methods_to_test]
            if skipped:
                logger.warning(
                    f"⏭️ [Assessment Mode] {path}: metodi mutanti {skipped} saltati "
                    "(nessun rollback disponibile; usa --allow-mutations per riabilitarli)."
                )
            logger.info(
                f"🧪 [BOLA Role-Aware Assessment] Analisi endpoint dinamico: {path} "
                f"(metodi: {', '.join(methods_to_test)}{', path annidato' if nested else ''})"
            )

            # ID della risorsa per identità: quelli creati dal seeding per questa risorsa,
            # altrimenti l'UUID dell'identità (vincolo "ID risorsa = UUID del proprietario").
            ep_ids = seeded_ids.get(ep.get("resource_name", ""), {})
            endpoint_resource_ids = {
                key: ep_ids.get(key) or identity_uuids.get(key) or "" for key in IDENTITY_KEYS
            }

            for method in methods_to_test:
                if self.cancel_event.is_set():
                    break
                # 1. Snapshot dello stato prima del test (solo se il metodo puo alterarlo)
                manage_state = use_state_management and method in STATE_MUTATING_METHODS
                if manage_state:
                    APIStateEngine.take_snapshot(target_base_url, self.snapshot_path)

                # 2. Generazione ed esecuzione dei vettori di attacco per i 3 scenari
                scenarios_results = attack_generator.execute_tampering(
                    method=method,
                    target_base_url=target_base_url,
                    path=path,
                    headers_matrix=headers_matrix,
                    resource_ids=endpoint_resource_ids,
                    profiles=profiles,
                    discovered_refs=discovered_refs,
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
                            resource_owner_role=owner_role,
                            resource_id=stim.get("resource_id"),
                        )
                        is_vulnerable = assertion_result["is_vulnerable"]
                        verdict = assertion_result["verdict"]

                        import urllib.parse

                        parsed_url = urllib.parse.urlparse(target_url)

                        # Registriamo i dettagli del test
                        self.test_results.append(
                            {
                                "url": target_url,
                                "path": parsed_url.path,
                                "method": method,
                                "status_code": res_bob.status_code,
                                "test_name": f"{scenario_name} {method} Test",
                                "is_vulnerable": is_vulnerable,
                                "assertion_details": assertion_result,
                                "response_text": res_bob.text,
                                "res_owner_status": res_alice.status_code,
                                "res_owner_text": res_alice.text,
                                "attacker_role": attacker_role,
                                "owner_role": owner_role,
                                "scenario_name": scenario_name,
                                "resource_id": stim.get("resource_id"),
                                "nested": nested,
                            }
                        )

                        logger.info(
                            f"      [{scenario_name} - {method}] Verdict: {verdict}\n"
                            f"        - http_status_assertion: {assertion_result['http_status_assertion']}\n"
                            f"        - content_keyword_assertion: {assertion_result['content_keyword_assertion']}\n"
                            f"        - structural_similarity_assertion: {assertion_result['structural_similarity_assertion']}\n"
                            f"        - victim_reference_assertion: {assertion_result['victim_reference_assertion']}"
                        )

                        if is_vulnerable:
                            logger.error(
                                f"🚨 [ALERT CRITICAL] {verdict} RILEVATO SU: {method} {target_url}"
                            )
                            try:
                                self.zap.ascan.scan(url=zap_target_url, recurse="false")
                            except Exception as ze:
                                logger.debug(f"ZAP ascan fallito: {ze}")
                        else:
                            logger.info(
                                f"✅ [SAFE] {scenario_name} {method} su: {target_url} (Verdetto: {verdict})"
                            )
                    else:
                        logger.warning(
                            f"⚠️ Impossibile eseguire BOLA Assessment for {scenario_name} {method} dovuto a errori di rete."
                        )

                    # 4. Broken Authentication Check (Anonymous)
                    if res_anon is not None:
                        is_anon_vulnerable = res_anon.status_code in (200, 204)
                        import urllib.parse

                        parsed_url = urllib.parse.urlparse(target_url)

                        self.test_results.append(
                            {
                                "url": target_url,
                                "path": parsed_url.path,
                                "method": method,
                                "status_code": res_anon.status_code,
                                "test_name": f"Broken Auth {scenario_name} {method} Test",
                                "is_vulnerable": is_anon_vulnerable,
                                "assertion_details": {
                                    "http_status_assertion": not is_anon_vulnerable,
                                    "content_keyword_assertion": True,
                                    "structural_similarity_assertion": True,
                                },
                                "response_text": res_anon.text,
                                "res_owner_status": res_alice.status_code if res_alice else 200,
                                "res_owner_text": res_alice.text if res_alice else "",
                                "attacker_role": "anonymous",
                                "owner_role": owner_role,
                                "scenario_name": f"Broken Auth {scenario_name}",
                                "resource_id": stim.get("resource_id"),
                                "nested": nested,
                            }
                        )

                        if is_anon_vulnerable:
                            logger.error(
                                f"🚨 [ALERT CRITICAL] BROKEN AUTHENTICATION RILEVATA SU: {method} {target_url}"
                            )
                            try:
                                self.zap.ascan.scan(url=zap_target_url, recurse="false")
                            except Exception as ze:
                                logger.debug(f"ZAP ascan fallito: {ze}")

                # 5. Rollback dello stato dopo il test per ripulire gli effetti collaterali
                if manage_state:
                    APIStateEngine.trigger_rollback(target_base_url, self.rollback_path)

        # Attendi la conclusione degli active scan
        self._wait_for_scan_completion()

        # Salvataggio del report ZAP
        report_path = os.path.join(output_dir, "zap_report.json")
        self._export_report(report_path)

    def _stop_all_active_scans(self, reason: str) -> None:
        """Ferma tutti gli active scan di ZAP, senza propagare errori del proxy."""
        try:
            self.zap.ascan.stop_all_scans()
        except Exception as e:
            logger.debug(f"Impossibile fermare gli active scan di ZAP ({reason}): {e}")

    def _wait_for_scan_completion(self) -> None:
        """
        Attende la conclusione degli active scan registrati su OWASP ZAP effettuando il polling
        dello stato. L'attesa e limitata da ZAP_ACTIVE_SCAN_TIMEOUT_SECONDS (ZAP puo restare
        bloccato al 99%) e viene interrotta dalla cancellazione: in entrambi i casi gli scan
        vengono fermati esplicitamente.
        """
        deadline = time.monotonic() + ZAP_ACTIVE_SCAN_TIMEOUT_SECONDS
        while True:
            if self.cancel_event.is_set():
                logger.info("🛑 Attesa degli active scan interrotta per cancellazione.")
                self._stop_all_active_scans("cancellazione")
                return
            try:
                status = int(self.zap.ascan.status())
                logger.info(f"ZAP Active Scan in corso: {status}%")
                if status >= 100 or status < 0:
                    break
            except Exception:
                break
            if time.monotonic() >= deadline:
                logger.warning(
                    f"⏱️ ZAP Active Scan non concluso entro {ZAP_ACTIVE_SCAN_TIMEOUT_SECONDS}s "
                    f"(ultimo stato: {status}%): scansioni fermate forzatamente."
                )
                self._stop_all_active_scans("timeout")
                return
            # wait() al posto di sleep(): reagisce subito alla cancellazione
            self.cancel_event.wait(ZAP_POLL_INTERVAL_SECONDS)
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
        target_base_url: str | None = None,
        keycloak_url: str | None = None,
        zap_proxy_url: str = DEFAULT_ZAP_PROXY_URL,
        assessment_mode: bool = False,
        test_all_methods: bool = False,
        cancel_event: threading.Event | None = None,
        target_config: BolaTargetConfig | None = None,
        allow_mutations: bool | None = None,
    ):
        """
        Inizializza l'orchestratore dinamico configurando le dipendenze richieste.

        Il contratto del bersaglio (``config/bola_target.yaml``) fornisce URL, endpoint
        dell'harness, identity provider e identità; i parametri espliciti (CLI) prevalgono
        sul file per gli URL.

        Args:
            target_base_url (str | None): URL di base dell'applicazione target; None = dal contratto.
            keycloak_url (str | None): URL di Keycloak; None = dal contratto.
            zap_proxy_url (str): URL del proxy OWASP ZAP.
            assessment_mode (bool): Abilita la modalità Assessment (senza seeding/snapshot/rollback).
                È implicita quando il contratto dichiara ``identities.provider: traffic``.
            test_all_methods (bool): Esercita GET/POST/PUT/PATCH/DELETE su ogni endpoint invece
                dei soli metodi dichiarati dall'inventario (comportamento esaustivo, molto piu lento).
            cancel_event (threading.Event | None): Segnale di cancellazione condiviso con il
                ZapController; se assente ne viene creato uno dedicato a questa istanza.
            target_config (BolaTargetConfig | None): Contratto del bersaglio; None = quello condiviso.
            allow_mutations (bool | None): In Assessment Mode riabilita PUT/PATCH/DELETE;
                None = valore di ``assessment.allow_mutations`` del contratto.
        """
        self.config = target_config or get_bola_target_config()
        target_base_url = target_base_url or self.config.base_url
        keycloak_url = keycloak_url or self.config.keycloak_url
        validate_url(target_base_url, "target_base_url")
        validate_url(keycloak_url, "keycloak_url")
        validate_url(zap_proxy_url, "zap_proxy_url")

        self.target_base_url = target_base_url
        self.assessment_mode = assessment_mode or self.config.uses_traffic_identities
        self.allow_mutations = (
            self.config.allow_mutations if allow_mutations is None else allow_mutations
        )
        self.test_all_methods = test_all_methods
        self.cancel_event = cancel_event or threading.Event()
        self.identity_manager = IdentityManager(config=self.config, keycloak_url=keycloak_url)
        self.seeder = DatabaseSeeder(
            seed_url=self.config.seed_url(target_base_url), config=self.config
        )
        self.zap_controller = ZapController(
            zap_proxy_url=zap_proxy_url,
            cancel_event=self.cancel_event,
            zap_internal_host=self.config.zap_internal_host,
            snapshot_path=self.config.snapshot_path,
            rollback_path=self.config.rollback_path,
        )

    def cancel(self) -> None:
        """
        Richiede l'interruzione cooperativa della scansione D-AST di questa istanza.
        Il segnale e per-istanza: non influenza altre scansioni in corso.
        """
        self.cancel_event.set()

    @property
    def is_cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def _extract_endpoints_from_inventory(
        self, api_inventory: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """
        Estrae le rotte dall'inventario dei findings della pipeline,
        dividendole in dinamiche (con parametri {id}) e statiche.
        Raggruppa i metodi per ciascun percorso normalizzato.

        Nei path annidati (``/api/users/{id}/projects/{id}``) l'oggetto bersaglio è
        l'ULTIMO ``{id}``: la risorsa da seminare è quella che lo precede (``projects``),
        con la stessa convenzione di ``OwnershipInferenceEngine._parse_resource_from_path``.
        L'endpoint viene marcato ``nested`` e il numero di parametri in ``id_params``.

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
            if ID_PLACEHOLDER in path:
                dynamic_endpoints.append(
                    {"path": path, "methods": methods_list, **describe_dynamic_path(path)}
                )
            else:
                static_endpoints.append({"path": path, "methods": methods_list})

        logger.info(
            f"Filtro endpoint da inventario completato. Trovati {len(dynamic_endpoints)} endpoint dinamici e {len(static_endpoints)} statici."
        )
        return dynamic_endpoints, static_endpoints

    def run_dast_pipeline(
        self,
        api_inventory: list[dict[str, Any]],
        output_dir: str = "output",
        raw_traffic: list[dict[str, Any]] | None = None,
    ) -> list[Finding]:
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
        identity_uuids: dict[str, str | None] = dict.fromkeys(IDENTITY_KEYS)
        role_map = {}
        # {resource_name: {ruolo_logico: id}} — dal seeding o dal traffico osservato
        resource_ids: dict[str, dict[str, str]] = {}

        # Se siamo in Assessment Mode o se abbiamo traffico a disposizione,
        # arricchiamo gli endpoint ed estraiamo le relazioni di ownership
        if self.assessment_mode or raw_traffic:
            logger.info("🔍 [Assessment Mode / Traffic Analysis] Esecuzione Ownership Inference...")
            inference_engine = OwnershipInferenceEngine()
            inference_engine.analyze_traffic(raw_traffic or [])

            uuid_alice, uuid_bob, uuid_charlie, inferred_roles, inferred_headers = (
                inference_engine.get_inferred_identities()
            )
            identity_uuids = {
                IDENTITY_VICTIM: uuid_alice,
                IDENTITY_PEER: uuid_bob,
                IDENTITY_PRIVILEGED: uuid_charlie,
            }
            role_map.update(inferred_roles)
            headers_matrix.update(inferred_headers)
            owned_ids = inference_engine.get_owned_resource_ids()

            # Troviamo ulteriori endpoint con riferimenti a oggetti tramite ObjectReferenceDiscoveryEngine
            if raw_traffic:
                logger.info(
                    "🔍 [Object Reference Discovery] Analisi del traffico alla ricerca di ID nascosti..."
                )
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
                            # L'ultimo riferimento di path è l'oggetto bersaglio (path annidati)
                            path_refs = [r for r in refs if r["location"] == "path"]
                            resource_name = (
                                path_refs[-1]["name"].replace("_id", "") if path_refs else "generic"
                            )

                            dynamic_eps.append(
                                {
                                    "path": norm_path,
                                    "methods": [method],
                                    "resource_name": resource_name,
                                    "discovered_refs": refs,
                                    "nested": len(path_refs) > 1,
                                    "id_params": len(path_refs),
                                }
                            )

            # ID realmente osservati nel traffico per ciascuna identità e risorsa: sono
            # questi gli oggetti da attaccare, non il claim sub dell'utente.
            for ep in dynamic_eps:
                for key, uid in identity_uuids.items():
                    observed = (owned_ids.get(uid or "", {}) or {}).get(ep["resource_name"])
                    if observed:
                        resource_ids.setdefault(ep["resource_name"], {})[key] = observed[0]

        # Se non siamo in Assessment Mode o se non siamo riusciti ad estrarre le identità dal traffico, usiamo Keycloak (Lab Mode)
        use_state_management = True
        if self.assessment_mode:
            use_state_management = False

        if (
            not headers_matrix
            or not headers_matrix.get("userA")
            or not identity_uuids.get(IDENTITY_VICTIM)
        ):
            logger.info(
                f"🧪 [Lab Mode] Configurazione delle identità tramite provider "
                f"'{self.config.identity_provider}'..."
            )
            headers_matrix = self.identity_manager.get_headers_for_identities()
            identity_uuids = dict(self.identity_manager.identity_map)
            role_map = self.identity_manager.role_map

            # In Lab Mode eseguiamo anche il seeding e abilitiamo lo snapshot/rollback dello stato.
            # L'harness può rispondere con gli ID effettivamente creati: hanno la precedenza.
            seed_outcome = self.seeder.seed_target_application(dynamic_eps, identity_uuids)
            resource_ids = seed_outcome.resource_ids
            if not seed_outcome.success:
                logger.warning(
                    "Procedo con il test DAST anche se il seeding dinamico ha rilevato degli avvisi."
                )
        else:
            logger.info(
                "ℹ️ [Assessment Mode] Utilizzo delle identità e relazioni inferte dal traffico. Seeding saltato."
            )

        # 4. Differential Scan & Authorization Testing (Passando gli UUID e gli ID di contesto)
        self.zap_controller.run_differential_scan(
            target_base_url=self.target_base_url,
            dynamic_endpoints=dynamic_eps,
            headers_matrix=headers_matrix,
            # In assessment mode gli UUID possono essere None (identita inferite dal
            # traffico o assenti): la differential scan e i suoi consumatori lo gestiscono.
            identity_uuids=identity_uuids,
            role_map=role_map,
            output_dir=output_dir,
            use_state_management=use_state_management,
            test_all_methods=self.test_all_methods,
            resource_ids=resource_ids,
            usernames=self.config.usernames,
            allow_mutations=self.allow_mutations,
        )

        logger.info(
            "🏆 Pipeline D-AST completata con successo! Generazione dei findings di sbarramento..."
        )

        # Generiamo i findings per attestare se gli endpoint sono sicuri o vulnerabili
        from src.domain.entities import (
            APIContext,
            Finding,
            FindingCategory,
            FindingSource,
            RuntimeEvidence,
            Severity,
        )

        dast_findings = []

        for res in self.zap_controller.test_results:
            path = res["path"]
            method = res["method"]
            status_code = res["status_code"]
            test_name = res["test_name"]
            is_vulnerable = res["is_vulnerable"]
            assertion_details = res["assertion_details"]
            nested = bool(res.get("nested", False))
            raw_data = {
                "scenario": res.get("scenario_name"),
                "resource_id": res.get("resource_id"),
                "nested_path": nested,
            }
            nested_note = (
                "\nPath annidato: attaccato l'ultimo parametro {id} (oggetto figlio), "
                "i parametri genitori valorizzati con l'UUID del proprietario."
                if nested
                else ""
            )

            # Formattiamo i dettagli delle asserzioni per l'evidenza
            details_str = (
                f"Asserzioni di Sicurezza BOLA:\n"
                f"  - http_status_assertion: {assertion_details['http_status_assertion']}\n"
                f"  - content_keyword_assertion: {assertion_details['content_keyword_assertion']}\n"
                f"  - structural_similarity_assertion: {assertion_details['structural_similarity_assertion']}\n"
                f"  - victim_reference_assertion: {assertion_details.get('victim_reference_assertion', False)}\n"
                f"Verdetto finale: {'VULNERABLE' if is_vulnerable else 'SAFE'}"
            )

            evidence = RuntimeEvidence(
                tested_url=res["url"],
                http_status=status_code,
                response_snippet=details_str + f"\n\nPayload di Bob:\n{res['response_text'][:500]}",
            )

            if is_vulnerable:
                finding = Finding.create(
                    source=FindingSource.RUNTIME_VALIDATOR,
                    category=FindingCategory.AUTHORIZATION
                    if "BOLA" in test_name
                    else FindingCategory.AUTHENTICATION,
                    title=f"Vulnerabilità {test_name} confermata a runtime",
                    description=(
                        f"Il test differenziale '{test_name}' per l'endpoint '{path}' ha confermato che l'accesso "
                        f"non autorizzato è possibile.\n{details_str}{nested_note}"
                    ),
                    severity=Severity.HIGH,
                    confidence=1.0,
                    rule_id="dynamic-bola-exploited"
                    if "BOLA" in test_name
                    else "dynamic-broken-auth-exploited",
                    target_identifier=f"{method}:{path}:{test_name}",
                    rule_name=f"Dynamic {test_name} Exploitation Check",
                    api=APIContext(endpoint=path, method=method, requires_authentication=True),
                    runtime_evidence=evidence,
                    correlation_key=f"api:{method}:{APIEndpointNormalizer.normalize_path(path)}",
                    raw_data=raw_data,
                )
            else:
                finding = Finding.create(
                    source=FindingSource.RUNTIME_VALIDATOR,
                    category=FindingCategory.AUTHORIZATION
                    if "BOLA" in test_name
                    else FindingCategory.AUTHENTICATION,
                    title=f"Test {test_name} - Endpoint Sicuro ({status_code})",
                    description=(
                        f"Il test differenziale '{test_name}' ha verificato che l'accesso non autorizzato viene "
                        f"bloccato correttamente.\n{details_str}{nested_note}"
                    ),
                    severity=Severity.INFO,
                    confidence=1.0,
                    rule_id="dynamic-test-secure",
                    target_identifier=f"{method}:{path}:{test_name}",
                    rule_name="Dynamic Differential Authorization Check",
                    api=APIContext(endpoint=path, method=method, requires_authentication=True),
                    runtime_evidence=evidence,
                    correlation_key=f"api:{method}:{APIEndpointNormalizer.normalize_path(path)}",
                    raw_data=raw_data,
                )

            dast_findings.append(finding)

        return dast_findings


if __name__ == "__main__":
    # Esempio di esecuzione manuale standalone o caricamento dell'ultimo inventario
    inventory_path = "output/unified_api_inventory.json"
    if os.path.exists(inventory_path):
        logger.info(
            f"Caricamento inventario esistente da {inventory_path} per esecuzione standalone..."
        )
        with open(inventory_path, encoding="utf-8") as f:
            api_inv = json.load(f)
    else:
        logger.info(
            "Nessun inventario trovato. Utilizzo di un inventario mock per test standalone..."
        )
        # Generiamo dei mock findings che assomigliano alla struttura reale dei findings della pipeline
        api_inv = [
            {"api": {"endpoint": "/api/orders/<order_id>", "method": "GET"}},
            {"api": {"endpoint": "/api/orders/<order_id>", "method": "POST"}},
            {"api": {"endpoint": "/api/profile", "method": "GET"}},
            {"api": {"endpoint": "/api/invoices/{invoice_id}", "method": "GET"}},
        ]

    orchestrator = DynamicOrchestrator()
    orchestrator.run_dast_pipeline(api_inv)
