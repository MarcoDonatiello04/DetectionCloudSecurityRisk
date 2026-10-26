"""
Sezione "Bersagli esterni" della dashboard.

Rende eseguibile da interfaccia il flusso di validation/PROTOCOLLO.md sui bersagli dell'insieme
di prova: avvio dell'applicazione bersaglio, traffico di esercizio, dashboard dedicata e
archiviazione delle evidenze. Ogni bersaglio gira in una dashboard separata, su una porta
propria e con bersaglio, URL e cartella dei report fissati all'avvio: la dashboard principale
non cambia mai bersaglio, quindi una scansione in corso non può finire sul bersaglio sbagliato.

Le azioni eseguono solo comandi fissati dal registro (config/targets/registry.yaml) e sono
accettate soltanto da richieste locali. Il modulo non legge il codice dei bersagli né il
contenuto dei report: verifica solo la presenza dei file di evidenza.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, TextIO

import yaml
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

logger = logging.getLogger("SecurityPlatform.ExternalTargets")

REGISTRY_PATH = Path(os.getenv("EXTERNAL_TARGETS_REGISTRY", "config/targets/registry.yaml"))
LOGS_DIR = Path("output/external/_logs")
ARCHIVE_DIR = Path("validation/risultati")
TRAFFIC_SCRIPT = "entrypoints/operations/genera_traffico_esercizio.py"
TEMPLATE_PATH = Path("src/presentation/web/templates/external_targets.html")
GROUND_TRUTH_DIR = Path("validation/ground_truth")
DECISIONS_DIR = Path("validation/classificazioni")

# File che il protocollo (sezione 5) chiede di conservare per ogni esecuzione
EVIDENCE_FILES = (
    "unified_security_report.json",
    "core_findings.json",
    "benchmark_results.json",
    "bola_scan_results.json",
    "raw_traffic.json",
)

# Servizi della piattaforma necessari ai bersagli esterni (protocollo, sezione 4)
PLATFORM_SERVICES = {
    "mitmproxy": ("127.0.0.1", 8081),
    "owasp-zap": ("127.0.0.1", 8090),
}

_LOCAL_CLIENTS = {"127.0.0.1", "::1", "localhost"}

# Attese massime della preparazione guidata (secondi)
APP_WAIT_SECONDS = int(os.getenv("EXTERNAL_TARGETS_APP_WAIT", "240"))
SERVICE_WAIT_SECONDS = 90
DASHBOARD_WAIT_SECONDS = 30
# Durata massima della scansione nella dashboard dedicata: con BOLA servono decine di minuti
SCAN_TIMEOUT_SECONDS = int(os.getenv("EXTERNAL_TARGETS_SCAN_TIMEOUT", "1800"))
SCAN_TIMEOUT_BOLA_SECONDS = int(os.getenv("EXTERNAL_TARGETS_SCAN_BOLA_TIMEOUT", "14400"))

router = APIRouter()


@dataclass(frozen=True)
class ExternalTarget:
    """Bersaglio esterno come descritto nel registro."""

    id: str
    label: str
    target_dir: str
    base_url: str
    output_dir: str
    bola_config: str
    port: int
    compose_dir: str | None = None
    compose_build: bool = False
    compose_overrides: tuple[str, ...] = ()
    traffic: bool = False
    note: str = ""

    @property
    def has_app(self) -> bool:
        """True se il bersaglio ha un'applicazione da avviare con docker compose."""
        return bool(self.compose_dir)

    def dashboard_env(self) -> dict[str, str]:
        """Variabili d'ambiente della dashboard dedicata (come `make dashboard-<id>`)."""
        return {
            "TARGET_DIR": self.target_dir,
            "TARGET_BASE_URL": self.base_url,
            "OUTPUT_DIR": self.output_dir,
            "BOLA_TARGET_CONFIG": self.bola_config,
            "PYTHONPATH": ".",
            # La dashboard dedicata non mostra a sua volta la sezione: i bersagli si gestiscono
            # solo dalla dashboard principale, che tiene traccia dei processi avviati.
            "EXTERNAL_TARGETS_PANEL": "0",
        }


def load_registry(path: Path | None = None) -> dict[str, ExternalTarget]:
    """
    Legge il registro dei bersagli esterni.

    Args:
        path (Path | None): Percorso del file YAML; se None, ``REGISTRY_PATH``.

    Returns:
        dict[str, ExternalTarget]: Bersagli indicizzati per identificativo; vuoto se il file manca.
    """
    path = path or REGISTRY_PATH
    if not path.exists():
        return {}
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    targets: dict[str, ExternalTarget] = {}
    for target_id, cfg in (raw.get("targets") or {}).items():
        targets[target_id] = ExternalTarget(
            id=target_id,
            label=cfg.get("label", target_id),
            target_dir=cfg["target_dir"],
            base_url=cfg["base_url"],
            output_dir=cfg["output_dir"],
            bola_config=cfg["bola_config"],
            port=int(cfg["port"]),
            compose_dir=cfg.get("compose_dir"),
            compose_build=bool(cfg.get("compose_build", False)),
            compose_overrides=tuple(cfg.get("compose_overrides") or ()),
            traffic=bool(cfg.get("traffic", False)),
            note=cfg.get("note", ""),
        )
    return targets


# ─── Comandi ─────────────────────────────────────────────────────────────────


def _compose_base(target: ExternalTarget) -> list[str]:
    """`docker compose` con gli eventuali override, risolti dalla radice del progetto."""
    cmd = ["docker", "compose"]
    if target.compose_overrides:
        cmd += ["-f", "docker-compose.yml"]
        for override in target.compose_overrides:
            cmd += ["-f", str(Path(override).resolve())]
    return cmd


def app_up_command(target: ExternalTarget) -> list[str]:
    """Comando che avvia l'applicazione bersaglio."""
    cmd = [*_compose_base(target), "up", "-d"]
    if target.compose_build:
        cmd.append("--build")
    return cmd


def platform_services_command() -> list[str]:
    """Comando che avvia i servizi della piattaforma necessari (protocollo, sezione 4)."""
    return ["docker", "compose", "up", "-d", *PLATFORM_SERVICES]


def app_down_command(target: ExternalTarget) -> list[str]:
    """Comando che ferma l'applicazione bersaglio (senza rimuovere i volumi dei dati)."""
    return [*_compose_base(target), "down"]


def traffic_command(target: ExternalTarget) -> list[str]:
    """Comando che genera il traffico di esercizio per la BOLA dinamica."""
    return [sys.executable, TRAFFIC_SCRIPT, target.id]


def dashboard_command(target: ExternalTarget) -> list[str]:
    """Comando della dashboard dedicata. Niente --reload: il bersaglio non deve cambiare."""
    return [
        sys.executable,
        "-m",
        "uvicorn",
        "src.presentation.api.server:app",
        "--host",
        "127.0.0.1",
        "--port",
        str(target.port),
    ]


# ─── Stato ───────────────────────────────────────────────────────────────────


def _port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _url_reachable(url: str, timeout: float = 2.0) -> bool:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        opener.open(url, timeout=timeout)
        return True
    except urllib.error.HTTPError:
        # Il server ha risposto: è raggiungibile anche se la radice non è una pagina valida.
        return True
    except Exception:
        return False


def _evidence_status(target: ExternalTarget) -> list[dict[str, Any]]:
    """Presenza e data dei file di evidenza, senza leggerne il contenuto."""
    status = []
    for name in EVIDENCE_FILES:
        path = Path(target.output_dir) / name
        exists = path.is_file()
        status.append(
            {
                "file": name,
                "present": exists,
                "modified": (
                    datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds")
                    if exists
                    else None
                ),
            }
        )
    return status


# ─── Processi e job ──────────────────────────────────────────────────────────

_jobs: dict[str, dict[str, Any]] = {}
_dashboards: dict[str, subprocess.Popen] = {}
_lock = threading.Lock()


def _log_path(target_id: str, kind: str) -> Path:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    return LOGS_DIR / f"{target_id}-{kind}.log"


Step = Callable[[TextIO], int]


def _command_step(cmd: list[str], cwd: str | None = None) -> Step:
    """Passo che esegue un comando e ne scrive l'output nel log del job."""

    def step(log: TextIO) -> int:
        log.write(f"$ {' '.join(cmd)}\n")
        log.flush()
        try:
            env = {**os.environ, "PYTHONPATH": "."}
            proc = subprocess.run(
                cmd, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT, check=False
            )
            return proc.returncode
        except Exception as exc:  # comando assente o non eseguibile
            log.write(f"Errore: {exc}\n")
            return -1

    return step


def _wait_step(label: str, check: Callable[[], bool], seconds: int) -> Step:
    """Passo che attende una condizione, con un limite di tempo."""

    def step(log: TextIO) -> int:
        log.write(f"… attesa: {label} (al massimo {seconds} s)\n")
        log.flush()
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if check():
                log.write(f"✓ {label}\n")
                return 0
            time.sleep(2)
        log.write(f"✗ {label}: tempo scaduto\n")
        return 1

    return step


def _note_step(message: str) -> Step:
    def step(log: TextIO) -> int:
        log.write(f"{message}\n")
        return 0

    return step


def _run_job(target_id: str, kind: str, steps: list[Step], description: str) -> dict:
    """Esegue i passi in background, in ordine, fermandosi al primo che fallisce."""
    with _lock:
        running = [
            j
            for j in _jobs.values()
            if j["status"] == "running" and (j["target"] == target_id or j["target"] == "*")
        ]
        if running:
            raise HTTPException(
                status_code=409,
                detail=f"C'è già un'azione in corso su {running[0]['target']}: attendi la fine.",
            )
        job = {
            "id": uuid.uuid4().hex[:8],
            "target": target_id,
            "kind": kind,
            "command": description,
            "status": "running",
            "returncode": None,
            "started": datetime.now().isoformat(timespec="seconds"),
            "ended": None,
            "log": str(_log_path(target_id if target_id != "*" else "tutti", kind)),
        }
        _jobs[job["id"]] = job

    def run() -> None:
        returncode = 0
        with open(job["log"], "w", encoding="utf-8") as log:
            for step in steps:
                returncode = step(log)
                log.flush()
                if returncode != 0:
                    log.write("\nInterrotto: il passo precedente non è riuscito.\n")
                    break
            else:
                log.write("\nCompletato.\n")
        with _lock:
            job["returncode"] = returncode
            job["status"] = "ok" if returncode == 0 else "error"
            job["ended"] = datetime.now().isoformat(timespec="seconds")

    threading.Thread(target=run, daemon=True).start()
    return job


def _start_job(target: ExternalTarget, kind: str, cmd: list[str], cwd: str | None) -> dict:
    """Esegue un singolo comando in background."""
    return _run_job(target.id, kind, [_command_step(cmd, cwd)], " ".join(cmd))


def dashboard_running(target: ExternalTarget) -> bool:
    return _port_open("127.0.0.1", target.port)


def _launch_dashboard(target: ExternalTarget) -> dict[str, Any]:
    """Avvia la dashboard dedicata, se non è già attiva sulla sua porta."""
    url = f"http://localhost:{target.port}/"
    with _lock:
        if dashboard_running(target):
            return {"status": "already_running", "url": url}
        Path(target.output_dir).mkdir(parents=True, exist_ok=True)
        log = open(_log_path(target.id, "dashboard"), "w", encoding="utf-8")  # noqa: SIM115
        proc = subprocess.Popen(
            dashboard_command(target),
            env={**os.environ, **target.dashboard_env()},
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        _dashboards[target.id] = proc
    logger.info(f"Dashboard dedicata a {target.id} avviata (pid {proc.pid}, porta {target.port}).")
    return {"status": "started", "pid": proc.pid, "url": url}


def _services_up() -> bool:
    return all(_port_open(host, port) for host, port in PLATFORM_SERVICES.values())


def prepare_steps(target: ExternalTarget, with_traffic: bool = True) -> list[Step]:
    """
    Sequenza della preparazione guidata: servizi della piattaforma, applicazione, attesa che
    risponda, traffico di esercizio e dashboard dedicata. I passi già soddisfatti si saltano.
    """
    steps: list[Step] = [_note_step(f"=== {target.label} ===")]

    def services(log: TextIO) -> int:
        if _services_up():
            log.write("✓ servizi della piattaforma già attivi\n")
            return 0
        return _command_step(platform_services_command())(log)

    steps.append(services)
    steps.append(_wait_step("mitmproxy in ascolto", lambda: _port_open("127.0.0.1", 8081), 60))

    if target.has_app:

        def app(log: TextIO) -> int:
            if _url_reachable(target.base_url):
                log.write(f"✓ applicazione già in esecuzione su {target.base_url}\n")
                return 0
            return _command_step(app_up_command(target), target.compose_dir)(log)

        steps.append(app)
        steps.append(
            _wait_step(
                f"applicazione raggiungibile su {target.base_url}",
                lambda: _url_reachable(target.base_url),
                APP_WAIT_SECONDS,
            )
        )
        if target.traffic and with_traffic:
            steps.append(_command_step(traffic_command(target)))
        elif target.traffic:
            steps.append(_note_step("– traffico di esercizio non richiesto: saltato"))

    def dashboard(log: TextIO) -> int:
        res = _launch_dashboard(target)
        log.write(f"dashboard dedicata: {res['status']} → {res['url']}\n")
        return 0

    steps.append(dashboard)
    steps.append(
        _wait_step(
            f"dashboard dedicata in ascolto sulla porta {target.port}",
            lambda: dashboard_running(target),
            DASHBOARD_WAIT_SECONDS,
        )
    )
    return steps


def _scan_step(target: ExternalTarget, run_bola: bool) -> Step:
    """
    Passo che lancia la scansione unificata nella dashboard dedicata del bersaglio, l'unica
    che lavora sul suo codice e sulla sua cartella dei report. Riporta nel log l'esito per
    modulo restituito dalla risposta, senza leggere i file dei report.
    """
    endpoint = "/api/scan/all" if run_bola else "/api/scan/non-bola"
    timeout = SCAN_TIMEOUT_BOLA_SECONDS if run_bola else SCAN_TIMEOUT_SECONDS

    def step(log: TextIO) -> int:
        url = f"http://127.0.0.1:{target.port}{endpoint}"
        log.write(f"POST {url} ({'con' if run_bola else 'senza'} BOLA)\n")
        log.flush()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(urllib.request.Request(url, method="POST"), timeout=timeout) as r:
                payload = json.loads(r.read().decode("utf-8"))
        except Exception as exc:
            log.write(f"✗ scansione non riuscita: {exc}\n")
            return 1
        modules = payload.get("benchmark") or []
        for module in modules:
            log.write(
                f"  {module.get('name')}: {module.get('status')} · "
                f"{module.get('findings', 0)} findings · {module.get('time', 0.0):.1f} s\n"
            )
        total = sum(m.get("findings", 0) for m in modules)
        log.write(f"✓ scansione completata: {len(modules)} moduli, {total} findings\n")
        return 0

    return step


def scan_steps(target: ExternalTarget, run_bola: bool) -> list[Step]:
    """
    Preparazione guidata seguita dalla scansione. Il traffico di esercizio serve solo alla
    BOLA dinamica, quindi la scansione rapida lo salta.
    """
    return [*prepare_steps(target, with_traffic=run_bola), _scan_step(target, run_bola)]


def _tool_versions() -> str:
    """Commit dello strumento e versioni degli scanner, da allegare alle evidenze."""
    lines = []
    for label, cmd in (
        ("commit", ["git", "rev-parse", "HEAD"]),
        ("tag", ["git", "describe", "--tags", "--always"]),
        ("modifiche non committate", ["git", "status", "--porcelain"]),
        ("checkov", ["checkov", "--version"]),
        ("semgrep", ["semgrep", "--version"]),
        ("spectral", ["spectral", "--version"]),
    ):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
            value = (out.stdout or out.stderr).strip()
            if label == "modifiche non committate":
                value = f"{len(value.splitlines())} file" if value else "nessuna"
        except Exception as exc:
            value = f"non disponibile ({exc.__class__.__name__})"
        lines.append(f"{label}: {value}")
    return "\n".join(lines) + "\n"


def archive_evidence(target: ExternalTarget, now: datetime | None = None) -> Path:
    """
    Copia la cartella dei report in validation/risultati/<AAAA-MM-GG>_<bersaglio>/
    (protocollo, sezione 5) e vi aggiunge le versioni dello strumento. Non sovrascrive mai
    un'archiviazione esistente.
    """
    source = Path(target.output_dir)
    if not source.is_dir() or not any(source.iterdir()):
        raise HTTPException(status_code=404, detail="Nessun report da archiviare.")
    stamp = (now or datetime.now()).strftime("%Y-%m-%d")
    dest = ARCHIVE_DIR / f"{stamp}_{target.id}"
    suffix = 2
    while dest.exists():
        dest = ARCHIVE_DIR / f"{stamp}_{target.id}_{suffix}"
        suffix += 1
    shutil.copytree(source, dest)
    (dest / "versioni.txt").write_text(_tool_versions(), encoding="utf-8")
    return dest


# ─── Endpoint ────────────────────────────────────────────────────────────────


def _require_local(request: Request) -> None:
    host = request.client.host if request.client else ""
    if host not in _LOCAL_CLIENTS:
        raise HTTPException(status_code=403, detail="Azione consentita solo da localhost.")


def _get_target(target_id: str) -> ExternalTarget:
    target = load_registry().get(target_id)
    if target is None:
        raise HTTPException(status_code=404, detail=f"Bersaglio '{target_id}' non registrato.")
    return target


@router.get("/external-targets", response_class=HTMLResponse, tags=["UI"])
def serve_external_targets() -> HTMLResponse:
    """Pagina della sezione Bersagli esterni."""
    if TEMPLATE_PATH.exists():
        return HTMLResponse(TEMPLATE_PATH.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Bersagli esterni: template non trovato</h1>")


@router.get("/api/external-targets", tags=["External targets"])
def list_external_targets() -> dict[str, Any]:
    """Bersagli registrati con lo stato di applicazione, dashboard dedicata ed evidenze."""
    targets = []
    for target in load_registry().values():
        targets.append(
            {
                "id": target.id,
                "label": target.label,
                "target_dir": target.target_dir,
                "target_dir_exists": Path(target.target_dir).is_dir(),
                "base_url": target.base_url,
                "output_dir": target.output_dir,
                "bola_config": target.bola_config,
                "port": target.port,
                "dashboard_url": f"http://localhost:{target.port}/",
                "has_app": target.has_app,
                "traffic": target.traffic,
                "note": target.note,
                "app_reachable": target.has_app and _url_reachable(target.base_url),
                "dashboard_running": dashboard_running(target),
                "evidence": _evidence_status(target),
            }
        )
    services = {name: _port_open(host, port) for name, (host, port) in PLATFORM_SERVICES.items()}
    return {"targets": targets, "services": services, "registry": str(REGISTRY_PATH)}


@router.get("/api/external-targets/jobs", tags=["External targets"])
def list_jobs() -> dict[str, Any]:
    """Azioni lanciate dalla pagina, dalla più recente."""
    with _lock:
        jobs = sorted(_jobs.values(), key=lambda j: j["started"], reverse=True)
    return {"jobs": jobs}


@router.get("/api/external-targets/jobs/{job_id}/log", tags=["External targets"])
def job_log(job_id: str, tail: int = 200) -> dict[str, Any]:
    """Ultime righe del log di un'azione."""
    with _lock:
        job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Azione non trovata.")
    path = Path(job["log"])
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines() if path.exists() else []
    return {"job": job, "lines": lines[-max(1, min(tail, 2000)) :]}


@router.post("/api/external-targets/{target_id}/app/start", tags=["External targets"])
def start_app(target_id: str, request: Request) -> dict[str, Any]:
    """Avvia l'applicazione bersaglio con docker compose."""
    _require_local(request)
    target = _get_target(target_id)
    if not target.has_app:
        raise HTTPException(status_code=400, detail="Questo bersaglio non ha un'applicazione.")
    return _start_job(target, "app-start", app_up_command(target), target.compose_dir)


@router.post("/api/external-targets/{target_id}/app/stop", tags=["External targets"])
def stop_app(target_id: str, request: Request) -> dict[str, Any]:
    """Ferma l'applicazione bersaglio con docker compose."""
    _require_local(request)
    target = _get_target(target_id)
    if not target.has_app:
        raise HTTPException(status_code=400, detail="Questo bersaglio non ha un'applicazione.")
    return _start_job(target, "app-stop", app_down_command(target), target.compose_dir)


@router.post("/api/external-targets/{target_id}/traffic", tags=["External targets"])
def generate_traffic(target_id: str, request: Request) -> dict[str, Any]:
    """Genera il traffico di esercizio da cui la BOLA dinamica ricava le identità."""
    _require_local(request)
    target = _get_target(target_id)
    if not target.traffic:
        raise HTTPException(status_code=400, detail="Nessun traffico di esercizio previsto.")
    return _start_job(target, "traffic", traffic_command(target), None)


@router.post("/api/external-targets/{target_id}/dashboard/start", tags=["External targets"])
def start_dashboard(target_id: str, request: Request) -> dict[str, Any]:
    """Avvia la dashboard dedicata al bersaglio sulla sua porta."""
    _require_local(request)
    return _launch_dashboard(_get_target(target_id))


@router.post("/api/external-targets/{target_id}/dashboard/stop", tags=["External targets"])
def stop_dashboard(target_id: str, request: Request) -> dict[str, Any]:
    """Ferma la dashboard dedicata, se è stata avviata da questa pagina."""
    _require_local(request)
    target = _get_target(target_id)
    with _lock:
        proc = _dashboards.pop(target.id, None)
    if proc is None or proc.poll() is not None:
        if dashboard_running(target):
            raise HTTPException(
                status_code=409,
                detail=(
                    f"La porta {target.port} è occupata da un processo non avviato da questa "
                    f"pagina: fermalo con `make stop-dashboard DASHBOARD_PORT={target.port}`."
                ),
            )
        return {"status": "not_running"}
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    return {"status": "stopped"}


@router.post("/api/external-targets/prepare-all", tags=["External targets"])
def prepare_all(request: Request, traffic: bool = True) -> dict[str, Any]:
    """Prepara tutti i bersagli, uno dopo l'altro."""
    _require_local(request)
    targets = list(load_registry().values())
    failed: list[str] = []

    def each(target: ExternalTarget) -> Step:
        # Un bersaglio che non si prepara non deve fermare gli altri.
        def step(log: TextIO) -> int:
            for sub in prepare_steps(target, with_traffic=traffic):
                if sub(log) != 0:
                    failed.append(target.id)
                    log.write(f"✗ {target.id} non pronto: si passa al bersaglio successivo\n\n")
                    break
            else:
                log.write("\n")
            return 0

        return step

    def summary(log: TextIO) -> int:
        if failed:
            log.write(f"Bersagli non pronti: {', '.join(failed)}\n")
            return 1
        return 0

    steps = [each(t) for t in targets] + [summary]
    return _run_job("*", "prepare", steps, "preparazione di tutti i bersagli")


@router.post("/api/external-targets/{target_id}/prepare", tags=["External targets"])
def prepare(target_id: str, request: Request, traffic: bool = True) -> dict[str, Any]:
    """Preparazione guidata del bersaglio, fino alla dashboard dedicata pronta."""
    _require_local(request)
    target = _get_target(target_id)
    return _run_job(target.id, "prepare", prepare_steps(target, traffic), "preparazione guidata")


@router.post("/api/external-targets/{target_id}/scan", tags=["External targets"])
def scan(target_id: str, request: Request, bola: bool = False) -> dict[str, Any]:
    """
    Prepara il bersaglio e vi esegue la scansione unificata (rapida, o completa con BOLA),
    in background: l'avanzamento si segue dal log dell'azione restituita.
    """
    _require_local(request)
    target = _get_target(target_id)
    kind = "scan-bola" if bola else "scan"
    description = f"scansione {'completa con BOLA' if bola else 'rapida'}"
    return _run_job(target.id, kind, scan_steps(target, bola), description)


@router.get("/api/external-targets/{target_id}/metrics", tags=["External targets"])
def target_metrics(target_id: str) -> dict[str, Any]:
    """
    Metriche di accuratezza sulle evidenze correnti del bersaglio (validation/PROTOCOLLO.md,
    §6), con le decisioni manuali di validation/classificazioni/ se presenti.
    """
    from src.application.evaluation.accuracy import (
        evaluate,
        load_decisions,
        load_ground_truth,
        load_signals,
    )

    target = _get_target(target_id)
    ground_truth = GROUND_TRUTH_DIR / f"{target.id.replace('_sicuro', '')}.yaml"
    evidence = Path(target.output_dir)
    if not ground_truth.is_file():
        raise HTTPException(status_code=404, detail="Nessun riferimento di verità.")
    if (
        not (evidence / "core_findings.json").is_file()
        and not (evidence / "unified_security_report.json").is_file()
    ):
        raise HTTPException(status_code=404, detail="Nessuna esecuzione da valutare.")
    _, entries = load_ground_truth(ground_truth)
    signals = load_signals(evidence, Path(target.target_dir))
    report = evaluate(entries, signals, load_decisions(DECISIONS_DIR / f"{target.id}.yaml"))
    return {"bersaglio": target.id, "complessivo": report["complessivo"], "voci": report["voci"]}


@router.post("/api/external-targets/{target_id}/archive", tags=["External targets"])
def archive(target_id: str, request: Request) -> dict[str, Any]:
    """Archivia le evidenze in validation/risultati (protocollo, sezione 5)."""
    _require_local(request)
    target = _get_target(target_id)
    dest = archive_evidence(target)
    return {"status": "archived", "path": str(dest)}
