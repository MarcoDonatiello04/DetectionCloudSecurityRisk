"""
Catalogo dei bersagli locali selezionabili dalla dashboard unica.

A differenza di ``external_targets`` (che avvia una dashboard dedicata per ciascun bersaglio
dell'insieme di prova), questo modulo descrive *tutti* i bersagli locali in un unico catalogo,
così che la dashboard principale possa cambiare bersaglio in-process con un menu a tendina.

Il catalogo è costruito per scoperta:
  - **Casi di prova** — ogni cartella di ``data/test_targets`` con una coppia
    ``vulnerable_app`` / ``secure_app`` diventa due voci (una per versione); i bersagli a
    cartella singola che espongono codice e contratto (``bola``) diventano una voce sola.
  - **Repo target** — ``data/test_targets/repo_target``, l'applicazione cooperante costruita
    per esercitare tutti i moduli (statici e BOLA dinamico).
  - **Insieme di prova** — i bersagli esterni del registro (``config/targets/registry.yaml``),
    riusati tramite ``external_targets.load_registry``.

Ogni voce porta con sé i parametri che la dashboard applica al bersaglio corrente
(``TARGET_DIR``, ``TARGET_BASE_URL``, ``OUTPUT_DIR``, contratto OpenAPI). I bersagli puramente
statici non hanno un'applicazione in esecuzione: ``base_url`` resta vuoto e la parte dinamica
semplicemente non trova nulla da interrogare.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from src.core.config import DEFAULT_TARGET_BASE_URL
from src.presentation.api import external_targets

TEST_TARGETS_DIR = Path("data/test_targets")

# Cartelle di test_targets che non sono bersagli selezionabili.
_SKIP_DIRS = {"external", "crapi_repo", "__pycache__"}

# Etichette leggibili per le categorie dei casi di prova (cartella -> nome mostrato).
_CATEGORY_LABELS = {
    "bola": "BOLA — bersaglio con Keycloak (API1)",
    "broken_authentication": "Broken Authentication (API2)",
    "broken_function_level_authorization": "BFLA (API5)",
    "broken_object_level_authorization": "BOLA (API1)",
    "broken_object_property_level_authorization": "BOPLA (API3)",
    "security_misconfiguration": "Security Misconfiguration (API8)",
    "unrestricted_resource_consumption": "Resource Consumption (API4)",
}

GROUP_TEST_CASES = "Casi di prova"
GROUP_REPO_TARGET = "Repo target"
GROUP_TEST_SET = "Insieme di prova"

# Ordine con cui i gruppi compaiono nel menu.
GROUP_ORDER = (GROUP_REPO_TARGET, GROUP_TEST_CASES, GROUP_TEST_SET)


@dataclass(frozen=True)
class DashboardTarget:
    """Un bersaglio selezionabile dal menu della dashboard unica."""

    id: str
    label: str
    group: str
    target_dir: str
    output_dir: str
    base_url: str = ""
    openapi: str = ""
    bola_config: str = ""
    external: bool = False
    note: str = ""
    aliases: tuple[str, ...] = field(default_factory=tuple)

    @property
    def has_app(self) -> bool:
        """True se il bersaglio dichiara un'applicazione in esecuzione da interrogare."""
        return bool(self.base_url)


def _find_openapi(directory: Path) -> str:
    """Primo contratto OpenAPI nella cartella del bersaglio, se presente."""
    for name in ("openapi.yaml", "openapi.yml", "openapi.json"):
        candidate = directory / name
        if candidate.is_file():
            return str(candidate)
    return ""


def _category_label(folder: str) -> str:
    """Etichetta leggibile per una categoria; ripiego sul nome della cartella."""
    return _CATEGORY_LABELS.get(folder, folder.replace("_", " ").title())


def _test_case_targets() -> list[DashboardTarget]:
    """Scopre i bersagli dei casi di prova in ``data/test_targets``."""
    targets: list[DashboardTarget] = []
    if not TEST_TARGETS_DIR.is_dir():
        return targets

    for entry in sorted(TEST_TARGETS_DIR.iterdir()):
        if not entry.is_dir() or entry.name in _SKIP_DIRS or entry.name == "repo_target":
            continue

        label = _category_label(entry.name)
        pair = {"vulnerable": entry / "vulnerable_app", "secure": entry / "secure_app"}

        if pair["vulnerable"].is_dir() or pair["secure"].is_dir():
            # Coppia gemella: una voce per versione.
            openapi = _find_openapi(entry)  # il contratto, se c'è, è condiviso dalla coppia
            for variant, sub in pair.items():
                if not sub.is_dir():
                    continue
                suffix = "vulnerabile" if variant == "vulnerable" else "sicura"
                targets.append(
                    DashboardTarget(
                        id=f"{entry.name}__{variant}",
                        label=f"{label} — {suffix}",
                        group=GROUP_TEST_CASES,
                        target_dir=str(sub),
                        output_dir=f"output/casi_prova/{entry.name}_{variant}",
                        openapi=openapi,
                    )
                )
        elif (entry / "app.py").is_file():
            # Bersaglio a cartella singola (es. bola): espone codice e contratto propri.
            targets.append(
                DashboardTarget(
                    id=entry.name,
                    label=label,
                    group=GROUP_TEST_CASES,
                    target_dir=str(entry),
                    output_dir=f"output/casi_prova/{entry.name}",
                    base_url=DEFAULT_TARGET_BASE_URL,
                    openapi=_find_openapi(entry),
                )
            )
    return targets


def _repo_target() -> DashboardTarget:
    """Il bersaglio ``repo_target`` (applicazione cooperante di validazione)."""
    directory = TEST_TARGETS_DIR / "repo_target"
    return DashboardTarget(
        id="repo_target",
        label="Repo target (applicazione cooperante)",
        group=GROUP_REPO_TARGET,
        target_dir=str(directory),
        output_dir="output/repo_target",
        base_url=DEFAULT_TARGET_BASE_URL,
        openapi=_find_openapi(directory),
        note="Esercita tutti i moduli, incluso il BOLA dinamico con snapshot/rollback.",
    )


def _external_targets() -> list[DashboardTarget]:
    """I bersagli dell'insieme di prova dal registro esterno."""
    out: list[DashboardTarget] = []
    for target in external_targets.load_registry().values():
        out.append(
            DashboardTarget(
                id=target.id,
                label=target.label,
                group=GROUP_TEST_SET,
                target_dir=target.target_dir,
                output_dir=target.output_dir,
                base_url=target.base_url,
                bola_config=target.bola_config,
                external=True,
                note=target.note,
            )
        )
    return out


def build_catalog() -> dict[str, DashboardTarget]:
    """
    Costruisce il catalogo completo dei bersagli locali, indicizzato per id.

    Returns:
        dict[str, DashboardTarget]: bersagli, nell'ordine Repo target, Casi di prova,
        Insieme di prova.
    """
    catalog: dict[str, DashboardTarget] = {}
    for target in (_repo_target(), *_test_case_targets(), *_external_targets()):
        catalog[target.id] = target
    return catalog


def default_target_id() -> str:
    """Bersaglio su cui la dashboard parte se l'ambiente non ne indica un altro."""
    return "repo_target"


def match_by_dirs(
    target_dir: str,
    catalog: dict[str, DashboardTarget] | None = None,
    output_dir: str | None = None,
) -> str | None:
    """
    Id del bersaglio del catalogo la cui ``target_dir`` coincide con quella data.

    Serve a riconoscere, all'avvio, quale voce del catalogo corrisponde al ``TARGET_DIR``
    passato dall'ambiente (compatibilità con i vecchi ``make dashboard-<bersaglio>``). Più voci
    possono condividere il codice (VAmPI vulnerabile e sicuro): ``output_dir``, se dato, le
    distingue.
    """
    catalog = catalog or build_catalog()
    wanted = os.path.normpath(target_dir)
    if output_dir:
        wanted_out = os.path.normpath(output_dir)
        for target in catalog.values():
            if (
                os.path.normpath(target.target_dir) == wanted
                and os.path.normpath(target.output_dir) == wanted_out
            ):
                return target.id
    for target in catalog.values():
        if os.path.normpath(target.target_dir) == wanted:
            return target.id
    return None
