"""
Metriche di accuratezza sui bersagli con riferimento di verità (validation/PROTOCOLLO.md, §6).

Confronta le segnalazioni prodotte dallo strumento su un bersaglio con le voci del suo
riferimento di verità (validation/ground_truth/<bersaglio>.yaml) e calcola, per categoria
OWASP, veri positivi, falsi negativi, recall complessiva e nel perimetro, precisione.

Regola di corrispondenza, fissata nei riferimenti prima dell'esecuzione: una segnalazione
corrisponde a una voce se ha la stessa categoria OWASP (o l'alternativa accettata) e lo stesso
punto di esposizione, cioè metodo e percorso normalizzato, qualunque sia il livello che l'ha
prodotta. Le segnalazioni dei livelli statici che indicano un file e una riga, ma non un
endpoint, corrispondono quando cadono nella funzione che il riferimento indica come posizione
dichiarata della voce: è lo stesso punto di esposizione, identificato dal codice anziché
dalla rotta.

Ciò che la regola affida al giudizio umano non viene deciso qui:
- le voci con punto di esposizione "globale" e le voci senza endpoint (sadcloud) producono
  solo CANDIDATI, che diventano VP o FN con una decisione esplicita;
- le segnalazioni che non corrispondono a nessuna voce restano "da classificare" finché non
  vengono classificate come vero positivo non documentato, falso positivo o indeterminate.
Le decisioni stanno in validation/classificazioni/<bersaglio>.yaml, ciascuna con il motivo.
Senza decisioni, la precisione è riportata come limite inferiore.
"""

from __future__ import annotations

import ast
import json
import re
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Categoria OWASP API 2023 di ogni modulo Core (chiavi di core_findings.json)
CATEGORY_BY_MODULE = {
    "bola": "API1",
    "bola_static": "API1",
    "broken_authentication": "API2",
    "bopla": "API3",
    "unrestricted_resource_consumption": "API4",
    "bfla": "API5",
    "ssrf": "API7",
    "security_misconfiguration": "API8",
    "unsafe_consumption": "API10",
}

OUT_OF_TOP10 = "FUORI_TOP10"
HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

# Esiti di una voce del riferimento
VP, FN, CANDIDATE, OUT_OF_SCOPE, EXCLUDED = (
    "VP",
    "FN",
    "CANDIDATO",
    "FUORI_PERIMETRO",
    "ESCLUSA",
)

# Classi manuali di una segnalazione non corrispondente
SIGNAL_CLASSES = ("vero_non_documentato", "falso_positivo", "indeterminato")

_API_RULE = re.compile(r"api(\d{1,2})(?!\d)", re.IGNORECASE)
_POSITION = re.compile(r"^\s*([^,\[]+?)\s*,\s*([A-Za-z_][\w.]*)")


# ─── Modello ─────────────────────────────────────────────────────────────────


@dataclass
class Signal:
    """Segnalazione dello strumento, ridotta a ciò che serve alla corrispondenza."""

    id: str
    origin: str  # modulo Core o sorgente statica (SPECTRAL, CHECKOV)
    category: str | None  # API1..API10, "IAC" o None se non attribuibile
    title: str
    method: str | None = None
    path: str | None = None
    file: str | None = None
    line: int | None = None
    function: str | None = None
    application_level: bool = False

    @property
    def exposure(self) -> str:
        if self.method and self.path:
            return f"{self.method} {self.path}"
        if self.file:
            where = f"{self.file}:{self.line}" if self.line else self.file
            return f"{where} ({self.function})" if self.function else where
        return "applicazione"


@dataclass
class Entry:
    """Voce del riferimento di verità."""

    id: str
    name: str
    category: str
    alternative: str | None = None
    method: str | None = None
    path: str | None = None
    is_global: bool = False
    position_file: str | None = None
    position_function: str | None = None
    module_dir: str | None = None  # sadcloud: modulo Terraform del servizio

    @property
    def categories(self) -> set[str]:
        return {c for c in (self.category, self.alternative) if c}

    @property
    def counted(self) -> bool:
        return self.category != OUT_OF_TOP10


@dataclass
class EntryResult:
    entry: Entry
    outcome: str
    how: str = ""  # "percorso", "posizione", "decisione"
    signals: list[str] = field(default_factory=list)
    candidates: list[str] = field(default_factory=list)
    reason: str = ""


# ─── Caricamento ─────────────────────────────────────────────────────────────


def normalize_path(path: str | None) -> str | None:
    """Percorso confrontabile: parametri come {x} (anche <x> e :x), senza slash finale."""
    if not path:
        return None
    path = path.split("?", 1)[0].strip()
    segments = []
    for seg in path.strip("/").split("/"):
        if re.fullmatch(r"<[^>]+>|\{[^}]+\}|:[A-Za-z_]\w*", seg):
            seg = "{}"
        segments.append(seg)
    return "/" + "/".join(segments) if segments != [""] else "/"


def path_matches(signal_path: str | None, entry_path: str | None) -> bool:
    """
    Stesso punto di esposizione: segmento per segmento, un parametro della voce accetta
    qualunque valore (la BOLA dinamica riporta percorsi concreti, es. /books/v1/titolo).
    """
    a, b = normalize_path(signal_path), normalize_path(entry_path)
    if a is None or b is None:
        return False
    sa, sb = a.strip("/").split("/"), b.strip("/").split("/")
    if len(sa) != len(sb):
        return False
    return all(y == "{}" or x == y for x, y in zip(sa, sb, strict=True))


def load_ground_truth(path: Path) -> tuple[str, list[Entry]]:
    """Legge un riferimento di verità (formato di validation/ground_truth/)."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries = []
    for v in raw.get("voci") or []:
        point = v.get("punto_esposizione")
        method = path_ = None
        is_global = point == "globale"
        if isinstance(point, dict):
            method = str(point.get("metodo", "")).upper() or None
            path_ = point.get("percorso")
        file_ = func = None
        m = _POSITION.match(v.get("posizione_dichiarata", "") or "")
        if m:
            file_, func = m.group(1).strip(), m.group(2).split(".")[-1]
        # Percorso del modulo relativo alla radice Terraform del bersaglio
        module_dir = v.get("modulo_terraform")
        category = v.get("categoria_owasp_2023") or ("IAC" if module_dir else None)
        entries.append(
            Entry(
                id=v["id"],
                name=v.get("nome_autore")
                or v.get("etichetta_autore")
                or v.get("misconfigurazione")
                or v["id"],
                category=str(category),
                alternative=v.get("alternativa_accettata"),
                method=method,
                path=path_,
                is_global=is_global,
                position_file=file_,
                position_function=func,
                module_dir=module_dir,
            )
        )
    return raw.get("bersaglio", path.stem), entries


def _enclosing_function(source_root: Path | None, file: str, line: int | None) -> str | None:
    """Nome della funzione Python che contiene la riga, se ricavabile."""
    if not source_root or not line or not file.endswith(".py"):
        return None
    candidate = Path(file)
    if not candidate.is_absolute():
        for base in (Path("."), source_root):
            if (base / file).is_file():
                candidate = base / file
                break
    if not candidate.is_file():
        return None
    try:
        with warnings.catch_warnings():
            # Il codice dei bersagli può contenere sequenze di escape non valide: irrilevante qui.
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(candidate.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return None
    best: tuple[int, str] | None = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", node.lineno)
            if node.lineno <= line <= end and (best is None or node.lineno > best[0]):
                best = (node.lineno, node.name)
    return best[1] if best else None


def _relative(file: str | None, target_dir: Path | None) -> str | None:
    if not file:
        return None
    file = file.replace("\\", "/")
    if target_dir:
        prefix = str(target_dir).rstrip("/") + "/"
        if file.startswith(prefix):
            return file[len(prefix) :]
    return file.lstrip("/")


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def load_signals(evidence_dir: Path, target_dir: Path | None = None) -> list[Signal]:
    """
    Segnalazioni dalle evidenze di un'esecuzione: moduli Core (core_findings.json) e
    scansione statica (unified_security_report.json). L'inventario delle rotte (Semgrep) non
    è una segnalazione e viene escluso.
    """
    signals: list[Signal] = []
    seen: set[str] = set()

    def add(sig: Signal) -> None:
        if sig.id not in seen:
            seen.add(sig.id)
            signals.append(sig)

    core = evidence_dir / "core_findings.json"
    if core.is_file():
        modules = json.loads(core.read_text(encoding="utf-8")).get("findings", {})
        for module, items in modules.items():
            category = CATEGORY_BY_MODULE.get(module)
            for item in items or []:
                if module == "bola":
                    if not item.get("is_vulnerable"):
                        continue  # esiti sicuri e prove non vulnerabili non sono segnalazioni
                    method = str(item.get("method", "GET")).upper()
                    path = item.get("endpoint")
                    add(
                        Signal(
                            id=f"bola:{method} {path}",
                            origin=module,
                            category=category,
                            title=item.get("title", ""),
                            method=method,
                            path=path,
                        )
                    )
                    continue
                if module == "broken_authentication":
                    if item.get("stato") != "FAIL":
                        continue
                    add(
                        Signal(
                            id=f"broken_authentication:{item.get('test_id')}",
                            origin=module,
                            category=category,
                            title=f"{item.get('test_id')} {item.get('nome', '')}".strip(),
                            application_level=True,
                        )
                    )
                    continue
                file_ = _relative(item.get("file_path"), target_dir)
                line = _as_int(item.get("line_number"))
                endpoint = item.get("endpoint")
                endpoint = endpoint if endpoint and endpoint != "None" else None
                methods = item.get("http_methods") or (
                    [item["method"]] if item.get("method") else []
                )
                if isinstance(methods, str):
                    methods = re.findall(r"[A-Z]+", methods)
                rule = item.get("rule_id") or module
                function = _enclosing_function(target_dir, item.get("file_path") or "", line)
                for method in methods or [None]:
                    method = method.upper() if method and method.upper() in HTTP_METHODS else None
                    key = f"{module}:{rule}:{method or ''} {endpoint or ''}:{file_}:{line}"
                    add(
                        Signal(
                            id=key,
                            origin=module,
                            category=category,
                            title=f"{rule} {item.get('category', '')}".strip(),
                            method=method,
                            path=endpoint,
                            file=file_,
                            line=line,
                            function=function,
                            application_level=not (endpoint or line),
                        )
                    )

    static = evidence_dir / "unified_security_report.json"
    if static.is_file():
        for f in json.loads(static.read_text(encoding="utf-8")):
            source = f.get("source")
            rule = f.get("rule_id") or ""
            raw = f.get("raw_data") or {}
            if source == "SEMGREP" and rule == "api-route-discovery":
                continue
            if source == "SPECTRAL":
                m = _API_RULE.search(rule)
                category = f"API{int(m.group(1))}" if m else None
                method = path = None
                parts = raw.get("path") or []
                if len(parts) >= 2 and parts[0] == "paths":
                    path = parts[1]
                    if len(parts) >= 3 and str(parts[2]).upper() in HTTP_METHODS:
                        method = str(parts[2]).upper()
                line = _as_int((f.get("location") or {}).get("start_line"))
                add(
                    Signal(
                        id=f"spectral:{rule}:{method or ''} {path or ''}:{line}",
                        origin="SPECTRAL",
                        category=category,
                        title=rule,
                        method=method,
                        path=path,
                        application_level=path is None,
                    )
                )
            elif source == "CHECKOV":
                # Il motore di correlazione riunisce i controlli sulla stessa risorsa: la voce
                # porta il controllo rappresentativo in raw_data e quelli assorbiti, completi,
                # sotto le chiavi merged_<id>. Ogni controllo è una segnalazione.
                checks = [raw] + [
                    v for k, v in raw.items() if k.startswith("merged_") and isinstance(v, dict)
                ]
                for chk in checks:
                    file_ = (chk.get("file_path") or "").lstrip("/")
                    check_id = chk.get("check_id") or rule
                    resource = chk.get("resource") or ""
                    add(
                        Signal(
                            id=f"checkov:{check_id}:{resource}",
                            origin="CHECKOV",
                            category="IAC",
                            title=f"{check_id} {chk.get('check_name') or f.get('title', '')}",
                            file=file_,
                        )
                    )
    return signals


def load_decisions(path: Path | None) -> dict[str, Any]:
    """Decisioni manuali: {"voci": {id: {...}}, "segnalazioni": {id: {...}}}."""
    if not path or not path.is_file():
        return {"voci": {}, "segnalazioni": {}}
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {"voci": raw.get("voci") or {}, "segnalazioni": raw.get("segnalazioni") or {}}


# ─── Valutazione ─────────────────────────────────────────────────────────────


def _same_position(signal: Signal, entry: Entry) -> bool:
    if not (entry.position_file and entry.position_function and signal.file):
        return False
    return signal.file.endswith(entry.position_file) and signal.function == entry.position_function


def match_entry(entry: Entry, signals: list[Signal]) -> EntryResult:
    """Applica la regola di corrispondenza automatica a una voce."""
    if not entry.counted:
        return EntryResult(entry, EXCLUDED, reason="fuori dalla Top 10 API 2023")
    if entry.module_dir:  # voce infrastrutturale: corrispondenza da stabilire a mano
        # Prefisso di cartella, non di stringa: modules/aws/elb non deve includere elbv2.
        prefix = entry.module_dir.strip("/") + "/"
        cands = [
            s.id for s in signals if s.category == "IAC" and s.file and s.file.startswith(prefix)
        ]
        return EntryResult(entry, CANDIDATE if cands else FN, candidates=cands)
    cat = [s for s in signals if s.category in entry.categories]
    by_path = [
        s.id
        for s in cat
        if entry.method and s.method == entry.method and path_matches(s.path, entry.path)
    ]
    if by_path:
        return EntryResult(entry, VP, how="percorso", signals=by_path)
    by_position = [s.id for s in cat if _same_position(s, entry)]
    if by_position:
        return EntryResult(entry, VP, how="posizione", signals=by_position)
    # Senza corrispondenza automatica, le segnalazioni della stessa categoria che non indicano
    # un endpoint (livello applicativo o solo file e riga) possono descrivere la stessa
    # debolezza: sono candidate, e la decisione spetta a una classificazione manuale.
    cands = [s.id for s in cat if not s.path]
    return EntryResult(entry, CANDIDATE if cands else FN, candidates=cands)


def evaluate(
    entries: list[Entry], signals: list[Signal], decisions: dict[str, Any] | None = None
) -> dict[str, Any]:
    """
    Esito di ogni voce e di ogni segnalazione, e metriche per categoria e complessive.

    Le decisioni manuali risolvono i candidati, dichiarano voci fuori perimetro e classificano
    le segnalazioni non corrispondenti. Una decisione non può trasformare in VP una voce senza
    indicare la segnalazione che la copre.
    """
    decisions = decisions or {"voci": {}, "segnalazioni": {}}
    signal_ids = {s.id for s in signals}
    results: list[EntryResult] = []
    for entry in entries:
        res = match_entry(entry, signals)
        dec = decisions["voci"].get(entry.id) or {}
        if dec.get("fuori_perimetro") and res.outcome != VP:
            res.outcome, res.how, res.reason = OUT_OF_SCOPE, "decisione", dec["fuori_perimetro"]
        elif res.outcome in (CANDIDATE, FN) and dec.get("esito") in (VP, FN):
            covering = [s for s in (dec.get("segnalazioni") or []) if s in signal_ids]
            if dec["esito"] == VP and not covering:
                raise ValueError(
                    f"{entry.id}: una decisione VP deve citare una segnalazione esistente"
                )
            res.outcome, res.how, res.reason = dec["esito"], "decisione", dec.get("motivo", "")
            res.signals = covering
        results.append(res)

    matched = {sid for r in results if r.outcome == VP for sid in r.signals}
    candidate_ids = {sid for r in results if r.outcome == CANDIDATE for sid in r.candidates}
    scope = {c for e in entries if e.counted for c in e.categories}
    signal_rows = []
    for s in signals:
        if s.id in matched:
            klass = "corrispondente"
        else:
            manual = (decisions["segnalazioni"].get(s.id) or {}).get("classe")
            klass = manual if manual in SIGNAL_CLASSES else "da_classificare"
        signal_rows.append(
            {
                "id": s.id,
                "origine": s.origin,
                "categoria": s.category,
                "punto": s.exposure,
                "titolo": s.title,
                "classe": klass,
                "candidata": s.id in candidate_ids,
                "in_ambito": s.category in scope,
            }
        )

    def metrics(cats: set[str] | None) -> dict[str, Any]:
        rs = [r for r in results if r.entry.counted and (cats is None or r.entry.category in cats)]
        vp = sum(r.outcome == VP for r in rs)
        fn = sum(r.outcome == FN for r in rs)
        cand = sum(r.outcome == CANDIDATE for r in rs)
        oos = sum(r.outcome == OUT_OF_SCOPE for r in rs)
        total = len(rs)
        in_scope = total - oos
        sig = [
            x for x in signal_rows if x["in_ambito"] and (cats is None or x["categoria"] in cats)
        ]
        corr = sum(x["classe"] == "corrispondente" for x in sig)
        true_undoc = sum(x["classe"] == "vero_non_documentato" for x in sig)
        fp = sum(x["classe"] == "falso_positivo" for x in sig)
        pending = sum(x["classe"] in ("da_classificare", "indeterminato") for x in sig)
        return {
            "voci": total,
            "vp": vp,
            "fn": fn,
            "candidati": cand,
            "fuori_perimetro": oos,
            "recall": vp / total if total else None,
            "recall_massima": (vp + cand) / total if total else None,
            "recall_nel_perimetro": vp / in_scope if in_scope else None,
            "segnalazioni": len(sig),
            "corrispondenti": corr,
            "vere_non_documentate": true_undoc,
            "falsi_positivi": fp,
            "da_classificare": pending,
            # Limite inferiore: ogni segnalazione non ancora classificata conta come errata.
            "precisione_minima": (corr + true_undoc) / len(sig) if sig else None,
            # Precisione: definita solo quando ogni segnalazione in ambito è classificata;
            # prima di allora vale soltanto il limite inferiore.
            "precisione": (
                (corr + true_undoc) / (corr + true_undoc + fp)
                if pending == 0 and (corr + true_undoc + fp)
                else None
            ),
        }

    categories = sorted({r.entry.category for r in results if r.entry.counted}, key=_cat_key)
    return {
        "voci": [
            {
                "id": r.entry.id,
                "nome": r.entry.name,
                "categoria": r.entry.category,
                "alternativa": r.entry.alternative,
                "punto": (
                    f"{r.entry.method} {r.entry.path}"
                    if r.entry.method
                    else ("globale" if r.entry.is_global else (r.entry.module_dir or ""))
                ),
                "esito": r.outcome,
                "come": r.how,
                "segnalazioni": r.signals,
                "candidati": r.candidates,
                "motivo": r.reason,
            }
            for r in results
        ],
        "segnalazioni": signal_rows,
        "per_categoria": {c: metrics({c}) for c in categories},
        "complessivo": metrics(None),
    }


def _cat_key(cat: str) -> tuple[int, str]:
    m = re.match(r"API(\d+)", cat)
    return (int(m.group(1)) if m else 99, cat)


def to_markdown(target: str, report: dict[str, Any]) -> str:
    """Rapporto leggibile delle metriche, con l'esito di ogni voce."""

    def pct(x: float | None) -> str:
        return "–" if x is None else f"{100 * x:.0f}%"

    lines = [f"# Metriche di accuratezza — {target}", ""]
    lines += [
        "| Categoria | Voci | VP | FN | Candidati | Fuori perimetro | Recall | Recall nel perimetro | Precisione minima |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    rows = [*report["per_categoria"].items(), ("Totale", report["complessivo"])]
    for cat, m in rows:
        lines.append(
            f"| {cat} | {m['voci']} | {m['vp']} | {m['fn']} | {m['candidati']} | "
            f"{m['fuori_perimetro']} | {pct(m['recall'])} | {pct(m['recall_nel_perimetro'])} | "
            f"{pct(m['precisione_minima'])} |"
        )
    lines += [
        "",
        "## Voci",
        "",
        "| Voce | Categoria | Punto | Esito | Come | Segnalazioni / motivo |",
        "|---|---|---|---|---|---|",
    ]
    for v in report["voci"]:
        detail = (
            ", ".join(v["segnalazioni"])
            or v["motivo"]
            or (f"{len(v['candidati'])} candidati" if v["candidati"] else "")
        )
        lines.append(
            f"| {v['id']} {v['nome']} | {v['categoria']} | {v['punto']} | {v['esito']} | "
            f"{v['come']} | {detail} |"
        )
    c = report["complessivo"]
    lines += [
        "",
        f"Segnalazioni in ambito: {c['segnalazioni']} — corrispondenti {c['corrispondenti']}, "
        f"vere non documentate {c['vere_non_documentate']}, falsi positivi {c['falsi_positivi']}, "
        f"da classificare {c['da_classificare']}.",
    ]
    return "\n".join(lines) + "\n"
