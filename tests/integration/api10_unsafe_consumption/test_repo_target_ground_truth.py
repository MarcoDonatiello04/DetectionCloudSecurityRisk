"""Riferimento di verità di API10 sulle integrazioni della repo target.

A differenza delle app gemelle, i casi includono varianti che il modulo sbaglia:
flussi attraverso helper, connessioni come attributi, client alternativi (Session,
httpx), validazioni passate per keyword, cast che neutralizzano l'input. Il test
fissa la matrice di confusione misurata: se il rilevatore migliora, va aggiornata
qui insieme all'etichetta del caso.
"""

import ast
from pathlib import Path

from src.core.api10_unsafe_consumption import detector

PROJECT_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists())
INTEGRATIONS = PROJECT_ROOT / "data" / "test_targets" / "repo_target" / "integrations"

# (file, funzione) -> (regola, vulnerabile secondo il riferimento di verità)
GROUND_TRUTH = {
    ("supplier_sync.py", "sync_exchange_rates"): ("UC-001", True),
    ("supplier_sync.py", "import_supplier"): ("UC-001", True),
    ("supplier_sync.py", "sync_supplier_quote"): ("UC-001", False),
    ("supplier_sync.py", "record_supplier_rating"): ("UC-001", False),
    ("supplier_sync.py", "refresh_catalog"): ("UC-001", True),
    ("supplier_sync.py", "mirror_order"): ("UC-001", True),
    ("supplier_sync.py", "import_shipment_status"): ("UC-001", True),
    ("supplier_sync.py", "sync_stock_level"): ("UC-001", False),
    ("supplier_sync.py", "register_sku"): ("UC-001", False),
    ("transport.py", "fetch_legacy_orders"): ("UC-002", True),
    ("transport.py", "track_parcel"): ("UC-002", True),
    ("transport.py", "list_payouts"): ("UC-002", False),
    ("transport.py", "local_dev_healthcheck"): ("UC-002", False),
    ("transport.py", "forecast"): ("UC-002", True),
    ("transport.py", "latest_fx_snapshot"): ("UC-002", True),
    ("transport.py", "soap_envelope_prefix"): ("UC-002", False),
    ("outbound.py", "submit_kyc_check"): ("UC-003", True),
    ("outbound.py", "push_crm_contact"): ("UC-003", True),
    ("outbound.py", "submit_kyc_check_strict"): ("UC-003", False),
    ("outbound.py", "partner_status"): ("UC-003", False),
    ("outbound.py", "sync_contact"): ("UC-003", True),
    ("outbound.py", "export_patient_record"): ("UC-003", True),
    ("outbound.py", "send_usage_metrics"): ("UC-003", False),
}

# Matrice misurata per regola: i FN e gli FP sono limiti noti, non regressioni.
EXPECTED_MATRIX = {
    "UC-001": {"TP": 2, "FN": 3, "TN": 2, "FP": 2},
    "UC-002": {"TP": 2, "FN": 2, "TN": 2, "FP": 1},
    "UC-003": {"TP": 2, "FN": 2, "TN": 2, "FP": 1},
}


def _function_spans(path: Path) -> dict[str, tuple[int, int]]:
    tree = ast.parse(path.read_text())
    return {
        node.name: (node.lineno, node.end_lineno)
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
    }


def _detected_by_case() -> tuple[dict[tuple[str, str], set[str]], list]:
    report = detector.analyze(str(INTEGRATIONS))
    spans = {f.name: _function_spans(f) for f in INTEGRATIONS.glob("*.py")}
    detected: dict[tuple[str, str], set[str]] = {}
    orphans = []
    for finding in report.findings:
        file_name = Path(finding.file_path).name
        owner = next(
            (
                name
                for name, (start, end) in spans.get(file_name, {}).items()
                if start <= finding.line_number <= end and (file_name, name) in GROUND_TRUTH
            ),
            None,
        )
        if owner is None:
            orphans.append(finding)
        else:
            detected.setdefault((file_name, owner), set()).add(finding.rule_id)
    return detected, orphans


def _confusion_matrix() -> tuple[dict[str, dict[str, int]], list]:
    detected, orphans = _detected_by_case()
    matrix = {rule: {"TP": 0, "FN": 0, "TN": 0, "FP": 0} for rule in EXPECTED_MATRIX}
    for case, (rule, vulnerable) in GROUND_TRUTH.items():
        rules_fired = detected.get(case, set())
        # Una regola diversa da quella sotto esame che scatta sul caso è un falso positivo.
        for other in rules_fired - {rule}:
            orphans.append((case, other))
        hit = rule in rules_fired
        cell = ("TP" if hit else "FN") if vulnerable else ("FP" if hit else "TN")
        matrix[rule][cell] += 1
    return matrix, orphans


def test_every_finding_belongs_to_a_labelled_case():
    _, orphans = _confusion_matrix()
    assert orphans == [], f"Segnalazioni fuori dai casi etichettati: {orphans}"


def test_confusion_matrix_matches_measured_baseline():
    matrix, _ = _confusion_matrix()
    assert matrix == EXPECTED_MATRIX


def test_known_misses_and_false_alarms():
    """Nomina i casi limite, così un cambio di esito indica quale comportamento è cambiato."""
    detected, _ = _detected_by_case()
    false_negatives = {
        case
        for case, (rule, vulnerable) in GROUND_TRUTH.items()
        if vulnerable and rule not in detected.get(case, set())
    }
    false_positives = {
        case
        for case, (rule, vulnerable) in GROUND_TRUTH.items()
        if not vulnerable and rule in detected.get(case, set())
    }
    assert {name for _, name in false_negatives} == {
        "refresh_catalog",  # flusso attraverso un helper
        "mirror_order",  # self.db.execute non riconosciuto
        "import_shipment_status",  # len() scambiato per validazione
        "forecast",  # http nel default di os.environ.get
        "latest_fx_snapshot",  # http nel base_url di httpx.Client
        "sync_contact",  # requests.Session
        "export_patient_record",  # httpx con follow_redirects=True
    }
    assert {name for _, name in false_positives} == {
        "sync_stock_level",  # int() neutralizza l'input
        "register_sku",  # jsonschema.validate con argomenti keyword
        "soap_envelope_prefix",  # dict.get con chiave un namespace http://
        "send_usage_metrics",  # "data" nel nome, ma dati non sensibili
    }
