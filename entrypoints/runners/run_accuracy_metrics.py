"""
Metriche di accuratezza su un bersaglio dell'insieme di prova (validation/PROTOCOLLO.md, §6).

Confronta le evidenze di un'esecuzione con il riferimento di verità del bersaglio, applica le
decisioni manuali (se presenti) e scrive metriche.json e metriche.md nella cartella delle
evidenze.

Uso (dalla radice, PYTHONPATH=.):
    python entrypoints/runners/run_accuracy_metrics.py vampi
    python entrypoints/runners/run_accuracy_metrics.py dvapi --evidence validation/risultati/2026-10-01_dvapi
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.application.evaluation.accuracy import (
    evaluate,
    load_decisions,
    load_ground_truth,
    load_signals,
    to_markdown,
)
from src.presentation.api.external_targets import load_registry

GROUND_TRUTH_DIR = Path("validation/ground_truth")
DECISIONS_DIR = Path("validation/classificazioni")
RESULTS_DIR = Path("validation/risultati")


def latest_evidence(target: str) -> Path | None:
    """Archiviazione più recente del bersaglio in validation/risultati/."""
    runs = sorted(p for p in RESULTS_DIR.glob(f"*_{target}") if p.is_dir())
    return runs[-1] if runs else None


def main() -> int:
    parser = argparse.ArgumentParser(description="Metriche di accuratezza su un bersaglio")
    parser.add_argument("target", help="bersaglio del registro (es. vampi, dvapi, sadcloud)")
    parser.add_argument("--evidence", help="cartella delle evidenze (default: la più recente)")
    parser.add_argument("--ground-truth", help="riferimento di verità (default: per bersaglio)")
    parser.add_argument("--decisions", help="decisioni manuali (default: per bersaglio)")
    args = parser.parse_args()

    registry = load_registry()
    target = registry.get(args.target)
    gt_name = args.target.replace("_sicuro", "")
    gt_path = Path(args.ground_truth or GROUND_TRUTH_DIR / f"{gt_name}.yaml")
    evidence = Path(args.evidence) if args.evidence else latest_evidence(args.target)
    if not gt_path.is_file():
        print(f"Riferimento di verità non trovato: {gt_path}")
        return 2
    if evidence is None or not evidence.is_dir():
        print(f"Evidenze non trovate per {args.target}: archiviale dalla sezione Bersagli esterni.")
        return 2

    _, entries = load_ground_truth(gt_path)
    signals = load_signals(evidence, Path(target.target_dir) if target else None)
    decisions = load_decisions(Path(args.decisions or DECISIONS_DIR / f"{args.target}.yaml"))
    report = evaluate(entries, signals, decisions)
    report["bersaglio"] = args.target
    report["evidenze"] = str(evidence)
    report["riferimento"] = str(gt_path)

    (evidence / "metriche.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    markdown = to_markdown(args.target, report)
    (evidence / "metriche.md").write_text(markdown, encoding="utf-8")
    print(markdown)
    print(f"Scritto in {evidence}/metriche.json e metriche.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
