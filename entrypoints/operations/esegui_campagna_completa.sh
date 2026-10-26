#!/bin/bash
# Campagna completa: tutti i moduli su tutti i bersagli, in sequenza.
#
# Bersaglio interno (repo_target, dashboard principale) e bersagli esterni (dashboard dedicate
# della sezione "Bersagli esterni"): scansione statica (/scan) e poi scansione completa dei
# moduli Core, BOLA dinamica inclusa (/api/scan/all). Seguono le validazioni interne.
#
# Prerequisiti: servizi della piattaforma e bersagli preparati (pagina /external-targets,
# "Prepara tutti i bersagli"). Le esecuzioni sono in sequenza: le scansioni dinamiche
# condividono lo stesso ZAP.
#
# Uso: bash entrypoints/operations/esegui_campagna_completa.sh [cartella_log]
set -u

STAMP="$(date +%Y%m%d_%H%M%S)"
LOG_DIR="${1:-output/campagna/$STAMP}"
mkdir -p "$LOG_DIR"
SUMMARY="$LOG_DIR/riepilogo.tsv"
printf "passo\tesito\tsecondi\tlog\n" > "$SUMMARY"
PY=.venv/bin/python

step() {
    # step <nome> <comando...>
    local name="$1"; shift
    local log="$LOG_DIR/${name}.log"
    local start end rc
    echo "▶ $name"
    start=$(date +%s)
    "$@" > "$log" 2>&1
    rc=$?
    end=$(date +%s)
    printf "%s\t%s\t%s\t%s\n" "$name" "$([ $rc -eq 0 ] && echo ok || echo "errore($rc)")" \
        "$((end - start))" "$log" >> "$SUMMARY"
    echo "  → $([ $rc -eq 0 ] && echo ok || echo "errore $rc") in $((end - start)) s"
}

scan_dashboard() {
    # scan_dashboard <nome> <porta>
    local name="$1" port="$2" base="http://localhost:$2"
    step "${name}_statica" curl -sS --noproxy '*' --fail-with-body -X POST "$base/scan" \
        -o "$LOG_DIR/${name}_statica.json"
    step "${name}_moduli_core" curl -sS --noproxy '*' --fail-with-body -X POST \
        "$base/api/scan/all" -o "$LOG_DIR/${name}_moduli_core.json"
}

echo "Campagna completa — log in $LOG_DIR"

# 1. Bersaglio interno e bersagli esterni, tutti i moduli
scan_dashboard interno_repo_target 8000
scan_dashboard vampi 8101
scan_dashboard vampi_sicuro 8102
scan_dashboard dvapi 8103
scan_dashboard sadcloud 8104

# 2. Validazioni interne (riferimenti di verità dei moduli e campagna di validazione)
export PYTHONPATH=.
step validazioni_campagna "$PY" entrypoints/runners/run_all_validations.py
step gt_api1_bola_statica "$PY" tests/unit/api1_bola/validate_static_ground_truth.py
step gt_api4_resource "$PY" tests/unit/api4_resource_consumption/validate_ground_truth.py
step gt_api5_bfla "$PY" tests/unit/api5_bfla/validate_ground_truth.py
step gt_api7_ssrf "$PY" tests/unit/api7_ssrf/validate_ground_truth.py
step gt_api8_misconfig "$PY" tests/unit/api8_security_misconfig/validate_ground_truth.py
step gt_api10_unsafe "$PY" tests/unit/api10_unsafe_consumption/validate_ground_truth.py
step iac_analysis bash entrypoints/operations/run_iac_analysis.sh
step test_suite "$PY" -m pytest -q -p no:warnings

echo "Fine. Riepilogo: $SUMMARY"
column -t -s $'\t' "$SUMMARY"
