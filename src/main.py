import sys
import os

# Aggiungiamo la root del progetto al PYTHONPATH per permettere l'importazione dei moduli src.*
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.scanners.checkov_runner import run_checkov
from src.scanners.semgrep_runner import run_semgrep
from src.scanners.spectral_runner import run_spectral
from src.core.shadow_api_hunter import run_shadow_api_hunter
from src.core.report_builder import consolidate_reports

def main():
    target_dir = "."
    if len(sys.argv) > 1:
        target_dir = sys.argv[1]

    print(f"🎯 Target della scansione: {target_dir}")

    checkov_data = run_checkov(target_dir)
    spectral_data = run_spectral(target_dir)
    semgrep_data = run_semgrep(target_dir)
    shadow_apis = run_shadow_api_hunter(target_dir)
    
    consolidate_reports(spectral_data, checkov_data, semgrep_data, shadow_apis)

if __name__ == "__main__":
    main()
