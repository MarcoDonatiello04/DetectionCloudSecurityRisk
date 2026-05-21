import sys
import os

# Aggiungiamo la root del progetto al PYTHONPATH per permettere l'importazione dei moduli src.*
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.api_discovery_pipeline import run_pipeline

def main():
    target_dir = "."
    if len(sys.argv) > 1:
        target_dir = sys.argv[1]

    # Avvio della pipeline di API Discovery & Inventory
    run_pipeline(target_dir)

if __name__ == "__main__":
    main()

