import os
from src.infrastructure.adapters.spectral_adapter import SpectralScannerAdapter
from src.domain.entities import FindingSource

def test_spectral_scanner_adapter_execution():
    # Inizializza l'adapter
    adapter = SpectralScannerAdapter()
    
    # Verifica che il file del contratto OpenAPI di test esista
    target_openapi = "problema_api/openapi.yaml"
    assert os.path.exists(target_openapi), "Il file openapi.yaml di test non esiste"
    
    # Esegue lo scan
    findings = adapter.scan(target_openapi)
    
    # Verifica che la scansione abbia prodotto findings e che siano di tipo SPECTRAL
    assert len(findings) > 0, "Spectral non ha prodotto alcuna segnalazione"
    
    has_route_specific = False
    has_global = False
    
    for finding in findings:
        assert finding.source == FindingSource.SPECTRAL
        assert finding.rule_id is not None
        assert finding.description is not None
        # Verifica che il file di origine sia corretto
        assert target_openapi in finding.location.file_path
        
        if finding.api is not None:
            has_route_specific = True
            # Dovrebbe essere None in modo che RiskCorrelationEngine lo calcoli a runtime per la rotta
            assert finding.correlation_key is None, f"Atteso correlation_key None per rotta, trovato {finding.correlation_key}"
        else:
            has_global = True
            # Dovrebbe iniziare con openapi: per evitare fusioni totali
            assert finding.correlation_key.startswith("openapi:"), f"Atteso correlation_key openapi:*, trovato {finding.correlation_key}"
            
    assert has_route_specific, "Dovrebbero esserci violazioni specifiche per le rotte"
    assert has_global, "Dovrebbero esserci violazioni globali del contratto"

