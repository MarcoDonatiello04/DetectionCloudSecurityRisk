from typing import List, Dict, Optional
from dataclasses import dataclass, field
from Finding import Finding, FindingSource, Severity, ValidationStatus

@dataclass
class CorrelatedRisk:
    """
    Rappresenta un rischio unificato aggregato per un singolo asset o contesto 
    (es. una rotta API normalizzata o una risorsa Cloud specifica).
    Evita la frammentazione del report unendo i finding statici e le evidenze runtime.
    """
    correlation_key: str
    primary_category: str
    findings: List[Finding] = field(default_factory=list)
    has_runtime_evidence: bool = False
    is_exploitable: bool = False
    highest_severity: Severity = Severity.LOW
    
    def update_severity(self):
        """
        Funzione 4: Scoring Composito (Composite Risk Scoring)
        Calcola la severity combinata. Se un finding statico di gravità HIGH/MEDIUM 
        è confermato a runtime (es. raggiungibile senza auth), il rischio effettivo 
        viene promosso (es. a CRITICAL o HIGH) a dimostrazione del reale impatto.
        """
        severity_values = {
            Severity.INFO: 1,
            Severity.LOW: 2,
            Severity.MEDIUM: 3,
            Severity.HIGH: 4,
            Severity.CRITICAL: 5
        }
        
        max_sev = Severity.INFO
        max_val = 0
        for f in self.findings:
            val = severity_values.get(f.severity, 1)
            if val > max_val:
                max_val = val
                max_sev = f.severity
                
        # Promozione del rischio se confermato ed esplorabile a runtime (Static + Runtime correlation)
        if self.has_runtime_evidence and self.is_exploitable:
            if max_sev == Severity.HIGH:
                max_sev = Severity.CRITICAL
            elif max_sev == Severity.MEDIUM:
                max_sev = Severity.HIGH
                
        self.highest_severity = max_sev


class CorrelationEngine:
    """
    Motore di Correlazione minimo e corretto per unificare i Finding di Cloud & API Security.
    Progettato appositamente senza over-engineering o logiche enterprise complesse,
    ideale per un progetto di tesi incentrato sull'efficacia del rilevamento.
    """
    def __init__(self):
        self._raw_findings: Dict[str, Finding] = {}
        
    def ingest(self, findings: List[Finding]):
        """
        Funzione 1: Deduplicazione (Deduplication)
        Ingerisce i finding eliminando i duplicati esatti basandosi sul finding_id deterministico
        generato dai runner. Garantisce l'idempotenza delle scansioni.
        """
        for f in findings:
            if f.finding_id not in self._raw_findings:
                self._raw_findings[f.finding_id] = f

    def correlate(self) -> List[CorrelatedRisk]:
        """
        Funzione 2 & 3: Asset Clustering & Static-Runtime Linking
        Raggruppa i finding che condividono la stessa correlation_key (es. un endpoint OpenAPI
        o una risorsa Terraform) e collega le vulnerabilità statiche con i responsi di runtime.
        """
        clusters: Dict[str, CorrelatedRisk] = {}
        
        # Iteriamo su tutti i finding deduplicati
        for f in self._raw_findings.values():
            # Chiave di aggregazione semantica
            key = f.correlation_key or f"asset-{f.resource_id or f.finding_id}"
            
            if key not in clusters:
                clusters[key] = CorrelatedRisk(
                    correlation_key=key,
                    primary_category=f.category.value
                )
            
            cluster = clusters[key]
            cluster.findings.append(f)
            
            # Funzione 3: Link Statico/Runtime
            # Se il finding è di tipo dinamico o ha una runtime_evidence iniettata
            if f.source == FindingSource.RUNTIME_VALIDATOR or f.validation_status == ValidationStatus.CONFIRMED:
                cluster.has_runtime_evidence = True
                cluster.is_exploitable = True
            elif f.runtime_evidence is not None:
                cluster.has_runtime_evidence = True
                if f.runtime_evidence.accessible_without_auth or f.runtime_evidence.http_status == 200:
                    cluster.is_exploitable = True
                    
        # Funzione 4: Punteggio e ordinamento dei rischi
        res = []
        for risk in clusters.values():
            risk.update_severity()
            res.append(risk)
            
        # Ordiniamo i cluster per gravità decrescente
        severity_rank = {
            Severity.CRITICAL: 1,
            Severity.HIGH: 2,
            Severity.MEDIUM: 3,
            Severity.LOW: 4,
            Severity.INFO: 5
        }
        res.sort(key=lambda r: severity_rank.get(r.highest_severity, 6))
        return res
