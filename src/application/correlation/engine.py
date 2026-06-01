import logging
from typing import List, Dict, Any
from src.domain.entities import Finding, Severity, ValidationStatus, FindingSource, FindingCategory
from src.normalization.normalizer import APIEndpointNormalizer

logger = logging.getLogger("SecurityPlatform.CorrelationEngine")


class RiskCorrelationEngine:
    """
    Motore di Correlazione e Scoring.
    Raggruppa i findings statici (IaC/AST) e runtime (DAST/Traffic) basandosi su chiavi
    di risorsa e path API normalizzati. Conferma le vulnerabilità (validation_status)
    e calcola un punteggio di rischio complessivo pesato.
    """

    def __init__(self):
        self.correlated_findings: Dict[str, Finding] = {}

    def correlate(self, static_findings: List[Finding], runtime_findings: List[Finding]) -> List[Finding]:
        """
        Unisce i findings statici e runtime in un inventario correlato.
        Se un rischio statico trova riscontro in un test o log a runtime, lo convalida (CONFIRMED)
        e adegua la severity ed il punteggio di rischio.
        """
        self.correlated_findings = {}

        # 1. Indicizziamo prima i findings statici nel registro usando una chiave logica di risorsa
        for sf in static_findings:
            key = self._get_correlation_key(sf)
            if key not in self.correlated_findings:
                self.correlated_findings[key] = sf
            else:
                # Se c'è già una vulnerabilità sulla stessa risorsa, uniamo le informazioni
                existing = self.correlated_findings[key]
                self._merge_findings(existing, sf)

        # 2. Correliamo con i findings di runtime
        for rf in runtime_findings:
            key = self._get_correlation_key(rf)
            
            if key in self.correlated_findings:
                existing = self.correlated_findings[key]
                logger.info(f"🔗 Correlazione trovata per la chiave: {key}")
                
                # Caso importante: avevamo previsto la vulnerabilità staticamente e ora l'abbiamo confermata a runtime!
                # Aggiorniamo lo stato di convalida a CONFIRMED
                existing.validation_status = ValidationStatus.CONFIRMED
                existing.runtime_evidence = rf.runtime_evidence
                
                # Boost della severity e confidence in quanto verificata empiricamente a runtime
                if existing.severity.score < Severity.CRITICAL.score:
                    logger.info(f"🔺 Elevazione Severity per {existing.finding_id} da {existing.severity.value} a HIGH/CRITICAL per riscontro a runtime.")
                    existing.severity = Severity.CRITICAL if existing.severity == Severity.HIGH else Severity.HIGH
                
                existing.confidence = 1.0
                if rf.finding_id not in existing.related_findings:
                    existing.related_findings.append(rf.finding_id)
                    
                # Uniamo dati grezzi aggiuntivi
                existing.raw_data[f"runtime_verification_{rf.finding_id}"] = rf.raw_data
            else:
                # Trovato a runtime ma non previsto dall'analisi statica (es: Shadow API o vulnerabilità zero-day)
                # Lo registriamo come nuovo finding con validation_status = NOT_VALIDATED o CONFIRMED (in quanto testato direttamente)
                rf.validation_status = ValidationStatus.CONFIRMED
                rf.confidence = 0.9
                self.correlated_findings[key] = rf

        return list(self.correlated_findings.values())

    def calculate_risk_score(self, finding: Finding) -> float:
        """
        Calcola un punteggio di rischio numerico normalizzato (0.0 - 10.0).
        Formula: (Severità * 0.6) + (Confidenza * 0.2) + (ContextMultiplier * 0.2)
        """
        sev_score = finding.severity.score
        conf_score = finding.confidence * 10.0
        
        # Moltiplicatore di contesto (es: esposto a internet, dati sensibili)
        context_score = 0.0
        if finding.risk_context:
            if finding.risk_context.internet_exposed:
                context_score += 4.0
            if finding.risk_context.sensitive_data_detected:
                context_score += 4.0
            if finding.risk_context.public_resource:
                context_score += 2.0
        else:
            # Default basato sulla categoria
            if finding.category in (FindingCategory.AUTHENTICATION, FindingCategory.AUTHORIZATION):
                context_score = 6.0
            else:
                context_score = 3.0

        # Calcolo pesato
        risk_score = (sev_score * 0.6) + (conf_score * 0.2) + (context_score * 0.2)
        return round(min(risk_score, 10.0), 2)

    def _get_correlation_key(self, finding: Finding) -> str:
        """Determina la chiave logica per raggruppare i findings."""
        if finding.correlation_key:
            return finding.correlation_key
            
        # Per le API, usiamo METHOD + Path normalizzato
        if finding.api and finding.api.endpoint:
            norm_path = APIEndpointNormalizer.normalize_path(finding.api.endpoint)
            method = (finding.api.method or "GET").upper()
            return f"api:{method}:{norm_path}"
            
        # Per risorse cloud/IaC, usiamo il resource_id o resource_name
        if finding.resource_id:
            return f"resource:{finding.resource_id}"
            
        # Fallback al target localizzato (es: file e riga)
        if finding.location:
            return f"file:{finding.location.file_path}:{finding.location.start_line or 0}"
            
        return f"generic:{finding.finding_id}"

    def _merge_findings(self, target: Finding, source: Finding) -> None:
        """Sincronizza due findings statici sulla stessa risorsa."""
        # Se la sorgente ha severity maggiore, la eleviamo
        if source.severity.score > target.severity.score:
            target.severity = source.severity
            
        # Uniamo i riferimenti
        if source.finding_id not in target.related_findings:
            target.related_findings.append(source.finding_id)
            
        # Uniamo tag e referenze
        target.tags = list(set(target.tags + source.tags))
        target.references = list(set(target.references + source.references))
        
        # Conserviamo dati grezzi aggiuntivi
        target.raw_data[f"merged_{source.finding_id}"] = source.raw_data
