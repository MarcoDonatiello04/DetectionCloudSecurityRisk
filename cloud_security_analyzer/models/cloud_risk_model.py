"""
Aggrega le metriche di rischio e di scansione a livello globale.
Responsabilità:
- Calcolare statistiche aggregate (severità, validazioni, sorgenti).
- Calcolare l'indice di rischio globale normalizzato (0-10).
"""

from typing import List, Dict, Any
from cloud_security_analyzer.models.finding_model import FindingModel
from cloud_security_analyzer.models.endpoint_model import EndpointModel

class CloudRiskModel:
    """
    Rappresenta lo stato del rischio aggregato per l'intera scansione corrente.
    """

    def __init__(self, findings: List[FindingModel], endpoints: List[EndpointModel]):
        """
        Inizializza con la lista corrente di findings ed endpoint.
        """
        self.findings = findings
        self.endpoints = endpoints
        self.stats = self._calculate_stats()

    def _calculate_stats(self) -> Dict[str, Any]:
        """
        Calcola i valori statistici aggregati.
        """
        stats = {
            "total": len(self.findings),
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
            "confirmed": 0,
            "checkov_total": 0, "checkov_critical": 0, "checkov_high": 0, "checkov_medium": 0, "checkov_low": 0,
            "semgrep_total": 0,
            "spectral_total": 0,
            "zap_total": 0,
            "runtime_total": 0,
            
            # Catalog API
            "api_total": len(self.endpoints),
            "api_documented": sum(1 for e in self.endpoints if e.documented),
            "api_shadow": sum(1 for e in self.endpoints if e.shadow),
            "api_violations": sum(e.violation_count for e in self.endpoints),
            
            # BOLA stats
            "bola_total": sum(1 for e in self.endpoints if e.is_dynamic),
            "bola_vulnerable": sum(1 for e in self.endpoints if e.is_dynamic and e.bola_status == "VULNERABLE"),
            "bola_potential": sum(1 for e in self.endpoints if e.is_dynamic and e.bola_status == "POTENTIAL"),
            "bola_safe": sum(1 for e in self.endpoints if e.is_dynamic and e.bola_status == "SAFE")
        }

        for f in self.findings:
            # Severità globale
            sev = f.severity.lower()
            if sev in stats:
                stats[sev] += 1
            
            # Validati empiricamente
            if f.is_confirmed:
                stats["confirmed"] += 1
            
            # Statistiche specifiche per sorgente
            source = f.source
            if source == "CHECKOV":
                stats["checkov_total"] += 1
                if sev in ["critical", "high", "medium", "low"]:
                    stats[f"checkov_{sev}"] += 1
            elif source == "SEMGREP":
                stats["semgrep_total"] += 1
            elif source == "SPECTRAL":
                stats["spectral_total"] += 1
            elif source == "ZAP_DAST":
                stats["zap_total"] += 1
            elif source == "RUNTIME_VALIDATOR":
                stats["runtime_total"] += 1

        return stats

    @property
    def total_findings(self) -> int:
        return self.stats["total"]

    @property
    def critical_count(self) -> int:
        return self.stats["critical"]

    @property
    def high_count(self) -> int:
        return self.stats["high"]

    @property
    def medium_count(self) -> int:
        return self.stats["medium"]

    @property
    def low_count(self) -> int:
        return self.stats["low"]

    @property
    def info_count(self) -> int:
        return self.stats["info"]

    @property
    def confirmed_count(self) -> int:
        return self.stats["confirmed"]

    @property
    def global_risk_score(self) -> float:
        """
        Calcola l'indice di rischio complessivo normalizzato (da 0.0 a 10.0).
        Tiene conto del numero e della gravità dei finding, pesando maggiormente quelli confermati.
        """
        if not self.findings:
            return 0.0

        # Prende il valore massimo dei risk score dei singoli finding, oppure calcola una media pesata.
        # Nelle best practices di security, il rischio del sistema è determinato dal peggior finding confermato.
        max_score = 0.0
        for f in self.findings:
            if f.risk_score > max_score:
                max_score = f.risk_score
                
        return max_score

    @property
    def status_summary(self) -> str:
        """
        Descrive sinteticamente lo stato generale del cloud/API.
        """
        score = self.global_risk_score
        if score >= 9.0:
            return "PERICOLO CRITICO"
        if score >= 7.0:
            return "RISCHIO ELEVATO"
        if score >= 4.5:
            return "RISCHIO MEDIO"
        if score >= 2.0:
            return "RISCHIO BASSO"
        return "SICURO"
