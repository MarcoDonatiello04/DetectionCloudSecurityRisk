"""
Modello dati della Remediation Intelligence.
Responsabilità:
- Rappresentare in modo strutturato una remediation arricchita.
- Fornire metodi di conversione e formattazione dei dati per la GUI.
"""

from typing import List, Dict, Any

class RemediationModel:
    """
    Modello dati che incapsula le informazioni correttive e di impatto di una vulnerabilità.
    """

    def __init__(
        self,
        finding_id: str,
        title: str,
        severity: str,
        description: str,
        impact: str,
        remediation_steps: List[str],
        example: str,
        source: str = "knowledge_base",
        confidence: float = 1.0
    ):
        """
        Inizializza l'oggetto con le informazioni dettagliate della remediation.
        """
        self.finding_id = finding_id
        self.title = title
        self.severity = severity
        self.description = description
        self.impact = impact
        self.remediation_steps = remediation_steps
        self.example = example
        self.source = source  # "knowledge_base", "llm", "cache"
        self.confidence = confidence

    def to_dict(self) -> Dict[str, Any]:
        """
        Serializza l'oggetto in un dizionario compatibile con JSON.
        """
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "impact": self.impact,
            "remediation_steps": self.remediation_steps,
            "example": self.example,
            "source": self.source,
            "confidence": self.confidence
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RemediationModel':
        """
        Istanzia un oggetto RemediationModel a partire da un dizionario serializzato.
        """
        return cls(
            finding_id=data.get("finding_id", ""),
            title=data.get("title", ""),
            severity=data.get("severity", "INFO"),
            description=data.get("description", ""),
            impact=data.get("impact", ""),
            remediation_steps=data.get("remediation_steps", []),
            example=data.get("example", ""),
            source=data.get("source", "knowledge_base"),
            confidence=data.get("confidence", 1.0)
        )
