"""
Accesso condiviso alla configurazione del risk scoring (ADR-005).

La configurazione viene caricata una sola volta da ``load_risk_scoring_config`` e
riusata da chi calcola il punteggio (motore di correlazione, ``Severity.score``) e da
chi assegna la confidenza per sorgente (adapter). ``reset_risk_scoring_config`` serve ai
test o a chi cambia RISK_SCORING_CONFIG a runtime.
"""

from src.core.config import RiskScoringConfig, load_risk_scoring_config

_risk_scoring_config: RiskScoringConfig | None = None


def get_risk_scoring_config() -> RiskScoringConfig:
    """
    Ritorna l'istanza condivisa della configurazione del risk scoring (caricata una volta).

    Returns:
        RiskScoringConfig: La configurazione attiva.
    """
    global _risk_scoring_config
    if _risk_scoring_config is None:
        _risk_scoring_config = load_risk_scoring_config()
    return _risk_scoring_config


def reset_risk_scoring_config(config: RiskScoringConfig | None = None) -> None:
    """
    Sostituisce (o azzera, se None) l'istanza condivisa: il prossimo accesso la ricarica.

    Args:
        config (RiskScoringConfig | None): Configurazione da imporre, oppure None.
    """
    global _risk_scoring_config
    _risk_scoring_config = config
