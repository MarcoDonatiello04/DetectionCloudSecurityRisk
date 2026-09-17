"""
Accesso condiviso alla configurazione del modulo BOLA (``config/bola.yaml``).

La configurazione viene caricata una sola volta da ``load_bola_config`` e riusata
dall'assertion engine (campi volatili del confronto strutturale) e dalla privilege
matrix (gerarchia dei ruoli). ``reset_bola_config`` serve ai test o a chi cambia
BOLA_CONFIG a runtime.
"""

from src.core.config import BolaConfig, load_bola_config

_bola_config: BolaConfig | None = None


def get_bola_config() -> BolaConfig:
    """
    Ritorna l'istanza condivisa della configurazione BOLA (caricata una volta).

    Returns:
        BolaConfig: La configurazione attiva.
    """
    global _bola_config
    if _bola_config is None:
        _bola_config = load_bola_config()
    return _bola_config


def reset_bola_config(config: BolaConfig | None = None) -> None:
    """
    Sostituisce (o azzera, se None) l'istanza condivisa: il prossimo accesso la ricarica.

    Args:
        config (BolaConfig | None): Configurazione da imporre, oppure None.
    """
    global _bola_config
    _bola_config = config
