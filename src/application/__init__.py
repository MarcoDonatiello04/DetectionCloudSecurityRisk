"""
Application Layer Package.
Contiene i casi d'uso, l'orchestrazione della scansione, il bus degli eventi in-memory e il caricamento dei plugin.
"""

from src.application.correlation.engine import RiskCorrelationEngine
from src.application.event_bus import EventBus
from src.application.orchestrator import ScanPipelineOrchestrator
from src.application.plugin_loader import PluginLoader

__all__ = [
    "ScanPipelineOrchestrator",
    "EventBus",
    "PluginLoader",
    "RiskCorrelationEngine",
]
