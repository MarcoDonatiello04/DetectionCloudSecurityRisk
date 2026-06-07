"""
Modulo contenente i componenti grafici (widget) riutilizzabili:
- DonutChartWidget e BarChartWidget (disegnati tramite QPainter)
- SeverityBadge (badge colorati per severità)
- SearchBar (casella di input moderna)
- FilterPanel (chips di filtro severità)
- RiskCard (pannelli metrici di riepilogo)
- OrbitWidget (animazione 3D ellittica dell'infrastruttura cloud target)
- ScannerStatusWidget (badge circolari di stato degli scanner integrati)
"""

from cloud_security_analyzer.widgets.charts import DonutChartWidget, BarChartWidget
from cloud_security_analyzer.widgets.severity_badge import SeverityBadge
from cloud_security_analyzer.widgets.search_bar import SearchBar
from cloud_security_analyzer.widgets.filter_panel import FilterPanel
from cloud_security_analyzer.widgets.risk_card import RiskCard
from cloud_security_analyzer.widgets.orbit_widget import OrbitWidget
from cloud_security_analyzer.widgets.scanner_status_widget import ScannerStatusWidget
