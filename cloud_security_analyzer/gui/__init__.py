"""
Modulo contenente le viste della GUI:
- MainWindow (Finestra principale con sidebar)
- DashboardView (Statistiche grafiche)
- FindingsView (Elenco completo delle vulnerabilità)
- EndpointsView (Catalogo e conformità API)
- AuthorizationView (Contesto BOLA/IDOR)
- AuthenticationView (Contesto Auth)
- InfrastructureView (Misconfig IaC)
- LogsView (Console di log)
- SettingsView (Impostazioni e report)
"""

from cloud_security_analyzer.gui.main_window.main_window_view import MainWindow
from cloud_security_analyzer.gui.dashboard.dashboard_view import DashboardView
from cloud_security_analyzer.gui.findings.findings_view import FindingsView
from cloud_security_analyzer.gui.endpoints.endpoints_view import EndpointsView
from cloud_security_analyzer.gui.authorization.authorization_view import AuthorizationView
from cloud_security_analyzer.gui.authentication.authentication_view import AuthenticationView
from cloud_security_analyzer.gui.infrastructure.infrastructure_view import InfrastructureView
from cloud_security_analyzer.gui.logs.logs_view import LogsView
from cloud_security_analyzer.gui.settings.settings_view import SettingsView
