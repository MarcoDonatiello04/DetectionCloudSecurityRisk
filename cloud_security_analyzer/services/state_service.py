"""
Gestisce lo stato globale e reattivo dell'applicazione GUI.
Responsabilità:
- Mantenere traccia dei findings, degli endpoint e delle metriche di rischio correnti.
- Gestire lo stato dei filtri attivi (ricerca, severità, sorgente, categoria).
- Notificare i controller ed i widget sui cambiamenti tramite segnali Qt.
"""

from typing import List, Optional, Set
from PySide6.QtCore import QObject, Signal

from cloud_security_analyzer.models.finding_model import FindingModel
from cloud_security_analyzer.models.endpoint_model import EndpointModel
from cloud_security_analyzer.models.cloud_risk_model import CloudRiskModel

class StateService(QObject):
    """
    Servizio centrale dello stato reattivo per l'architettura GUI.
    """

    # Segnali per notificare i cambiamenti di stato
    data_loaded = Signal()                     # Emesso quando i dati vengono ricaricati con successo
    filters_changed = Signal()                 # Emesso quando cambiano i filtri di visualizzazione
    selected_finding_changed = Signal(object)  # Emesso quando viene selezionato un altro finding (emette FindingModel)
    theme_changed = Signal(str)                # Emesso al cambio tema (es: "dark", "light")
    scan_directory_changed = Signal(str)       # Emesso quando la cartella dei report cambia

    def __init__(self):
        super().__init__()
        # Dati correnti
        self._findings: List[FindingModel] = []
        self._endpoints: List[EndpointModel] = []
        self._risk_model: Optional[CloudRiskModel] = None
        self._scan_directory: str = ""
        self._theme: str = "dark"

        # Stato dei Filtri
        self._search_query: str = ""
        self._selected_severities: Set[str] = set()
        self._selected_sources: Set[str] = set()
        self._selected_categories: Set[str] = set()
        self._selected_finding: Optional[FindingModel] = None

    # Getter e Setter per Dati
    @property
    def findings(self) -> List[FindingModel]:
        return self._findings

    @property
    def endpoints(self) -> List[EndpointModel]:
        return self._endpoints

    @property
    def risk_model(self) -> Optional[CloudRiskModel]:
        return self._risk_model

    @property
    def scan_directory(self) -> str:
        return self._scan_directory

    def set_scan_directory(self, path: str):
        if self._scan_directory != path:
            self._scan_directory = path
            self.scan_directory_changed.emit(path)

    @property
    def theme(self) -> str:
        return self._theme

    def set_theme(self, theme_name: str):
        if self._theme != theme_name:
            self._theme = theme_name
            self.theme_changed.emit(theme_name)

    def update_data(self, findings: List[FindingModel], endpoints: List[EndpointModel]):
        """
        Aggiorna l'archivio dei dati centralizzato e ricalcola il modello di rischio.
        """
        self._findings = findings
        self._endpoints = endpoints
        self._risk_model = CloudRiskModel(findings, endpoints)
        self._selected_finding = None
        
        self.data_loaded.emit()
        self.filters_changed.emit()

    # Getter e Setter per i Filtri
    @property
    def search_query(self) -> str:
        return self._search_query

    def set_search_query(self, query: str):
        if self._search_query != query:
            self._search_query = query
            self.filters_changed.emit()

    @property
    def selected_severities(self) -> Set[str]:
        return self._selected_severities

    def toggle_severity_filter(self, severity: str):
        """
        Attiva o disattiva il filtro di una severità specifica.
        """
        sev_upper = severity.upper()
        if sev_upper in self._selected_severities:
            self._selected_severities.remove(sev_upper)
        else:
            self._selected_severities.add(sev_upper)
        self.filters_changed.emit()

    def clear_severity_filters(self):
        if self._selected_severities:
            self._selected_severities.clear()
            self.filters_changed.emit()

    @property
    def selected_sources(self) -> Set[str]:
        return self._selected_sources

    def toggle_source_filter(self, source: str):
        src_upper = source.upper()
        if src_upper in self._selected_sources:
            self._selected_sources.remove(src_upper)
        else:
            self._selected_sources.add(src_upper)
        self.filters_changed.emit()

    def clear_source_filters(self):
        if self._selected_sources:
            self._selected_sources.clear()
            self.filters_changed.emit()

    @property
    def selected_categories(self) -> Set[str]:
        return self._selected_categories

    def toggle_category_filter(self, category: str):
        cat_upper = category.upper()
        if cat_upper in self._selected_categories:
            self._selected_categories.remove(cat_upper)
        else:
            self._selected_categories.add(cat_upper)
        self.filters_changed.emit()

    def clear_category_filters(self):
        if self._selected_categories:
            self._selected_categories.clear()
            self.filters_changed.emit()

    def clear_all_filters(self):
        """
        Azzera tutti i filtri attivi contemporaneamente.
        """
        self._search_query = ""
        self._selected_severities.clear()
        self._selected_sources.clear()
        self._selected_categories.clear()
        self.filters_changed.emit()

    # Gestione del finding correntemente selezionato
    @property
    def selected_finding(self) -> Optional[FindingModel]:
        return self._selected_finding

    def set_selected_finding(self, finding: Optional[FindingModel]):
        if self._selected_finding != finding:
            self._selected_finding = finding
            self.selected_finding_changed.emit(finding)
