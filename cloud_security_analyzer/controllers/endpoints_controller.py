"""
Gestisce la logica di filtraggio, ricerca e navigazione del Catalogo API.
Responsabilità:
- Filtrare gli endpoint caricati in base a ricerche testuali e conformità OpenAPI.
- Gestire filtri specifici come Shadow APIs (non documentate) e stato BOLA.
"""

from typing import List
from cloud_security_analyzer.services.state_service import StateService
from cloud_security_analyzer.models.endpoint_model import EndpointModel

class EndpointsController:
    """
    Controller responsabile del coordinamento degli endpoint API.
    """

    def __init__(self, state_service: StateService):
        self.state = state_service
        self._filter_show_all = True
        self._filter_shadow_only = False
        self._filter_documented_only = False
        self._filter_bola_status = ""  # "", "VULNERABLE", "SAFE", "UNTESTED"

    def set_filter_shadow_only(self, value: bool):
        if self._filter_shadow_only != value:
            self._filter_shadow_only = value
            self.state.filters_changed.emit()

    def set_filter_documented_only(self, value: bool):
        if self._filter_documented_only != value:
            self._filter_documented_only = value
            self.state.filters_changed.emit()

    def set_filter_bola_status(self, status: str):
        if self._filter_bola_status != status:
            self._filter_bola_status = status
            self.state.filters_changed.emit()

    def set_search_query(self, query: str):
        """
        Aggiorna il filtro della query testuale.
        """
        self.state.set_search_query(query)

    def get_filtered_endpoints(self) -> List[EndpointModel]:
        """
        Ritorna la lista degli endpoint filtrati.
        """
        all_endpoints = self.state.endpoints
        filtered = []

        query = self.state.search_query.strip().lower()

        for ep in all_endpoints:
            # 1. Filtro Shadow API / Documentate
            if self._filter_shadow_only and not ep.shadow:
                continue
            if self._filter_documented_only and not ep.documented:
                continue

            # 2. Filtro per stato BOLA
            if self._filter_bola_status and ep.bola_status != self._filter_bola_status:
                continue

            # 3. Filtro per query testuale (path, metodo, summary, descrizione)
            if query:
                in_path = query in ep.path.lower()
                in_method = query in ep.method.lower()
                in_summary = query in ep.summary.lower()
                
                if not (in_path or in_method or in_summary):
                    continue

            filtered.append(ep)

        return filtered
