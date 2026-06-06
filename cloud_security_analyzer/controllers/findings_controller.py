"""
Gestisce la logica di filtraggio, ricerca e selezione dei findings.
Responsabilità:
- Filtrare i findings caricati in base alle selezioni (severità, sorgente, categoria, ricerca testuale).
- Gestire la selezione di un singolo finding per visualizzarne i dettagli.
- Mantenere la separazione tra la vista dei findings e lo StateService.
"""

from typing import List, Optional
from cloud_security_analyzer.services.state_service import StateService
from cloud_security_analyzer.models.finding_model import FindingModel

class FindingsController:
    """
    Controller responsabile del coordinamento della schermata dei Findings.
    """

    def __init__(self, state_service: StateService, preset_filters: dict = None):
        self.state = state_service
        self.preset_filters = preset_filters or {}

    def get_filtered_findings(self) -> List[FindingModel]:
        """
        Ritorna la lista dei findings filtrata secondo lo stato corrente.
        """
        all_findings = self.state.findings
        filtered = []

        query = self.state.search_query.strip().lower()
        sevs = self.state.selected_severities
        srcs = self.state.selected_sources
        cats = self.state.selected_categories

        # Filtri preimpostati (usati per le viste specializzate)
        preset_cats = self.preset_filters.get("category", [])
        preset_srcs = self.preset_filters.get("source", [])

        for f in all_findings:
            # Filtri preimpostati strutturali
            if preset_cats and f.category not in preset_cats:
                continue
            if preset_srcs and f.source not in preset_srcs:
                continue

            # 1. Filtro per severità (se selezionato almeno uno)
            if sevs and f.severity not in sevs:
                continue
            
            # 2. Filtro per sorgente scanner (se selezionato almeno uno)
            if srcs and f.source not in srcs:
                continue

            # 3. Filtro per categoria logica (se selezionato almeno uno)
            if cats and f.category not in cats:
                continue

            # 4. Filtro per query di ricerca (titolo, descrizione, file_path, resource, rule_id, cwe, cve)
            if query:
                in_title = query in f.title.lower()
                in_desc = query in f.description.lower()
                in_file = query in f.file_path.lower()
                in_res = query in f.resource.lower()
                in_rule = query in f.rule_id.lower()
                in_cwe = query in f.cwe.lower()
                in_cve = query in f.cve.lower()
                
                if not (in_title or in_desc or in_file or in_res or in_rule or in_cwe or in_cve):
                    continue

            filtered.append(f)

        return filtered

    def select_finding(self, finding: Optional[FindingModel]):
        """
        Imposta il finding correntemente selezionato per la visualizzazione dettagliata.
        """
        self.state.set_selected_finding(finding)

    def toggle_severity(self, severity: str):
        """
        Inverte la presenza del filtro severità.
        """
        self.state.toggle_severity_filter(severity)

    def set_search_query(self, query: str):
        """
        Aggiorna il filtro della query testuale.
        """
        self.state.set_search_query(query)

    def clear_filters(self):
        """
        Rimuove tutti i filtri.
        """
        self.state.clear_all_filters()
