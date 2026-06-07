"""
Gestisce il caricamento delle scansioni e dei risultati di sicurezza.
Responsabilità:
- Caricare in modo asincrono i report dei findings (unified_security_report.json).
- Caricare il catalogo degli endpoint (unified_api_inventory.json).
- Analizzare la cartella 'reports' per catalogare ed elencare lo storico delle scansioni passate.
- Caricare snapshot storiche selezionate dall'utente.
- Effettuare il parsing dei dati grezzi nei rispettivi modelli della GUI.
"""

import os
import json
import glob
import logging
from typing import List, Tuple, Dict, Any
from datetime import datetime

from src.domain.entities import (
    Finding, Severity, FindingCategory, FindingSource, ValidationStatus,
    CodeLocation, APIContext, RuntimeEvidence, RiskContext
)
from cloud_security_analyzer.models.finding_model import FindingModel
from cloud_security_analyzer.models.endpoint_model import EndpointModel

logger = logging.getLogger("SecurityPlatform.GUI.ScanService")

class ScanService:
    """
    Servizio deputato al recupero, parsing ed indicizzazione dello storico scansioni.
    """

    def __init__(self, default_dir: str):
        """
        Inizializza con la directory di scansione predefinita.
        """
        self.current_dir = os.path.abspath(default_dir)

    def set_directory(self, path: str):
        """
        Imposta una nuova directory di scansione.
        """
        self.current_dir = os.path.abspath(path)

    def verify_files_exist(self) -> Tuple[bool, str]:
        """
        Verifica se i file di report necessari esistono nella directory corrente.
        Ritorna (success, message).
        """
        report_path = os.path.join(self.current_dir, "unified_security_report.json")
        inventory_path = os.path.join(self.current_dir, "unified_api_inventory.json")

        if not os.path.exists(report_path):
            return False, f"Il file dei findings non esiste in:\n{report_path}"
        if not os.path.exists(inventory_path):
            return False, f"Il file dell'inventario API non esiste in:\n{inventory_path}"
        return True, ""

    def load_findings(self) -> List[FindingModel]:
        """
        Carica e decodifica i findings dal file JSON.
        """
        report_path = os.path.join(self.current_dir, "unified_security_report.json")
        return self._read_findings_file(report_path)

    def load_endpoints(self) -> List[EndpointModel]:
        """
        Carica e decodifica gli endpoint dell'inventario.
        """
        inventory_path = os.path.join(self.current_dir, "unified_api_inventory.json")
        return self._read_endpoints_file(inventory_path)

    def list_historical_scans(self) -> List[Dict[str, Any]]:
        """
        Scansiona la directory 'reports/' del progetto cercando file del tipo 'unified_report_*.json'.
        Ritorna una lista ordinata con informazioni sommarie di ogni scansione.
        """
        reports_dir = os.path.join(os.path.dirname(self.current_dir), "reports")
        if not os.path.exists(reports_dir):
            return []

        search_pattern = os.path.join(reports_dir, "unified_report_*.json")
        files = glob.glob(search_pattern)
        
        history = []
        for filepath in files:
            basename = os.path.basename(filepath)
            # Estrae la data del nome file: unified_report_YYYYMMDD_HHMMSS.json
            date_part = basename.replace("unified_report_", "").replace(".json", "")
            try:
                dt = datetime.strptime(date_part, "%Y%m%d_%H%M%S")
                date_str = dt.strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                dt = datetime.fromtimestamp(os.path.getmtime(filepath))
                date_str = dt.strftime("%Y-%m-%d %H:%M:%S")

            # Estrae statistiche rapide leggendo parzialmente il file
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                total = len(data)
                
                # Calcola il massimo risk_score
                max_score = 0.0
                for item in data:
                    score = 0.0
                    raw = item.get("raw_data", {})
                    if raw and "correlated_risk_score" in raw:
                        score = float(raw["correlated_risk_score"])
                    else:
                        # Fallback rapido
                        sev = item.get("severity", "INFO")
                        conf = item.get("confidence", 1.0)
                        score = 9.0 if sev == "CRITICAL" else 7.0 if sev == "HIGH" else 4.5 if sev == "MEDIUM" else 2.0
                        score = score * conf
                    if score > max_score:
                        max_score = score
                max_score = round(max_score, 1)

                history.append({
                    "filepath": filepath,
                    "basename": basename,
                    "date_str": date_str,
                    "timestamp": dt,
                    "total_findings": total,
                    "risk_score": max_score
                })
            except Exception as ex:
                logger.error(f"Errore lettura metadati scansione storica {filepath}: {ex}")

        # Ordina per data decrescente (la più recente per prima)
        history.sort(key=lambda x: x["timestamp"], reverse=True)
        return history

    def load_historical_scan(self, report_filepath: str) -> Tuple[List[FindingModel], List[EndpointModel]]:
        """
        Carica i findings ed endpoint da un file di scansione storica specifico.
        """
        findings = self._read_findings_file(report_filepath)
        
        # Cerca l'inventario associato sostituendo il prefisso del file
        basename = os.path.basename(report_filepath)
        inv_basename = basename.replace("unified_report_", "unified_inventory_")
        inv_path = os.path.join(os.path.dirname(report_filepath), inv_basename)
        
        endpoints = []
        if os.path.exists(inv_path):
            endpoints = self._read_endpoints_file(inv_path)
        else:
            logger.warning(f"File inventario storico non trovato: {inv_path}")
            
        return findings, endpoints

    def _read_findings_file(self, filepath: str) -> List[FindingModel]:
        if not os.path.exists(filepath):
            logger.warning(f"File findings non trovato: {filepath}")
            return []

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                raw_data = json.load(f)
            
            findings = []
            for item in raw_data:
                try:
                    finding_entity = self._map_to_finding(item)
                    findings.append(FindingModel(finding_entity))
                except Exception as ex:
                    logger.error(f"Errore durante il parsing del finding: {ex}", exc_info=True)
            
            logger.info(f"Caricati con successo {len(findings)} findings da {filepath}.")
            return findings
        except Exception as e:
            logger.error(f"Impossibile leggere i findings in {filepath}: {e}", exc_info=True)
            raise RuntimeError(f"Errore lettura report: {str(e)}")

    def _read_endpoints_file(self, filepath: str) -> List[EndpointModel]:
        if not os.path.exists(filepath):
            logger.warning(f"File inventario non trovato: {filepath}")
            return []

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                raw_data = json.load(f)
            
            endpoints = [EndpointModel(item) for item in raw_data]
            logger.info(f"Caricati con successo {len(endpoints)} endpoint da {filepath}.")
            return endpoints
        except Exception as e:
            logger.error(f"Impossibile leggere l'inventario in {filepath}: {e}", exc_info=True)
            raise RuntimeError(f"Errore lettura inventario: {str(e)}")

    def _map_to_finding(self, data: Dict[str, Any]) -> Finding:
        """
        Mappa una entry dizionario JSON all'entità di dominio Finding.
        """
        # Mapping Severity
        sev_str = data.get("severity", "INFO")
        try:
            severity = Severity(sev_str)
        except ValueError:
            severity = Severity.INFO

        # Mapping Source
        src_str = data.get("source", "CHECKOV")
        try:
            source = FindingSource(src_str)
        except ValueError:
            source = FindingSource.CHECKOV

        # Mapping Category
        cat_str = data.get("category", "MISCONFIGURATION")
        try:
            category = FindingCategory(cat_str)
        except ValueError:
            category = FindingCategory.MISCONFIGURATION

        # Mapping ValidationStatus
        val_str = data.get("validation_status", "NOT_VALIDATED")
        try:
            val_status = ValidationStatus(val_str)
        except ValueError:
            val_status = ValidationStatus.NOT_VALIDATED

        # Location
        loc_data = data.get("location")
        location = None
        if loc_data:
            location = CodeLocation(
                file_path=loc_data.get("file_path", ""),
                start_line=loc_data.get("start_line"),
                end_line=loc_data.get("end_line"),
                code_snippet=loc_data.get("code_snippet")
            )

        # APIContext
        api_data = data.get("api")
        api = None
        if api_data:
            api = APIContext(
                endpoint=api_data.get("endpoint"),
                method=api_data.get("method"),
                base_url=api_data.get("base_url"),
                api_version=api_data.get("api_version"),
                requires_authentication=api_data.get("requires_authentication")
            )

        # RuntimeEvidence
        re_data = data.get("runtime_evidence")
        runtime_evidence = None
        if re_data:
            runtime_evidence = RuntimeEvidence(
                tested_url=re_data.get("tested_url"),
                http_status=re_data.get("http_status"),
                response_time_ms=re_data.get("response_time_ms"),
                response_headers=re_data.get("response_headers", {}),
                response_snippet=re_data.get("response_snippet"),
                accessible_without_auth=re_data.get("accessible_without_auth"),
                rate_limit_detected=re_data.get("rate_limit_detected")
            )

        # RiskContext
        rc_data = data.get("risk_context")
        risk_context = None
        if rc_data:
            risk_context = RiskContext(
                internet_exposed=rc_data.get("internet_exposed"),
                sensitive_data_detected=rc_data.get("sensitive_data_detected"),
                public_resource=rc_data.get("public_resource"),
                exploitable=rc_data.get("exploitable"),
                attack_complexity=rc_data.get("attack_complexity"),
                impact=rc_data.get("impact")
            )

        # Date representation
        det_str = data.get("detected_at")
        detected_at = datetime.utcnow()
        if det_str:
            try:
                detected_at = datetime.fromisoformat(det_str)
            except ValueError:
                pass

        return Finding(
            finding_id=data.get("finding_id", ""),
            source=source,
            category=category,
            title=data.get("title", ""),
            description=data.get("description", ""),
            severity=severity,
            confidence=data.get("confidence", 1.0),
            rule_id=data.get("rule_id"),
            rule_name=data.get("rule_name"),
            resource_type=data.get("resource_type"),
            resource_name=data.get("resource_name"),
            resource_id=data.get("resource_id"),
            location=location,
            api=api,
            validation_status=val_status,
            runtime_evidence=runtime_evidence,
            risk_context=risk_context,
            correlation_key=data.get("correlation_key"),
            related_findings=data.get("related_findings", []),
            owasp_api_category=data.get("owasp_api_category"),
            cwe_id=data.get("cwe_id"),
            cve_id=data.get("cve_id"),
            remediation=data.get("remediation"),
            tags=data.get("tags", []),
            references=data.get("references", []),
            raw_data=data.get("raw_data", {}),
            detected_at=detected_at
        )
