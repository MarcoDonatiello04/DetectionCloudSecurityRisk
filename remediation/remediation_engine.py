"""
Motore centrale della Remediation Intelligence.
Responsabilità:
- Ricevere un finding di sicurezza (o modello GUI).
- Cercare la remediation nella Knowledge Base locale.
- Gestire la cache locale delle remediation (local_cache.json).
- Interrogare Ollama in caso di cache miss.
- Gestire gli errori e fornire fallback leggibili offline.
"""

import os
import json
import logging
from typing import Dict, Any, Optional, Union

from remediation.models.remediation_model import RemediationModel
from remediation.llm_provider import LlmProvider

logger = logging.getLogger("SecurityPlatform.Remediation.Engine")

class RemediationEngine:
    """
    Engine centrale di coordinamento per la remediation automatica offline.
    """

    def __init__(self, kb_directory: Optional[str] = None):
        if not kb_directory:
            kb_directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), "knowledge_base")
        self.kb_directory = os.path.abspath(kb_directory)
        
        # Mappa dei file di Knowledge Base
        self.checkov_path = os.path.join(self.kb_directory, "checkov_remediation.json")
        self.owasp_path = os.path.join(self.kb_directory, "owasp_api_remediation.json")
        self.cloud_path = os.path.join(self.kb_directory, "cloud_remediation.json")
        self.cache_path = os.path.join(self.kb_directory, "local_cache.json")

        self.llm_provider = LlmProvider()

        # Carica in memoria i database locali
        self.checkov_kb = self._load_json_db(self.checkov_path)
        self.owasp_kb = self._load_json_db(self.owasp_path)
        self.cloud_kb = self._load_json_db(self.cloud_path)
        self.cache_kb = self._load_json_db(self.cache_path)

    def get_remediation(self, finding: Any) -> RemediationModel:
        """
        Analizza un finding e ritorna il modello arricchito di Remediation.
        findings supportati: modelli GUI o entità del dominio.
        """
        # Estrae i parametri base dal finding in modo sicuro
        finding_id = getattr(finding, "id", "") or getattr(finding, "finding_id", "")
        rule_id = getattr(finding, "rule_id", "") or "N/A"
        title = getattr(finding, "title", "")
        description = getattr(finding, "description", "")
        
        # Gestione Enums di dominio o stringhe della GUI
        severity = getattr(finding, "severity", "INFO")
        if not isinstance(severity, str):
            severity = severity.value if hasattr(severity, "value") else str(severity)
            
        category = getattr(finding, "category", "MISCONFIGURATION")
        if not isinstance(category, str):
            category = category.value if hasattr(category, "value") else str(category)
            
        source = getattr(finding, "source", "CHECKOV")
        if not isinstance(source, str):
            source = source.value if hasattr(source, "value") else str(source)

        remediation_default = getattr(finding, "remediation", "") or "Nessuna mitigazione specificata."

        # Chiave di ricerca primaria
        search_key = rule_id if rule_id and rule_id != "N/A" else finding_id

        # ─── FASE 1: RICERCA IN KNOWLEDGE BASE LOCALE ───
        # 1. Ricerca Checkov KB
        if source == "CHECKOV" and search_key in self.checkov_kb:
            logger.info(f"Remediation trovata in Checkov KB per la regola: {search_key}")
            return self._build_model_from_kb(finding_id, severity, self.checkov_kb[search_key], "knowledge_base")

        # 2. Ricerca OWASP API KB
        # Controlla per categoria (AUTHORIZATION, AUTHENTICATION, RATE_LIMITING ecc.)
        if category in self.owasp_kb:
            logger.info(f"Remediation trovata in OWASP API KB per la categoria: {category}")
            return self._build_model_from_kb(finding_id, severity, self.owasp_kb[category], "knowledge_base")

        # 3. Ricerca Cloud Misconfiguration KB
        if search_key in self.cloud_kb:
            logger.info(f"Remediation trovata in Cloud Misconfiguration KB per la regola: {search_key}")
            return self._build_model_from_kb(finding_id, severity, self.cloud_kb[search_key], "knowledge_base")

        # ─── FASE 2: RICERCA IN CACHE LOCALE ───
        if search_key in self.cache_kb:
            logger.info(f"Remediation trovata in cache locale per: {search_key}")
            return self._build_model_from_kb(finding_id, severity, self.cache_kb[search_key], "cache", confidence=0.9)

        # ─── FASE 3: GENERAZIONE FALLBACK TRAMITE LLM OLLAMA LOCALE ───
        llm_data = self.llm_provider.generate_remediation(
            finding_id=search_key,
            title=title,
            category=category,
            source=source,
            description=description
        )

        if llm_data:
            # Salva in cache
            self._save_to_cache(search_key, llm_data)
            model_name = self.llm_provider.get_available_model() or ""
            source_label = "offline_simulator" if "Simulato" in model_name else "llm"
            return self._build_model_from_kb(finding_id, severity, llm_data, source_label, confidence=0.8)

        # ─── FASE 4: FALLBACK DI EMERGENZA (OFFLINE SENZA LLM) ───
        logger.warning(f"Nessuna remediation trovata. Fallback standard per: {finding_id}")
        return RemediationModel(
            finding_id=finding_id,
            title=title,
            severity=severity,
            description=description,
            impact="L'impatto esatto di questa vulnerabilità non è stato analizzato.",
            remediation_steps=[remediation_default],
            example="# Nessun esempio di configurazione disponibile.",
            source="knowledge_base_fallback",
            confidence=0.5
        )

    def get_remediation_source_fast(self, finding: Any) -> str:
        """
        Ottiene la sorgente della remediation in modo immediato (in-memory KB o cache)
        senza effettuare chiamate LLM.
        """
        finding_id = getattr(finding, "id", "") or getattr(finding, "finding_id", "")
        rule_id = getattr(finding, "rule_id", "") or "N/A"
        
        category = getattr(finding, "category", "MISCONFIGURATION")
        if not isinstance(category, str):
            category = category.value if hasattr(category, "value") else str(category)
            
        source = getattr(finding, "source", "CHECKOV")
        if not isinstance(source, str):
            source = source.value if hasattr(source, "value") else str(source)
            
        search_key = rule_id if rule_id and rule_id != "N/A" else finding_id
        
        if source == "CHECKOV" and search_key in self.checkov_kb:
            return "knowledge_base"
        if category in self.owasp_kb:
            return "knowledge_base"
        if search_key in self.cloud_kb:
            return "knowledge_base"
        if search_key in self.cache_kb:
            return "cache"
            
        if self.llm_provider.get_available_model():
            return "llm"
            
        return "fallback"

    def _load_json_db(self, path: str) -> Dict[str, Any]:
        """
        Carica in memoria un file JSON. Crea un dizionario vuoto se non esiste.
        """
        if not os.path.exists(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Errore lettura file KB {path}: {e}")
            return {}

    def _build_model_from_kb(
        self,
        finding_id: str,
        severity: str,
        kb_entry: Dict[str, Any],
        source: str,
        confidence: float = 1.0
    ) -> RemediationModel:
        """
        Costruisce un RemediationModel a partire da una entry JSON di KB.
        """
        return RemediationModel(
            finding_id=finding_id,
            title=kb_entry.get("title", "N/A"),
            severity=severity,
            description=kb_entry.get("description", ""),
            impact=kb_entry.get("impact", ""),
            remediation_steps=kb_entry.get("remediation_steps", []),
            example=kb_entry.get("example", ""),
            source=source,
            confidence=confidence
        )

    def _save_to_cache(self, key: str, data: Dict[str, Any]):
        """
        Aggiorna il file di cache locale scrivendolo su disco.
        """
        self.cache_kb[key] = data
        try:
            with open(self.cache_path, "w", encoding="utf-8") as f:
                json.dump(self.cache_kb, f, indent=2, ensure_ascii=False)
            logger.info(f"Cache locale aggiornata e salvata in: {self.cache_path}")
        except Exception as e:
            logger.error(f"Impossibile salvare la cache in {self.cache_path}: {e}")
