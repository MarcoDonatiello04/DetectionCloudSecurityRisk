import json
import logging
import os
import subprocess
from typing import Any

from src.core.config import CHECKOV_CMD, CONFIDENCE_BY_CATALOG_MATCH, DEFAULT_CHECKOV_CONFIG
from src.core.config import DEFAULT_SCAN_TIMEOUT_SECONDS as DEFAULT_TIMEOUT_SECONDS
from src.domain.entities import (
    CodeLocation,
    Finding,
    FindingCategory,
    FindingSource,
    RiskContext,
)
from src.domain.interfaces import IScanner
from src.infrastructure.adapters.checkov_policy_catalog import (
    CheckovPolicyCatalog,
    get_default_catalog,
)

logger = logging.getLogger("SecurityPlatform.CheckovAdapter")


class CheckovScannerAdapter(IScanner):
    """
    Adapter infrastrutturale per Checkov.
    Esegue l'analisi statica dei file di infrastruttura (Terraform/HCL)
    e trasforma l'output grezzo JSON in oggetti Finding del Dominio.

    Natura (EXPOSURE/HARDENING) e severità di ciascun controllo provengono dal catalogo
    semantico delle policy (``CheckovPolicyCatalog``), così che un'ACL pubblica e una
    notifica mancante sulla stessa risorsa non siano più indistinguibili.
    """

    def __init__(self, policy_catalog: CheckovPolicyCatalog | None = None):
        """
        Inizializza l'adapter con il catalogo delle policy (iniettabile per i test).

        Args:
            policy_catalog (CheckovPolicyCatalog | None): Catalogo da usare; se None, il default.
        """
        self._policy_catalog = policy_catalog

    @property
    def policy_catalog(self) -> CheckovPolicyCatalog:
        """Catalogo delle policy, caricato pigramente alla prima necessità."""
        if self._policy_catalog is None:
            self._policy_catalog = get_default_catalog()
        return self._policy_catalog

    @staticmethod
    def _build_command(target_dir: str) -> list[str]:
        """
        Costruisce la riga di comando di Checkov per la directory target.

        Il perimetro della scansione è sempre ``target_dir`` (``-d``): il file di
        configurazione ``DEFAULT_CHECKOV_CONFIG``, se presente nella directory di lavoro,
        viene aggiunto solo come sorgente di opzioni accessorie (formato, skip-path,
        soft-fail), mai come sorgente del perimetro. In Checkov gli argomenti da riga di
        comando prevalgono su quelli del file, quindi un'eventuale chiave ``directory``
        nel file non può allargare la scansione oltre il bersaglio richiesto.

        Args:
            target_dir (str): Percorso della directory target da scansionare.

        Returns:
            list[str]: Argomenti del comando da passare a ``subprocess.run``.
        """
        checkov_bin = CHECKOV_CMD
        if os.path.exists("./.venv/bin/checkov"):
            checkov_bin = "./.venv/bin/checkov"

        cmd = [checkov_bin, "--skip-download", "--no-cert-verify", "-o", "json", "-d", target_dir]
        if os.path.exists(DEFAULT_CHECKOV_CONFIG):
            cmd.extend(["--config-file", DEFAULT_CHECKOV_CONFIG])
        return cmd

    def scan(self, target_dir: str) -> list[Finding]:
        """
        Esegue l'analisi statica con Checkov sulla cartella target.

        Il perimetro è il bersaglio: viene scansionato esclusivamente ``target_dir``.
        Il file ``.checkov.yaml`` della piattaforma, se esiste, governa solo le altre
        opzioni (formato dell'output, percorsi da ignorare, soft-fail).

        Args:
            target_dir (str): Percorso della directory target da scansionare.

        Returns:
            List[Finding]: Lista di Finding di sicurezza IaC rilevati da Checkov.
        """
        logger.info(f"🚀 Esecuzione Checkov Scanner su: {target_dir}")
        cmd = self._build_command(target_dir)

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=DEFAULT_TIMEOUT_SECONDS
            )
            output_str = result.stdout
        except (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
            logger.error(f"Errore durante l'esecuzione del comando checkov: {e}")
            return []

        try:
            json_start = output_str.find("{")
            json_start_array = output_str.find("[")
            start_idx = -1
            if json_start != -1 and json_start_array != -1:
                start_idx = min(json_start, json_start_array)
            elif json_start != -1:
                start_idx = json_start
            elif json_start_array != -1:
                start_idx = json_start_array

            if start_idx == -1:
                logger.warning("Nessun output JSON valido rilevato da Checkov.")
                return []

            data = json.loads(output_str[start_idx:])
            findings: list[Finding] = []
            reports = [data] if isinstance(data, dict) else data

            for report in reports:
                # Gestisce sia singoli report che array di report per diversi tipi di risorsa
                failed_checks = report.get("results", {}).get("failed_checks", [])
                for check in failed_checks:
                    findings.append(self.build_finding(check))

            logger.info(f"Checkov completato. Trovati {len(findings)} disallineamenti IaC.")
            return findings

        except Exception as e:
            logger.error(f"Errore nel parsing dell'output di Checkov: {e}", exc_info=True)

        return []

    def build_finding(self, check: dict[str, Any]) -> Finding:
        """
        Traduce un singolo controllo fallito di Checkov nell'entità Finding del Dominio.

        Args:
            check (dict): Record grezzo di Checkov (check_id, check_name, resource, file_path, ...).

        Returns:
            Finding: Il Finding con categoria, natura, severità e contesto di rischio derivati.
        """
        check_id = check.get("check_id", "unknown")
        check_name = check.get("check_name") or "IaC Misconfiguration"
        resource_id = check.get("resource", "unknown")

        category = self._derive_category(check_id, check_name, resource_id)

        # Natura e severità dal catalogo semantico: le parole chiave operano sul nome
        # ufficiale del controllo, non sull'identificativo opaco (CKV_AWS_53).
        classification = self.policy_catalog.classify(check_id, check_name)

        # Solo un'esposizione che rende la risorsa raggiungibile da chiunque attiva
        # il bonus di contesto: un bucket privato senza log non è "esposto a Internet".
        # I controlli su segreti e cifratura a riposo dichiarano invece dati sensibili.
        risk_context = (
            RiskContext(
                internet_exposed=classification.public_facing,
                public_resource=classification.public_facing,
                sensitive_data_detected=classification.sensitive_data,
            )
            if classification.public_facing or classification.sensitive_data
            else None
        )

        line_range = check.get("file_line_range") or [None, None]
        loc = CodeLocation(
            file_path=check.get("file_path", ""),
            start_line=line_range[0] if len(line_range) > 0 else None,
            end_line=line_range[1] if len(line_range) > 1 else None,
        )

        target_ident = f"{resource_id}:{loc.file_path}"
        corr_key = resource_id.split(".")[-1] if "." in resource_id else resource_id
        # Tipo di risorsa solo per identificativi strutturati (aws_s3_bucket.nome, Kind.ns.nome)
        parts = resource_id.split(".")
        is_structured = len(parts) >= 2 and bool(parts[0]) and "/" not in resource_id
        resource_type = parts[0] if is_structured else None

        return Finding.create(
            source=FindingSource.CHECKOV,
            category=category,
            title=check_name,
            description=f"{check_name} per la risorsa {resource_id}",
            severity=classification.severity,
            # La confidenza riflette la precisione della regola del catalogo che ha
            # classificato il controllo: mappatura esplicita > prefisso > keyword > default.
            confidence=CONFIDENCE_BY_CATALOG_MATCH[classification.matched_by],
            rule_id=check_id,
            target_identifier=target_ident,
            rule_name=check.get("check_name"),
            resource_type=resource_type,
            resource_name=corr_key or None,
            resource_id=resource_id,
            location=loc,
            risk_context=risk_context,
            correlation_key=corr_key,
            nature=classification.nature,
            raw_data=check,
        )

    @staticmethod
    def _derive_category(check_id: str, check_name: str, resource_id: str) -> FindingCategory:
        """
        Deriva la categoria del Finding da identificativo, nome ufficiale e tipo di risorsa.

        Args:
            check_id (str): Identificativo del controllo.
            check_name (str): Nome ufficiale del controllo.
            resource_id (str): Nome completo della risorsa (es. aws_s3_bucket.bucket_1).

        Returns:
            FindingCategory: La prima categoria la cui regola è soddisfatta.
        """
        check_id_lower = check_id.lower()
        resource_lower = resource_id.lower()
        # Spazi ai bordi per confrontare parole intere nel nome ("Ensure IAM policies ...")
        name_lower = f" {check_name.lower()} "

        if "iam" in check_id_lower or "iam" in resource_lower or " iam " in name_lower:
            return FindingCategory.IAM
        if (
            "s3" in check_id_lower
            or "acl" in check_id_lower
            or "storage" in resource_lower
            or "s3" in resource_lower
            or "dynamodb" in resource_lower
            or " s3 " in name_lower
        ):
            return FindingCategory.STORAGE
        if (
            "sg" in check_id_lower
            or "security_group" in resource_lower
            or "vpc" in resource_lower
            or "port" in check_id_lower
            or "security group" in name_lower
            or "0.0.0.0" in name_lower
        ):
            return FindingCategory.NETWORK
        if "encrypt" in check_id_lower or "kms" in resource_lower or "encrypt" in name_lower:
            return FindingCategory.ENCRYPTION
        if "log" in check_id_lower or "trail" in resource_lower or "logging" in name_lower:
            return FindingCategory.LOGGING
        if (
            "apigateway" in check_id_lower
            or "api_gateway" in resource_lower
            or "api gateway" in name_lower
        ):
            return FindingCategory.API_GATEWAY
        return FindingCategory.MISCONFIGURATION


CheckovAdapter = CheckovScannerAdapter
