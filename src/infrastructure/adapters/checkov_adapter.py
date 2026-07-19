import json
import logging
import os
import subprocess

from src.domain.entities import CodeLocation, Finding, FindingCategory, FindingSource, Severity
from src.domain.interfaces import IScanner

logger = logging.getLogger("SecurityPlatform.CheckovAdapter")

# Configurazione default di esecuzione per Checkov
DEFAULT_TIMEOUT_SECONDS = 60
DEFAULT_CHECKOV_CONFIG = ".checkov.yaml"


class CheckovScannerAdapter(IScanner):
    """
    Adapter infrastrutturale per Checkov.
    Esegue l'analisi statica dei file di infrastruttura (Terraform/HCL)
    e trasforma l'output grezzo JSON in oggetti Finding del Dominio.
    """

    def scan(self, target_dir: str) -> list[Finding]:
        """
        Esegue l'analisi statica con Checkov sulla cartella target.

        Args:
            target_dir (str): Percorso della directory target da scansionare.

        Returns:
            List[Finding]: Lista di Finding di sicurezza IaC rilevati da Checkov.
        """
        logger.info(f"🚀 Esecuzione Checkov Scanner su: {target_dir}")
        checkov_bin = "checkov"
        if os.path.exists("./.venv/bin/checkov"):
            checkov_bin = "./.venv/bin/checkov"

        cmd = [checkov_bin, "--skip-download", "--no-cert-verify", "-o", "json"]
        if os.path.exists(DEFAULT_CHECKOV_CONFIG):
            cmd.extend(["--config-file", DEFAULT_CHECKOV_CONFIG])
        else:
            cmd.extend(["-d", target_dir])

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
                    check_id = check.get("check_id", "unknown")
                    check_id_lower = check_id.lower()
                    resource_id = check.get("resource", "unknown")

                    # Riconduzione accurata della categoria
                    category = FindingCategory.MISCONFIGURATION
                    if "iam" in check_id_lower or "iam" in resource_id.lower():
                        category = FindingCategory.IAM
                    elif (
                        "s3" in check_id_lower
                        or "acl" in check_id_lower
                        or "storage" in resource_id.lower()
                    ):
                        category = FindingCategory.STORAGE
                    elif (
                        "sg" in check_id_lower
                        or "security_group" in resource_id.lower()
                        or "vpc" in resource_id.lower()
                        or "port" in check_id_lower
                    ):
                        category = FindingCategory.NETWORK
                    elif "encrypt" in check_id_lower or "kms" in resource_id.lower():
                        category = FindingCategory.ENCRYPTION
                    elif "log" in check_id_lower or "trail" in resource_id.lower():
                        category = FindingCategory.LOGGING
                    elif "apigateway" in check_id_lower or "api_gateway" in resource_id.lower():
                        category = FindingCategory.API_GATEWAY

                    # Calcolo Severity
                    severity = Severity.MEDIUM
                    is_critical = category in (FindingCategory.IAM, FindingCategory.STORAGE) and (
                        "public" in check_id_lower
                        or "star" in check_id_lower
                        or "admin" in check_id_lower
                    )

                    if is_critical:
                        severity = Severity.CRITICAL
                    elif (
                        category in (FindingCategory.NETWORK, FindingCategory.ENCRYPTION)
                        or "public" in check_id_lower
                    ):
                        severity = Severity.HIGH
                    elif "low" in check_id_lower:
                        severity = Severity.LOW

                    loc = CodeLocation(
                        file_path=check.get("file_path", ""),
                        start_line=check.get("file_line_range", [None])[0],
                        end_line=check.get("file_line_range", [None, None])[1],
                    )

                    target_ident = f"{resource_id}:{loc.file_path}"
                    corr_key = resource_id.split(".")[-1] if "." in resource_id else resource_id

                    finding = Finding.create(
                        source=FindingSource.CHECKOV,
                        category=category,
                        title=check.get("check_name", "IaC Misconfiguration"),
                        description=f"{check.get('check_name')} per la risorsa {resource_id}",
                        severity=severity,
                        confidence=1.0,
                        rule_id=check_id,
                        target_identifier=target_ident,
                        rule_name=check.get("check_name"),
                        resource_id=resource_id,
                        location=loc,
                        correlation_key=corr_key,
                        raw_data=check,
                    )
                    findings.append(finding)

            logger.info(f"Checkov completato. Trovati {len(findings)} disallineamenti IaC.")
            return findings

        except Exception as e:
            logger.error(f"Errore nel parsing dell'output di Checkov: {e}", exc_info=True)

        return []
