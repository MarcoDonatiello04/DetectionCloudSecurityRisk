import os
import json
import subprocess
import logging
from typing import List
from src.domain.interfaces import IScanner
from src.domain.entities import Finding, FindingSource, FindingCategory, Severity, CodeLocation, APIContext

logger = logging.getLogger("SecurityPlatform.SpectralAdapter")

# Configurazione default di esecuzione per Spectral CLI
DEFAULT_SPECTRAL_RULESET_PATH = "config/scanner_configs/spectral-owasp.yaml"
DEFAULT_SPECTRAL_REPORT_FILE = "spectral_report_temp.json"
SPECTRAL_TIMEOUT_SECONDS = 30
OPENAPI_PREVIEW_SIZE_BYTES = 2048


class SpectralScannerAdapter(IScanner):
    """
    Adapter per Stoplight Spectral.
    Esegue il linting di contratti OpenAPI/Swagger rispetto a regole di sicurezza OWASP
    e mappa gli alert del linter in oggetti Finding.
    """

    def scan(self, target_file_or_dir: str) -> List[Finding]:
        """
        Esegue l'analisi di conformità con Spectral sull'OpenAPI contract.

        Args:
            target_file_or_dir (str): Percorso del file o della directory contenente il contratto OpenAPI.

        Returns:
            List[Finding]: Lista di Finding generati durante l'analisi.
        """
        logger.info(f"🚀 Esecuzione Spectral API Contract Scanner su: {target_file_or_dir}")
        openapi_file = None
        
        if os.path.isfile(target_file_or_dir):
            if self._is_openapi_file(target_file_or_dir):
                openapi_file = target_file_or_dir
        else:
            for root, dirs, files in os.walk(target_file_or_dir):
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                for file in files:
                    if file.endswith(('.yaml', '.yml', '.json')):
                        filepath = os.path.join(root, file)
                        if self._is_openapi_file(filepath):
                            openapi_file = filepath
                            break
                if openapi_file:
                    break

        if not openapi_file:
            logger.info("Nessun file OpenAPI/Swagger rilevato per Spectral.")
            return []

        logger.info(f"📄 Trovato contratto OpenAPI da scansionare: {openapi_file}")
        
        ruleset_path = DEFAULT_SPECTRAL_RULESET_PATH
        if not os.path.exists(ruleset_path):
            ruleset_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../config/scanner_configs/spectral-owasp.yaml"))

        report_file = DEFAULT_SPECTRAL_REPORT_FILE
        cmd = ["npx", "-y", "@stoplight/spectral-cli", "lint", openapi_file, 
               "--ruleset", ruleset_path, "--format", "json", "-o", report_file]
               
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=SPECTRAL_TIMEOUT_SECONDS)
        except (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
            logger.warning(f"Salto scansione Spectral (npx o comando fallito): {e}")
            return []
        
        findings: List[Finding] = []
        if os.path.exists(report_file):
            try:
                with open(report_file, "r", encoding="utf-8") as f:
                    issues = json.load(f)
                    
                for issue in issues:
                    rule_code = str(issue.get("code", "unknown"))
                    msg = issue.get("message", "Violazione contratto API")
                    severity_val = Severity.HIGH if issue.get("severity") == 0 else Severity.MEDIUM
                    
                    # Categoria derivata da rule_code o message
                    rule_code_lower = rule_code.lower()
                    msg_lower = msg.lower()
                    
                    category = FindingCategory.DATA_EXPOSURE
                    if "auth" in rule_code_lower or "security" in rule_code_lower or "auth" in msg_lower:
                        category = FindingCategory.AUTHENTICATION
                    elif "rate" in rule_code_lower or "limit" in rule_code_lower:
                        category = FindingCategory.RATE_LIMITING
                    elif "validate" in rule_code_lower or "schema" in rule_code_lower or "type" in rule_code_lower:
                        category = FindingCategory.INPUT_VALIDATION
                    elif "header" in rule_code_lower or "cors" in rule_code_lower:
                        category = FindingCategory.SECURITY_HEADERS

                    start_line = issue.get("range", {}).get("start", {}).get("line")
                    source_file = issue.get("source", openapi_file)
                    loc = CodeLocation(
                        file_path=source_file,
                        start_line=start_line
                    )
                    
                    # Estrae l'API Context dal JSON path di Spectral
                    path_list = issue.get("path", [])
                    api_ctx = None
                    target_ident = f"{source_file}"
                    if len(path_list) >= 3 and path_list[0] == "paths":
                        api_ctx = APIContext(
                            endpoint=path_list[1],
                            method=str(path_list[2]).upper()
                        )
                        target_ident += f"|{api_ctx.endpoint}|{api_ctx.method}"
                    
                    corr_key = source_file.split("/")[-1] if "/" in source_file else source_file

                    finding = Finding.create(
                        source=FindingSource.SPECTRAL,
                        category=category,
                        title=rule_code,
                        description=msg,
                        severity=severity_val,
                        confidence=1.0,
                        rule_id=rule_code,
                        target_identifier=target_ident,
                        rule_name=rule_code,
                        location=loc,
                        api=api_ctx,
                        correlation_key=corr_key,
                        raw_data=issue
                    )
                    findings.append(finding)
            except (json.JSONDecodeError, OSError) as e:
                logger.error(f"Errore parsing report di Spectral: {e}", exc_info=True)
            finally:
                if os.path.exists(report_file):
                    os.remove(report_file)
                    
        logger.info(f"Spectral completato. Rilevate {len(findings)} deviazioni contrattuali.")
        return findings

    def _is_openapi_file(self, filepath: str) -> bool:
        """
        Verifica preliminarmente se il file all'indirizzo fornito contiene firme del formato OpenAPI.

        Args:
            filepath (str): Percorso del file da controllare.

        Returns:
            bool: True se contiene firme OpenAPI, altrimenti False.
        """
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read(OPENAPI_PREVIEW_SIZE_BYTES)  # Legge i primi KB per efficienza
                if "openapi:" in content or "swagger:" in content:
                    return True
        except Exception:
            pass
        return False
