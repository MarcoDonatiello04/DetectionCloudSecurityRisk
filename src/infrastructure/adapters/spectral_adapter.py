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
        
        # 1. Carica le rotte originali definite nel contratto per poter fare distinzione
        from src.normalization.normalizer import APIEndpointNormalizer
        import yaml
        original_paths = set()
        original_data = {}
        try:
            with open(openapi_file, "r", encoding="utf-8") as f:
                original_data = yaml.safe_load(f) or {}
                paths_dict = original_data.get("paths", {}) or {}
                for p in paths_dict.keys():
                    original_paths.add(APIEndpointNormalizer.normalize_path(p))
        except Exception as e:
            logger.error(f"Errore lettura api spec originale: {e}")

        # 2. Ottieni la lista degli endpoint scoperti da Semgrep (se presente nella cache statica)
        from src.infrastructure.adapters.semgrep_adapter import SemgrepScannerAdapter
        discovered = getattr(SemgrepScannerAdapter, "discovered_endpoints_cache", [])

        # 3. Costruisci il dizionario OpenAPI unito (merged)
        import copy
        merged_data = copy.deepcopy(original_data)
        if "paths" not in merged_data or merged_data["paths"] is None:
            merged_data["paths"] = {}

        # Aggiungi gli endpoint scoperti da Semgrep che non erano documentati
        for ep in discovered:
            method = ep["method"].lower()
            path = ep["path"]
            norm_path = APIEndpointNormalizer.normalize_path(path)
            
            if norm_path not in original_paths:
                if path not in merged_data["paths"]:
                    merged_data["paths"][path] = {}
                
                # Definiamo l'operazione minimale
                op_data = {
                    "summary": f"Discovered API Endpoint ({ep.get('framework', 'Semgrep')})",
                    "responses": {
                        "200": {
                            "description": "Risposta automatica"
                        }
                    }
                }
                # Se Semgrep ha rilevato che richiede autenticazione, aggiungiamo il campo security
                if ep.get("auth_detected"):
                    op_data["security"] = [{"BearerAuth": []}]
                
                merged_data["paths"][path][method] = op_data

        # 4. Scrivi il contratto unito in un file temporaneo nello stesso folder
        merged_file_path = openapi_file.replace(os.path.basename(openapi_file), "openapi_merged_temp.yaml")
        try:
            with open(merged_file_path, "w", encoding="utf-8") as f:
                yaml.safe_dump(merged_data, f, default_flow_style=False)
            logger.info(f"📄 Creato file temporaneo OpenAPI unito per Spectral: {merged_file_path}")
            
            # Salva una copia stabile nella cartella output per la Dashboard UI
            stable_output_path = "output/openapi_merged.yaml"
            os.makedirs("output", exist_ok=True)
            with open(stable_output_path, "w", encoding="utf-8") as f_stable:
                yaml.safe_dump(merged_data, f_stable, default_flow_style=False)
            logger.info(f"💾 Copia stabile OpenAPI salvata per la UI in: {stable_output_path}")
        except Exception as e:
            logger.error(f"Errore scrittura merged yaml: {e}")
            merged_file_path = openapi_file  # fallback all'originale in caso di errore

        ruleset_path = DEFAULT_SPECTRAL_RULESET_PATH
        if not os.path.exists(ruleset_path):
            ruleset_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../config/scanner_configs/spectral-owasp.yaml"))

        report_file = DEFAULT_SPECTRAL_REPORT_FILE
        cmd = ["npx", "-y", "@stoplight/spectral-cli", "lint", merged_file_path, 
               "--ruleset", ruleset_path, "--format", "json", "-o", report_file]
               
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=SPECTRAL_TIMEOUT_SECONDS)
        except (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
            logger.warning(f"Salto scansione Spectral (npx o comando fallito): {e}")
            if merged_file_path != openapi_file and os.path.exists(merged_file_path):
                os.remove(merged_file_path)
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
                    
                    if "openapi_merged_temp" in source_file:
                        source_file = openapi_file

                    loc = CodeLocation(
                        file_path=source_file,
                        start_line=start_line
                    )
                    
                    # Estrae l'API Context dal JSON path di Spectral
                    path_list = issue.get("path", [])
                    api_ctx = None
                    target_ident = f"{source_file}"
                    is_documented = True

                    if len(path_list) >= 3 and path_list[0] == "paths":
                        api_path = path_list[1]
                        api_method = str(path_list[2]).upper()
                        api_ctx = APIContext(
                            endpoint=api_path,
                            method=api_method
                        )
                        target_ident += f"|{api_ctx.endpoint}|{api_ctx.method}"
                        
                        norm_api_path = APIEndpointNormalizer.normalize_path(api_path)
                        if norm_api_path not in original_paths:
                            is_documented = False

                    # Definisce il titolo e descrizione in base a se l'API è documentata o scoperta
                    if is_documented:
                        title_str = f"[Documented API] {rule_code}"
                        desc_str = f"Violazione su API già documentata: {msg}"
                    else:
                        title_str = f"[Discovered API] {rule_code}"
                        desc_str = f"Violazione su API scoperta da Semgrep (non in OpenAPI): {msg}"

                    # Definiamo la chiave di correlazione includendo la regola specifica,
                    # altrimenti l'orchestratore raggrupperà tutte le violazioni dello stesso endpoint in un unico Finding.
                    if api_ctx:
                        corr_key = f"spectral:{api_ctx.endpoint}:{api_ctx.method}:{rule_code}"
                    else:
                        filename = source_file.split("/")[-1] if "/" in source_file else source_file
                        corr_key = f"openapi:{filename}:{rule_code}"

                    finding = Finding.create(
                        source=FindingSource.SPECTRAL,
                        category=category,
                        title=title_str,
                        description=desc_str,
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
                if merged_file_path != openapi_file and os.path.exists(merged_file_path):
                    try:
                        os.remove(merged_file_path)
                    except Exception as e:
                        logger.error(f"Errore rimozione file temporaneo unito: {e}")
                    
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
