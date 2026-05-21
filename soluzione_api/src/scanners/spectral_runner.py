import os
import json
import subprocess
from typing import List
from src.models.finding import Finding, FindingSource, FindingCategory, Severity, CodeLocation, APIContext

def is_openapi_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            if 'openapi:' in content or 'swagger:' in content:
                return True
    except Exception:
        pass
    return False

from src.interfaces.scanner import ScannerInterface

class SpectralRunner(ScannerInterface):
    def scan(self, target_file_or_dir: str = ".") -> List[Finding]:
        print("🚀 Esecuzione Spectral API Scanner (OWASP)...")
        openapi_file = None
        
        if os.path.isfile(target_file_or_dir):
            openapi_file = target_file_or_dir
        else:
            for root, dirs, files in os.walk(target_file_or_dir):
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                for file in files:
                    if file.endswith(('.yaml', '.yml', '.json')):
                        filepath = os.path.join(root, file)
                        if is_openapi_file(filepath):
                            openapi_file = filepath
                            break
                if openapi_file: break

        if not openapi_file:
            print("ℹ️ Nessun file OpenAPI trovato.")
            return []

        print(f"📄 File OpenAPI trovato: {openapi_file}")
        
        ruleset_path = "config/scanner_configs/spectral-owasp.yaml"
        if not os.path.exists(ruleset_path):
            ruleset_path = os.path.join(os.path.dirname(__file__), "../../../config/scanner_configs/spectral-owasp.yaml")

        cmd = ["npx", "-y", "@stoplight/spectral-cli", "lint", openapi_file, "--ruleset", ruleset_path, "--format", "json", "-o", "spectral_report.json"]
        try:
            subprocess.run(cmd, capture_output=True, text=True)
        except FileNotFoundError:
            print("⚠️ npx non trovato. Salto la scansione Spectral.")
            return []
        except Exception as e:
            print(f"⚠️ Errore durante l'esecuzione di Spectral: {e}")
            return []
        
        findings = []
        if os.path.exists("spectral_report.json"):
            with open("spectral_report.json", "r") as f:
                try:
                    issues = json.load(f)
                    idx = 0
                    for issue in issues:
                        rule_code = str(issue.get("code", "unknown"))
                        msg = issue.get("message", "Violazione contratto API")
                        severity_val = Severity.HIGH if issue.get("severity") == 0 else Severity.MEDIUM
                        
                        # Categoria derivata da rule_code o message
                        rule_code_lower = rule_code.lower()
                        msg_lower = msg.lower()
                        if "auth" in rule_code_lower or "security" in rule_code_lower or "auth" in msg_lower:
                            cat = FindingCategory.AUTHENTICATION
                        elif "rate" in rule_code_lower or "limit" in rule_code_lower:
                            cat = FindingCategory.RATE_LIMITING
                        elif "validate" in rule_code_lower or "schema" in rule_code_lower or "type" in rule_code_lower:
                            cat = FindingCategory.INPUT_VALIDATION
                        elif "header" in rule_code_lower or "cors" in rule_code_lower:
                            cat = FindingCategory.SECURITY_HEADERS
                        else:
                            cat = FindingCategory.DATA_EXPOSURE

                        start_line = issue.get("range", {}).get("start", {}).get("line")
                        source_file = issue.get("source", openapi_file)
                        loc = CodeLocation(
                            file_path=source_file,
                            start_line=start_line
                        )
                        
                        # Estrae l'API Context dalla gerarchia del path di Spectral
                        path_list = issue.get("path", [])
                        api_ctx = None
                        target_ident = f"{source_file}"
                        if len(path_list) >= 3 and path_list[0] == "paths":
                            api_ctx = APIContext(
                                endpoint=path_list[1],
                                method=str(path_list[2]).upper()
                            )
                            target_ident += f"|{api_ctx.endpoint}|{api_ctx.method}"
                        
                        # Generazione ID univoco basato anche su endpoint e metodo per evitare sovrascritture/duplicati logici
                        finding_id = Finding.generate_deterministic_id(FindingSource.SPECTRAL, rule_code, target_ident)
                        corr_key = source_file.split("/")[-1] if "/" in source_file else source_file

                        finding = Finding(
                            finding_id=finding_id,
                            source=FindingSource.SPECTRAL,
                            category=cat,
                            title=rule_code,
                            description=msg,
                            severity=severity_val,
                            confidence=1.0,
                            rule_id=rule_code,
                            rule_name=rule_code,
                            location=loc,
                            api=api_ctx,
                            correlation_key=corr_key,
                            raw_data=issue
                        )
                        findings.append(finding)
                except Exception as e:
                    print(f"⚠️ Errore parsing Spectral JSON: {e}")
        return findings

def run_spectral(target_file_or_dir=".") -> List[Finding]:
    return SpectralRunner().scan(target_file_or_dir)
