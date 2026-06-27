from dataclasses import dataclass
from typing import List, Dict, Optional, Any

@dataclass
class SsrfFinding:
    rule_id: str              # es. "SS-001"
    semgrep_rule_id: str      # es. "python.requests.ssrf.requests-ssrf"
    cwe_id: str               # sempre "CWE-918"
    category: str             # es. "direct_url_from_input", "insufficient_validation"
    severity: str             # "CRITICAL" | "HIGH" | "MEDIUM"
    file_path: str
    line_number: int
    endpoint: Optional[str]      # route associata se identificabile
    source: str               # dove entra l'input utente (es. "request.args.get('url')")
    sink: str                 # dove finisce (es. "requests.get(url)")
    validation_found: bool    # True se esiste una validazione (anche insufficiente)
    validation_type: Optional[str]  # "allowlist" | "blocklist" | "none"
    allow_redirects: Optional[bool] # True se il client segue redirect (rischio aggiuntivo)
    evidence: str
    confidence: float
    layer: str                # "semgrep" | "openapi"

@dataclass
class SsrfReport:
    target_path: str
    semgrep_version: str
    findings: List[SsrfFinding]
    coverage_signals: Dict[str, Any]
    summary: Dict[str, Any]
