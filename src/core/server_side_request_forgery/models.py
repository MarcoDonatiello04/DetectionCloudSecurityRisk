from dataclasses import dataclass
from typing import Any


@dataclass
class SsrfFinding:
    rule_id: str  # es. "SS-001"
    semgrep_rule_id: str  # es. "python.requests.ssrf.requests-ssrf"
    cwe_id: str  # sempre "CWE-918"
    category: str  # es. "direct_url_from_input", "insufficient_validation"
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM"
    file_path: str
    line_number: int | None  # None per le finding a livello di contratto OpenAPI
    endpoint: str | None  # route associata se identificabile
    source: str  # dove entra l'input utente (es. "request.args.get('url')")
    sink: str  # dove finisce (es. "requests.get(url)")
    validation_found: bool  # True se esiste una validazione (anche insufficiente)
    validation_type: str | None  # "allowlist" | "blocklist" | "none"
    allow_redirects: bool | None  # True se il client segue redirect (rischio aggiuntivo)
    evidence: str
    confidence: float
    layer: str  # "semgrep" | "openapi"


@dataclass
class SsrfReport:
    target_path: str
    semgrep_version: str
    findings: list[SsrfFinding]
    coverage_signals: dict[str, Any]
    summary: dict[str, Any]
