import os
import re

from src.core.api8_ssrf.models import SsrfFinding


def normalize_semgrep_output(semgrep_json: dict, target_path: str) -> list[SsrfFinding]:
    """
    Converte l'output JSON di Semgrep in lista di SsrfFinding.
    """
    findings = []

    for result in semgrep_json.get("results", []):
        metadata = result.get("extra", {}).get("metadata", {})

        finding = SsrfFinding(
            rule_id=metadata.get("rule_id_internal", "SS-000"),
            semgrep_rule_id=result.get("check_id", ""),
            cwe_id=metadata.get("cwe", "CWE-918"),
            category=metadata.get("category", "unknown"),
            severity=_map_severity(result.get("extra", {}).get("severity", "WARNING")),
            file_path=_make_relative(result.get("path", ""), target_path),
            line_number=result.get("start", {}).get("line", 0),
            endpoint=None,  # arricchito dopo da route discovery
            source=_extract_source(result),
            sink=_extract_sink(result),
            validation_found=_has_validation(result),
            validation_type=_detect_validation_type(result),
            allow_redirects=_detect_allow_redirects(result),
            evidence=result.get("extra", {}).get("lines", "").strip(),
            confidence=_compute_confidence(result),
            layer="semgrep",
        )
        findings.append(finding)

    return findings


def _map_severity(semgrep_severity: str) -> str:
    return {"ERROR": "CRITICAL", "WARNING": "HIGH", "INFO": "MEDIUM"}.get(
        semgrep_severity, "MEDIUM"
    )


def _compute_confidence(result: dict) -> float:
    """
    Confidenza basata sul tipo di match:
    - Match diretto source→sink nello stesso scope: 0.90
    - Match con validazione presente ma insufficiente: 0.75
    - Match su metadata endpoint (SS-005): 0.70 (potrebbe essere legittimo)
    """
    category = result.get("extra", {}).get("metadata", {}).get("category", "")
    if category == "cloud_metadata_access":
        return 0.70
    if _has_validation(result):
        return 0.75
    return 0.90


def _has_validation(result: dict) -> bool:
    """Verifica se Semgrep ha trovato una validazione (anche insufficiente)."""
    lines = result.get("extra", {}).get("lines", "")
    validation_keywords = ["urlparse", "allowlist", "whitelist", "is_allowed", "validate_url"]
    return any(kw in lines for kw in validation_keywords)


def _make_relative(path: str, target_path: str) -> str:
    """Converte un percorso assoluto in relativo al target_path."""
    try:
        return os.path.relpath(path, target_path)
    except Exception:
        return path


def _extract_source(result: dict) -> str:
    """Estrae la variabile o espressione sorgente dell'input."""
    extra = result.get("extra", {})
    metavars = extra.get("metavars", {})
    if "$URL" in metavars:
        return metavars["$URL"].get("abstract_content", "url")

    # Fallback heuristico da lines
    lines = extra.get("lines", "")
    match = re.search(r'request\.(args|json|form|headers)\.get\([\'"]([^\'"]+)[\'"]\)', lines)
    if match:
        return f"request.{match.group(1)}['{match.group(2)}']"
    return "user_input"


def _extract_sink(result: dict) -> str:
    """Estrae la chiamata del client HTTP (sink)."""
    extra = result.get("extra", {})
    lines = extra.get("lines", "").strip()
    if not lines:
        return result.get("check_id", "http_request")
    return lines.split("\n")[0].strip()


def _detect_validation_type(result: dict) -> str | None:
    """Identifica la tipologia di validazione."""
    lines = result.get("extra", {}).get("lines", "").lower()
    if any(kw in lines for kw in ["allowlist", "whitelist", "is_allowed"]):
        return "allowlist"
    if any(kw in lines for kw in ["blacklist", "blocklist", "not_allowed"]):
        return "blocklist"
    if _has_validation(result):
        return "none"
    return "none"


def _detect_allow_redirects(result: dict) -> bool | None:
    """Indica se il client segue redirect (rischio aggiuntivo)."""
    lines = result.get("extra", {}).get("lines", "")
    if "allow_redirects" in lines:
        no_spaces = lines.replace(" ", "")
        if "allow_redirects=True" in no_spaces:
            return True
        if "allow_redirects=False" in no_spaces:
            return False
    check_id = result.get("check_id", "")
    if "redirect" in check_id.lower():
        return True
    return None
