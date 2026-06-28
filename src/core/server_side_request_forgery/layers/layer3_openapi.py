import logging
from typing import Dict, Any, List, Optional
from src.core.server_side_request_forgery.models import SsrfFinding

logger = logging.getLogger(__name__)

URL_PARAMETER_NAMES = {
    "url", "uri", "endpoint", "target", "destination",
    "callback", "callback_url", "webhook", "webhook_url",
    "redirect", "redirect_url", "redirect_uri",
    "resource", "resource_url", "fetch_url",
    "proxy", "proxy_url", "forward_url",
    "src", "source", "origin", "host"
}

def analyze_openapi(
    spec: dict,
    enrich_spec: bool = False
) -> List[SsrfFinding]:
    """
    Analizza spec OpenAPI per parametri URL non validati.
    Produce finding SS-006.
    """
    findings = []
    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        return findings
    
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
            
        for method, operation in path_item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete"):
                continue
            if not isinstance(operation, dict):
                continue
            
            # Parametri query/path/header
            for param in operation.get("parameters", []):
                if not isinstance(param, dict):
                    continue
                finding = _check_url_parameter(param, path, method, spec)
                if finding:
                    findings.append(finding)
            
            # Properties nel requestBody
            body_findings = _check_request_body(
                operation.get("requestBody", {}), path, method
            )
            findings.extend(body_findings)
    
    if enrich_spec:
        _enrich_spec_with_findings(spec, findings)
    
    return findings


def _check_url_parameter(param: dict, path: str, method: str, spec: dict) -> Optional[SsrfFinding]:
    name = param.get("name", "").lower()
    if name not in URL_PARAMETER_NAMES:
        return None
    
    schema = param.get("schema", {})
    if not isinstance(schema, dict) or schema.get("type") != "string":
        return None
    
    has_format_uri = schema.get("format") == "uri"
    has_pattern = "pattern" in schema
    
    if has_format_uri and has_pattern:
        return None  # ben validato
    
    severity = "LOW" if has_format_uri else "HIGH"
    missing = []
    if not has_format_uri:
        missing.append("format: uri")
    if not has_pattern:
        missing.append("pattern (allowlist)")
    
    return SsrfFinding(
        rule_id="SS-006",
        semgrep_rule_id="openapi-url-param-no-validation",
        cwe_id="CWE-918",
        category="unvalidated_url_parameter",
        severity=severity,
        file_path="openapi_spec",
        line_number=None,
        endpoint=f"{method.upper()} {path}",
        source=f"parameter '{param.get('name')}' in {param.get('in')}",
        sink="unknown — inferred from spec",
        validation_found=has_format_uri,
        validation_type="format_uri" if has_format_uri else None,
        allow_redirects=None,
        evidence=f"Parameter '{param.get('name')}' (type: string) missing: {', '.join(missing)}",
        confidence=0.75,
        layer="openapi"
    )


def _check_request_body(request_body: dict, path: str, method: str) -> List[SsrfFinding]:
    findings = []
    if not isinstance(request_body, dict):
        return findings
    
    content = request_body.get("content", {})
    if not isinstance(content, dict):
        return findings
        
    for mime_type, media_type in content.items():
        if not isinstance(media_type, dict):
            continue
        schema = media_type.get("schema", {})
        if not isinstance(schema, dict):
            continue
            
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            continue
            
        for prop_name, prop_schema in properties.items():
            if not isinstance(prop_schema, dict):
                continue
            
            name_lower = prop_name.lower()
            if name_lower not in URL_PARAMETER_NAMES:
                continue
                
            if prop_schema.get("type") != "string":
                continue
                
            has_format_uri = prop_schema.get("format") == "uri"
            has_pattern = "pattern" in prop_schema
            
            if has_format_uri and has_pattern:
                continue  # ben validato
                
            severity = "LOW" if has_format_uri else "HIGH"
            missing = []
            if not has_format_uri:
                missing.append("format: uri")
            if not has_pattern:
                missing.append("pattern (allowlist)")
                
            finding = SsrfFinding(
                rule_id="SS-006",
                semgrep_rule_id="openapi-url-param-no-validation",
                cwe_id="CWE-918",
                category="unvalidated_url_parameter",
                severity=severity,
                file_path="openapi_spec",
                line_number=None,
                endpoint=f"{method.upper()} {path}",
                source=f"body property '{prop_name}'",
                sink="unknown — inferred from spec",
                validation_found=has_format_uri,
                validation_type="format_uri" if has_format_uri else None,
                allow_redirects=None,
                evidence=f"Request body property '{prop_name}' (type: string) missing: {', '.join(missing)}",
                confidence=0.75,
                layer="openapi"
            )
            findings.append(finding)
            
    return findings


def _enrich_spec_with_findings(spec: dict, findings: List[SsrfFinding]) -> None:
    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        return
        
    for finding in findings:
        if not finding.endpoint:
            continue
        parts = finding.endpoint.split(" ", 1)
        if len(parts) != 2:
            continue
        method, path = parts[0].lower(), parts[1]
        
        path_item = paths.get(path)
        if not isinstance(path_item, dict):
            continue
            
        operation = path_item.get(method)
        if not isinstance(operation, dict):
            continue
            
        sec_analysis = operation.setdefault("x-security-analysis", {})
        if not isinstance(sec_analysis, dict):
            sec_analysis = {}
            operation["x-security-analysis"] = sec_analysis
            
        api7_findings = sec_analysis.setdefault("api7_findings", [])
        if not isinstance(api7_findings, list):
            api7_findings = []
            sec_analysis["api7_findings"] = api7_findings
            
        api7_findings.append({
            "rule_id": finding.rule_id,
            "cwe_id": finding.cwe_id,
            "category": finding.category,
            "severity": finding.severity,
            "source": finding.source,
            "validation_found": finding.validation_found,
            "validation_type": finding.validation_type,
            "evidence": finding.evidence
        })
