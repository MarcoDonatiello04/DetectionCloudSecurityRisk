from src.core.server_side_request_forgery.normalizer import (
    _compute_confidence,
    _detect_allow_redirects,
    _detect_validation_type,
    _map_severity,
    normalize_semgrep_output,
)


def test_normalize_maps_severity():
    semgrep_json = {
        "results": [
            {
                "check_id": "ssrf-python-requests-url-from-input",
                "path": "/tmp/test.py",
                "start": {"line": 10},
                "extra": {
                    "severity": "ERROR",
                    "lines": "requests.get(url)",
                    "metadata": {
                        "rule_id_internal": "SS-001",
                        "cwe": "CWE-918",
                        "category": "direct_url_from_input",
                    },
                },
            }
        ]
    }
    findings = normalize_semgrep_output(semgrep_json, "/tmp")
    assert findings[0].severity == "CRITICAL"
    assert findings[0].rule_id == "SS-001"
    assert findings[0].cwe_id == "CWE-918"


def test_normalize_empty_results():
    findings = normalize_semgrep_output({"results": []}, "/tmp")
    assert findings == []


def test_map_severity():
    assert _map_severity("ERROR") == "CRITICAL"
    assert _map_severity("WARNING") == "HIGH"
    assert _map_severity("INFO") == "MEDIUM"
    assert _map_severity("OTHER") == "MEDIUM"


def test_compute_confidence():
    # Category: cloud_metadata_access -> 0.70
    assert (
        _compute_confidence({"extra": {"metadata": {"category": "cloud_metadata_access"}}}) == 0.70
    )

    # Has validation -> 0.75
    assert _compute_confidence({"extra": {"lines": "urlparse(url)"}}) == 0.75

    # Otherwise -> 0.90
    assert _compute_confidence({"extra": {"lines": "requests.get(url)"}}) == 0.90


def test_detect_validation_type():
    assert _detect_validation_type({"extra": {"lines": "if url in allowlist:"}}) == "allowlist"
    assert _detect_validation_type({"extra": {"lines": "if url in blacklist:"}}) == "blocklist"
    assert _detect_validation_type({"extra": {"lines": "urlparse(url)"}}) == "none"


def test_detect_allow_redirects():
    assert (
        _detect_allow_redirects({"extra": {"lines": "requests.get(url, allow_redirects=True)"}})
        is True
    )
    assert (
        _detect_allow_redirects({"extra": {"lines": "requests.get(url, allow_redirects=False)"}})
        is False
    )
    assert (
        _detect_allow_redirects(
            {"check_id": "ssrf-python-requests-redirect-following", "extra": {"lines": ""}}
        )
        is True
    )
    assert _detect_allow_redirects({"check_id": "other-rule", "extra": {"lines": ""}}) is None
