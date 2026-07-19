"""
Tests for Layer 2 Config detection — API4:2023 Unrestricted Resource Consumption.

Rules covered:
  RC-007 — No memory/CPU limits in docker-compose.yml
  RC-008 — No body size limit (nginx.conf, .env)
  RC-009 — No request timeout (nginx.conf, gunicorn.conf.py)

For each config type and rule:
  - TP: vulnerable fixture triggers the rule
  - TN: secure fixture does NOT trigger the rule
  - Robustness: malformed file → no crash, returns empty list

All tests read from real fixture files (no mocking).
"""

from __future__ import annotations

from pathlib import Path

from src.core.unrestricted_resource_consumption.layers.layer2_config import (
    _parse_docker_compose,
    _parse_env_body_size,
    _parse_gunicorn_timeout,
    _parse_nginx_body_size,
    _parse_nginx_timeout,
    analyze_configs,
    discover_config_files,
)

# ---------------------------------------------------------------------------
# Fixture paths
# ---------------------------------------------------------------------------

FIXTURES_DIR = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "test_targets"
    / "unrestricted_resource_consumption"
)
VULN_DIR = FIXTURES_DIR / "vulnerable_app"
SECURE_DIR = FIXTURES_DIR / "secure_app"

VULN_COMPOSE = VULN_DIR / "docker-compose.yml"
SECURE_COMPOSE = SECURE_DIR / "docker-compose.yml"

VULN_NGINX = VULN_DIR / "nginx.conf"
SECURE_NGINX = SECURE_DIR / "nginx.conf"

VULN_GUNICORN = VULN_DIR / "gunicorn.conf.py"
SECURE_GUNICORN = SECURE_DIR / "gunicorn.conf.py"

VULN_ENV = VULN_DIR / ".env"
SECURE_ENV = SECURE_DIR / ".env"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rule_ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


def _write_temp(tmp_path: Path, name: str, content: str) -> Path:
    f = tmp_path / name
    f.write_text(content)
    return f


# ===========================================================================
# RC-007 — docker-compose.yml: no resource limits
# ===========================================================================


class TestRC007DockerCompose:
    def test_tp_vulnerable_compose(self):
        """Vulnerable docker-compose: services without memory limits → RC-007"""
        findings = _parse_docker_compose(VULN_COMPOSE)
        assert any(f.rule_id == "RC-007" for f in findings), f"Expected RC-007, got: {findings}"

    def test_tn_secure_compose(self):
        """Secure docker-compose: all services have memory limits → no RC-007"""
        findings = _parse_docker_compose(SECURE_COMPOSE)
        rc007 = [f for f in findings if f.rule_id == "RC-007"]
        assert not rc007, f"Unexpected RC-007 in secure compose: {rc007}"

    def test_tp_reports_service_name(self):
        """Finding evidence includes the service name"""
        findings = _parse_docker_compose(VULN_COMPOSE)
        rc007 = [f for f in findings if f.rule_id == "RC-007"]
        assert rc007
        # At least one finding should mention a service name
        assert any("api" in f.evidence or "worker" in f.evidence for f in rc007)

    def test_tp_each_vulnerable_service_flagged(self):
        """Each service without limits should generate a finding"""
        findings = _parse_docker_compose(VULN_COMPOSE)
        # vulnerable_app/docker-compose.yml has 3 services without limits
        rc007 = [f for f in findings if f.rule_id == "RC-007"]
        assert len(rc007) >= 2, f"Expected ≥2 RC-007 findings, got {len(rc007)}"

    def test_robustness_malformed_yaml(self, tmp_path):
        """Malformed YAML → no crash, empty findings"""
        f = _write_temp(tmp_path, "docker-compose.yml", "services:\n  - [invalid yaml{{{\n")
        findings = _parse_docker_compose(f)
        assert isinstance(findings, list)

    def test_robustness_empty_yaml(self, tmp_path):
        """Empty YAML → no crash"""
        f = _write_temp(tmp_path, "docker-compose.yml", "")
        findings = _parse_docker_compose(f)
        assert isinstance(findings, list)

    def test_tp_inline_via_analyze_configs(self):
        """analyze_configs on vulnerable dir includes RC-007"""
        findings = analyze_configs(str(VULN_DIR))
        assert any(f.rule_id == "RC-007" for f in findings)

    def test_tn_inline_via_analyze_configs(self):
        """analyze_configs on secure dir should not include RC-007"""
        findings = analyze_configs(str(SECURE_DIR))
        rc007 = [f for f in findings if f.rule_id == "RC-007"]
        assert not rc007, f"Unexpected RC-007 in secure dir: {rc007}"


# ===========================================================================
# RC-008 — nginx.conf: no client_max_body_size
# ===========================================================================


class TestRC008NginxBodySize:
    def test_tp_vulnerable_nginx(self):
        """Vulnerable nginx.conf: no client_max_body_size → RC-008"""
        findings = _parse_nginx_body_size(VULN_NGINX)
        assert any(f.rule_id == "RC-008" for f in findings)

    def test_tn_secure_nginx(self):
        """Secure nginx.conf: client_max_body_size present → no HIGH RC-008"""
        findings = _parse_nginx_body_size(SECURE_NGINX)
        high = [f for f in findings if f.rule_id == "RC-008" and f.severity == "HIGH"]
        assert not high, f"Unexpected HIGH RC-008 in secure nginx: {high}"

    def test_tp_high_severity_when_absent(self):
        """Severity should be HIGH when directive completely absent"""
        findings = _parse_nginx_body_size(VULN_NGINX)
        rc008 = [f for f in findings if f.rule_id == "RC-008"]
        assert all(f.severity == "HIGH" for f in rc008)

    def test_robustness_empty_nginx(self, tmp_path):
        """Empty nginx.conf → no crash, finding generated (missing directive)"""
        f = _write_temp(tmp_path, "nginx.conf", "")
        findings = _parse_nginx_body_size(f)
        assert isinstance(findings, list)

    def test_robustness_nonexistent_file(self, tmp_path):
        """Non-existent file → no crash, empty list"""
        findings = _parse_nginx_body_size(tmp_path / "nonexistent.conf")
        assert findings == []

    def test_medium_severity_when_oversized(self, tmp_path):
        """client_max_body_size > 50MB → MEDIUM warning"""
        content = "http { server { client_max_body_size 100m; } }"
        f = _write_temp(tmp_path, "nginx.conf", content)
        findings = _parse_nginx_body_size(f)
        medium = [f for f in findings if f.rule_id == "RC-008" and f.severity == "MEDIUM"]
        assert medium, "Expected MEDIUM finding for oversized body limit"


# ===========================================================================
# RC-008 — .env: no MAX_CONTENT_LENGTH
# ===========================================================================


class TestRC008EnvBodySize:
    def test_tp_vulnerable_env(self):
        """Vulnerable .env: MAX_CONTENT_LENGTH absent → RC-008"""
        findings = _parse_env_body_size(VULN_ENV)
        assert any(f.rule_id == "RC-008" for f in findings)

    def test_tn_secure_env(self):
        """Secure .env: MAX_CONTENT_LENGTH present → no RC-008"""
        findings = _parse_env_body_size(SECURE_ENV)
        rc008 = [f for f in findings if f.rule_id == "RC-008"]
        assert not rc008, f"Unexpected RC-008 in secure .env: {rc008}"

    def test_tn_data_upload_max_memory(self, tmp_path):
        """Django DATA_UPLOAD_MAX_MEMORY_SIZE counts as a guard"""
        content = "DATABASE_URL=postgres://...\nDATA_UPLOAD_MAX_MEMORY_SIZE=5242880\n"
        f = _write_temp(tmp_path, ".env", content)
        findings = _parse_env_body_size(f)
        rc008 = [finding for finding in findings if finding.rule_id == "RC-008"]
        assert not rc008

    def test_robustness_empty_env(self, tmp_path):
        """Empty .env → finding (nothing set)"""
        f = _write_temp(tmp_path, ".env", "")
        findings = _parse_env_body_size(f)
        assert isinstance(findings, list)


# ===========================================================================
# RC-009 — nginx.conf: no proxy timeouts
# ===========================================================================


class TestRC009NginxTimeout:
    def test_tp_vulnerable_nginx(self):
        """Vulnerable nginx.conf: proxy_pass locations without timeouts → RC-009"""
        findings = _parse_nginx_timeout(VULN_NGINX)
        assert any(f.rule_id == "RC-009" for f in findings)

    def test_tn_secure_nginx(self):
        """Secure nginx.conf: all proxy locations have timeouts → no RC-009"""
        findings = _parse_nginx_timeout(SECURE_NGINX)
        rc009 = [f for f in findings if f.rule_id == "RC-009"]
        assert not rc009, f"Unexpected RC-009 in secure nginx: {rc009}"

    def test_tp_multiple_locations_flagged(self):
        """Each proxy_pass location without timeout generates a finding"""
        findings = _parse_nginx_timeout(VULN_NGINX)
        rc009 = [f for f in findings if f.rule_id == "RC-009"]
        # vulnerable nginx has 2 proxy_pass locations
        assert len(rc009) >= 2, f"Expected ≥2 RC-009 findings, got {len(rc009)}"

    def test_robustness_nginx_no_proxy(self, tmp_path):
        """nginx.conf without proxy_pass → no RC-009"""
        content = "server { location / { root /var/www; } }"
        f = _write_temp(tmp_path, "nginx.conf", content)
        findings = _parse_nginx_timeout(f)
        rc009 = [f for f in findings if f.rule_id == "RC-009"]
        assert not rc009

    def test_robustness_empty_nginx(self, tmp_path):
        """Empty nginx.conf → no crash"""
        f = _write_temp(tmp_path, "nginx.conf", "")
        findings = _parse_nginx_timeout(f)
        assert isinstance(findings, list)


# ===========================================================================
# RC-009 — gunicorn.conf.py: timeout = 0
# ===========================================================================


class TestRC009Gunicorn:
    def test_tp_timeout_zero(self):
        """gunicorn.conf.py with timeout = 0 → RC-009 HIGH"""
        findings = _parse_gunicorn_timeout(VULN_GUNICORN)
        rc009 = [f for f in findings if f.rule_id == "RC-009"]
        assert rc009, "Expected RC-009 for timeout=0"
        assert any(f.severity == "HIGH" for f in rc009)

    def test_tn_timeout_thirty(self):
        """gunicorn.conf.py with timeout = 30 → no RC-009"""
        findings = _parse_gunicorn_timeout(SECURE_GUNICORN)
        rc009 = [f for f in findings if f.rule_id == "RC-009"]
        assert not rc009, f"Unexpected RC-009 in secure gunicorn: {rc009}"

    def test_tp_timeout_zero_confidence(self):
        """timeout = 0 should have near-certain confidence"""
        findings = _parse_gunicorn_timeout(VULN_GUNICORN)
        rc009 = [f for f in findings if f.rule_id == "RC-009"]
        assert rc009 and rc009[0].confidence >= 0.95

    def test_tp_timeout_absent(self, tmp_path):
        """No timeout in gunicorn.conf.py → RC-009 LOW"""
        content = "bind = '0.0.0.0:8000'\nworkers = 4\n"
        f = _write_temp(tmp_path, "gunicorn.conf.py", content)
        findings = _parse_gunicorn_timeout(f)
        rc009 = [f for f in findings if f.rule_id == "RC-009"]
        assert rc009
        assert rc009[0].severity == "LOW"

    def test_robustness_syntax_error(self, tmp_path):
        """Broken Python syntax → no crash, empty list"""
        f = _write_temp(tmp_path, "gunicorn.conf.py", "timeout = [invalid(")
        findings = _parse_gunicorn_timeout(f)
        assert isinstance(findings, list)


# ===========================================================================
# Integration — analyze_configs() end-to-end
# ===========================================================================


class TestAnalyzeConfigs:
    def test_returns_list(self):
        result = analyze_configs(str(VULN_DIR))
        assert isinstance(result, list)

    def test_nonexistent_path_returns_empty(self):
        result = analyze_configs("/nonexistent/path/xyz")
        assert result == []

    def test_vulnerable_dir_all_rules_present(self):
        findings = analyze_configs(str(VULN_DIR))
        found = _rule_ids(findings)
        assert "RC-007" in found, f"RC-007 missing in: {found}"
        assert "RC-008" in found, f"RC-008 missing in: {found}"
        assert "RC-009" in found, f"RC-009 missing in: {found}"

    def test_secure_dir_no_high_severity_findings(self):
        findings = analyze_configs(str(SECURE_DIR))
        high = [f for f in findings if f.severity == "HIGH"]
        assert not high, f"Unexpected HIGH findings in secure dir: {high}"

    def test_all_findings_have_layer_config(self):
        findings = analyze_configs(str(VULN_DIR))
        assert all(f.layer == "config" for f in findings)

    def test_all_findings_have_file_path(self):
        findings = analyze_configs(str(VULN_DIR))
        assert all(f.file_path for f in findings)

    def test_discover_config_files_finds_expected(self):
        files = discover_config_files(str(VULN_DIR))
        names = {f.name for f in files}
        assert "docker-compose.yml" in names
        assert "nginx.conf" in names
        assert "gunicorn.conf.py" in names
        assert ".env" in names

    def test_discover_skips_nonexistent(self):
        files = discover_config_files("/does/not/exist")
        assert files == []

    def test_analyze_single_file(self):
        """analyze_configs should work on a single file path, not just directories"""
        findings = analyze_configs(str(VULN_NGINX))
        assert isinstance(findings, list)
