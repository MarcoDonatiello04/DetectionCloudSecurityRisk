"""
Test del risk scoring allineato alla formula documentata (ADR-005):
    R = min(10, 0.6·S + 0.2·(10·C) + 0.2·X)

Copre: assenza di regole per categoria, contributo dei dati sensibili, conferma
empirica (exploitable) che forza C=1, guardia sul massimo, contesto degli adapter
Spectral/Semgrep e loader YAML con fallback sui default.
"""

import pytest

from src.application.correlation.engine import RiskCorrelationEngine
from src.core.config import RiskScoringConfig, load_risk_scoring_config
from src.core.risk_config import get_risk_scoring_config, reset_risk_scoring_config
from src.domain.entities import (
    Finding,
    FindingCategory,
    FindingNature,
    FindingSource,
    RiskContext,
    Severity,
)

# ─── Helper ──────────────────────────────────────────────────────────────────


def _finding(
    severity: Severity,
    confidence: float = 1.0,
    category: FindingCategory = FindingCategory.STORAGE,
    nature: FindingNature | None = FindingNature.EXPOSURE,
    risk_context: RiskContext | None = None,
) -> Finding:
    return Finding.create(
        source=FindingSource.CHECKOV,
        category=category,
        title="finding",
        description="finding",
        severity=severity,
        confidence=confidence,
        rule_id="RULE",
        target_identifier="res:main.tf",
        nature=nature,
        risk_context=risk_context,
    )


@pytest.fixture
def engine() -> RiskCorrelationEngine:
    return RiskCorrelationEngine()


# ─── Contesto ────────────────────────────────────────────────────────────────


def test_no_category_rule_authentication_without_context_gets_default(engine):
    # AUTHENTICATION senza RiskContext: X=3 come ogni altra categoria (non più 6)
    auth = _finding(Severity.HIGH, category=FindingCategory.AUTHENTICATION, nature=None)
    other = _finding(Severity.HIGH, category=FindingCategory.STORAGE, nature=None)
    # 0.6*7 + 0.2*10 + 0.2*3 = 6.8
    assert engine.calculate_risk_score(auth) == pytest.approx(6.8)
    assert engine.calculate_risk_score(auth) == engine.calculate_risk_score(other)


def test_sensitive_data_context_contributes_four(engine):
    secret = _finding(Severity.CRITICAL, risk_context=RiskContext(sensitive_data_detected=True))
    # 0.6*10 + 0.2*10 + 0.2*4 = 8.8
    assert engine.calculate_risk_score(secret) == pytest.approx(8.8)


def test_sensitive_and_public_context_saturates_at_max(engine):
    # X = 4 (internet) + 4 (sensibili) + 2 (pubblico) = 10 → R = 6 + 2 + 2 = 10.0
    public_secret = _finding(
        Severity.CRITICAL,
        risk_context=RiskContext(
            internet_exposed=True, public_resource=True, sensitive_data_detected=True
        ),
    )
    assert engine.calculate_risk_score(public_secret) == pytest.approx(10.0)


def test_max_risk_score_is_an_effective_guard():
    # Pesi volutamente sbilanciati: la somma supera 10 e la guardia deve scattare
    cfg = RiskScoringConfig(weight_severity=1.0, weight_confidence=0.5, weight_context=0.5)
    engine = RiskCorrelationEngine(scoring_config=cfg)
    finding = _finding(Severity.CRITICAL, risk_context=RiskContext(internet_exposed=True))
    assert engine.calculate_risk_score(finding) == pytest.approx(10.0)


def test_hardening_never_gets_context_bonus_even_with_sensitive_data(engine):
    encrypted_at_rest = _finding(
        Severity.MEDIUM,
        nature=FindingNature.HARDENING,
        risk_context=RiskContext(sensitive_data_detected=True, internet_exposed=True),
    )
    # 0.6*4.5 + 0.2*10 + 0.2*0 = 4.7
    assert engine.calculate_risk_score(encrypted_at_rest) == pytest.approx(4.7)


# ─── Confidenza ──────────────────────────────────────────────────────────────


def test_exploitable_context_forces_full_confidence(engine):
    weak = _finding(Severity.HIGH, confidence=0.5, risk_context=RiskContext(exploitable=True))
    # C forzata a 1: 0.6*7 + 0.2*10 + 0.2*0 = 6.2 (exploitable da solo non è esposizione)
    assert engine.calculate_risk_score(weak) == pytest.approx(6.2)
    # Senza exploitable la confidenza dichiarata resta in vigore: 0.6*7 + 0.2*5 + 0 = 5.2
    unconfirmed = _finding(
        Severity.HIGH, confidence=0.5, risk_context=RiskContext(exploitable=False)
    )
    assert engine.calculate_risk_score(unconfirmed) == pytest.approx(5.2)


def test_uncorrelated_runtime_finding_keeps_adapter_confidence(engine):
    runtime = Finding.create(
        source=FindingSource.ZAP_DAST,
        category=FindingCategory.INJECTION,
        title="SQLi",
        description="SQLi",
        severity=Severity.HIGH,
        confidence=0.5,
        rule_id="40018",
        target_identifier="GET:/users/{id}",
        correlation_key="api:GET:/users/{id}",
    )
    correlated = engine.correlate([], [runtime])
    assert correlated[0].confidence == pytest.approx(0.5)


# ─── Adapter Spectral / Semgrep ──────────────────────────────────────────────


def test_spectral_unauthenticated_operation_is_internet_exposed(tmp_path):
    import json
    from unittest.mock import MagicMock, patch

    from src.infrastructure.adapters.spectral_adapter import SpectralScannerAdapter

    spec = tmp_path / "openapi.yaml"
    spec.write_text(
        "openapi: 3.0.0\ninfo: {title: t, version: '1'}\npaths:\n  /users/{id}:\n    get: {}\n",
        encoding="utf-8",
    )
    issues = [
        {
            "code": "owasp-api2-operation-security",
            "message": "Operation must define security",
            "severity": 0,
            "source": str(spec),
            "range": {"start": {"line": 5}},
            "path": ["paths", "/users/{id}", "get"],
        },
        {
            "code": "owasp:api3:2019-no-numeric-ids",
            "message": "Use uuids instead of numeric ids",
            "severity": 1,
            "source": str(spec),
            "range": {"start": {"line": 5}},
            "path": ["paths", "/users/{id}", "get"],
        },
    ]

    def fake_run(cmd, **kwargs):
        with open(cmd[cmd.index("-o") + 1], "w", encoding="utf-8") as f:
            json.dump(issues, f)
        return MagicMock(returncode=0)

    with patch("subprocess.run", side_effect=fake_run):
        findings = SpectralScannerAdapter().scan(str(spec))

    by_rule = {f.rule_id: f for f in findings}
    unauth = by_rule["owasp-api2-operation-security"]
    assert unauth.category == FindingCategory.AUTHENTICATION
    assert unauth.risk_context is not None
    assert unauth.risk_context.internet_exposed is True
    assert by_rule["owasp:api3:2019-no-numeric-ids"].risk_context is None


def test_semgrep_unauthenticated_route_is_internet_exposed(tmp_path):
    from unittest.mock import patch

    from src.infrastructure.adapters.semgrep_adapter import SemgrepScannerAdapter

    # La rotta protetta precede quella pubblica: l'euristica guarda avanti nel sorgente
    # e non deve leggere il decoratore di autenticazione di un'altra rotta.
    (tmp_path / "app.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n\n"
        "@app.route('/private')\n"
        "@login_required\n"
        "def private():\n"
        "    return 'ok'\n\n"
        "@app.route('/public')\n"
        "def public():\n"
        "    return 'ok'\n",
        encoding="utf-8",
    )
    with patch.object(SemgrepScannerAdapter, "_run_semgrep_discovery", return_value=None):
        findings = SemgrepScannerAdapter().scan(str(tmp_path))

    by_path = {f.api.endpoint: f for f in findings}
    assert by_path["/public"].risk_context is not None
    assert by_path["/public"].risk_context.internet_exposed is True
    assert by_path["/public"].confidence == pytest.approx(0.7)
    assert by_path["/private"].risk_context is None
    assert by_path["/private"].confidence == pytest.approx(0.95)


# ─── Loader YAML ─────────────────────────────────────────────────────────────


def test_loader_falls_back_to_defaults_when_file_is_missing(tmp_path):
    cfg = load_risk_scoring_config(str(tmp_path / "missing.yaml"))
    assert cfg == RiskScoringConfig()
    assert cfg.severity_scores["CRITICAL"] == 10.0
    assert cfg.confidence_by_catalog_match == {
        "exact": 1.0,
        "prefix": 0.9,
        "keyword": 0.8,
        "default": 0.6,
    }


def test_loader_overrides_only_present_keys(tmp_path):
    custom = tmp_path / "risk.yaml"
    custom.write_text(
        "weights: {severity: 0.5}\nseverity_scores: {LOW: 1.0}\ncontext: {default_other: 0}\n",
        encoding="utf-8",
    )
    cfg = load_risk_scoring_config(str(custom))
    assert cfg.weight_severity == 0.5
    assert cfg.weight_confidence == RiskScoringConfig().weight_confidence
    assert cfg.severity_scores["LOW"] == 1.0
    assert cfg.severity_scores["CRITICAL"] == 10.0
    assert cfg.default_context_other == 0.0


def test_project_yaml_matches_code_defaults():
    # Il file versionato deve riprodurre esattamente i default del codice
    assert load_risk_scoring_config() == RiskScoringConfig()


def test_severity_score_reads_shared_config():
    try:
        reset_risk_scoring_config(RiskScoringConfig(severity_scores={"CRITICAL": 3.0}))
        assert Severity.CRITICAL.score == 3.0
        assert Severity.HIGH.score == 0.0
    finally:
        reset_risk_scoring_config()
    assert Severity.CRITICAL.score == 10.0
    assert get_risk_scoring_config().max_risk_score == 10.0
