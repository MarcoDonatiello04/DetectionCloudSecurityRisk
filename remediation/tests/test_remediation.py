import os
import json
import pytest
from unittest.mock import MagicMock, patch

from remediation.remediation_engine import RemediationEngine
from remediation.models.remediation_model import RemediationModel
from src.domain.entities import Finding, FindingSource, FindingCategory, Severity

@pytest.fixture
def mock_kb_dir(tmp_path):
    checkov_data = {
        "CKV_AWS_20": {
            "title": "Checkov Rule 20 Title",
            "description": "Checkov Rule 20 Description",
            "impact": "Checkov Rule 20 Impact",
            "remediation_steps": ["Step 1", "Step 2"],
            "example": "aws_s3_bucket_policy example"
        }
    }
    owasp_data = {
        "AUTHORIZATION": {
            "title": "OWASP API Authz Title",
            "description": "OWASP API Authz Description",
            "impact": "OWASP API Authz Impact",
            "remediation_steps": ["Step A", "Step B"],
            "example": "secure authz code"
        }
    }
    cloud_data = {
        "SEC_GEN_001": {
            "title": "General Cloud Title",
            "description": "General Cloud Description",
            "impact": "General Cloud Impact",
            "remediation_steps": ["Fix IAM"],
            "example": "secure iam policy"
        }
    }
    
    # Save files
    with open(tmp_path / "checkov_remediation.json", "w", encoding="utf-8") as f:
        json.dump(checkov_data, f)
    with open(tmp_path / "owasp_api_remediation.json", "w", encoding="utf-8") as f:
        json.dump(owasp_data, f)
    with open(tmp_path / "cloud_remediation.json", "w", encoding="utf-8") as f:
        json.dump(cloud_data, f)
    with open(tmp_path / "local_cache.json", "w", encoding="utf-8") as f:
        json.dump({}, f)
        
    return tmp_path

def test_kb_priority_checkov(mock_kb_dir):
    engine = RemediationEngine(kb_directory=str(mock_kb_dir))
    
    finding = Finding.create(
        source=FindingSource.CHECKOV,
        category=FindingCategory.MISCONFIGURATION,
        title="Insecure S3 Policy",
        description="Public bucket access",
        severity=Severity.HIGH,
        confidence=0.9,
        rule_id="CKV_AWS_20",
        target_identifier="aws_s3_bucket.bucket"
    )
    
    res = engine.get_remediation(finding)
    
    assert res.title == "Checkov Rule 20 Title"
    assert res.impact == "Checkov Rule 20 Impact"
    assert res.source == "knowledge_base"
    assert res.remediation_steps == ["Step 1", "Step 2"]
    assert res.example == "aws_s3_bucket_policy example"
    assert res.confidence == 1.0

def test_kb_priority_owasp(mock_kb_dir):
    engine = RemediationEngine(kb_directory=str(mock_kb_dir))
    
    finding = Finding.create(
        source=FindingSource.RUNTIME_VALIDATOR,
        category=FindingCategory.AUTHORIZATION,
        title="BOLA Vulnerability",
        description="Authz checks missing",
        severity=Severity.HIGH,
        confidence=0.8,
        rule_id="N/A",
        target_identifier="/users/{id}"
    )
    
    res = engine.get_remediation(finding)
    
    assert res.title == "OWASP API Authz Title"
    assert res.source == "knowledge_base"
    assert res.remediation_steps == ["Step A", "Step B"]
    assert res.example == "secure authz code"

def test_kb_priority_cloud(mock_kb_dir):
    engine = RemediationEngine(kb_directory=str(mock_kb_dir))
    
    finding = Finding.create(
        source=FindingSource.SEMGREP,
        category=FindingCategory.MISCONFIGURATION,
        title="Custom Cloud Vulnerability",
        description="IAM policies wide open",
        severity=Severity.MEDIUM,
        confidence=0.7,
        rule_id="SEC_GEN_001",
        target_identifier="IAM Role"
    )
    
    res = engine.get_remediation(finding)
    
    assert res.title == "General Cloud Title"
    assert res.source == "knowledge_base"
    assert res.example == "secure iam policy"

def test_llm_fallback_and_caching(mock_kb_dir):
    engine = RemediationEngine(kb_directory=str(mock_kb_dir))
    
    # Mock LLM provider response
    mock_llm_response = {
        "title": "LLM Generated Title",
        "description": "LLM Generated Desc",
        "impact": "LLM Generated Impact",
        "remediation_steps": ["Step LLM 1"],
        "example": "secure code example from llm"
    }
    
    finding = Finding.create(
        source=FindingSource.SEMGREP,
        category=FindingCategory.RATE_LIMITING,
        title="No Rate Limiting",
        description="Endpoint lacks rate limit controls",
        severity=Severity.MEDIUM,
        confidence=0.6,
        rule_id="NO_RATE_LIMIT",
        target_identifier="/login"
    )
    
    with patch.object(engine.llm_provider, 'generate_remediation', return_value=mock_llm_response) as mock_gen:
        # First call: cache miss, LLM queried
        res1 = engine.get_remediation(finding)
        
        mock_gen.assert_called_once_with(
            finding_id="NO_RATE_LIMIT",
            title="No Rate Limiting",
            category="RATE_LIMITING",
            source="SEMGREP",
            description="Endpoint lacks rate limit controls"
        )
        assert res1.title == "LLM Generated Title"
        assert res1.source == "llm"
        assert res1.confidence == 0.8
        
        # Second call: cache hit, no LLM call
        mock_gen.reset_mock()
        res2 = engine.get_remediation(finding)
        
        mock_gen.assert_not_called()
        assert res2.title == "LLM Generated Title"
        assert res2.source == "cache"
        assert res2.confidence == 0.9

def test_emergency_fallback_when_offline(mock_kb_dir):
    engine = RemediationEngine(kb_directory=str(mock_kb_dir))
    
    finding = Finding.create(
        source=FindingSource.SEMGREP,
        category=FindingCategory.RATE_LIMITING,
        title="No Rate Limiting",
        description="Endpoint lacks rate limit controls",
        severity=Severity.MEDIUM,
        confidence=0.6,
        rule_id="NO_RATE_LIMIT_OFFLINE",
        target_identifier="/login",
        remediation="Ensure rate limits are enforced."
    )
    
    with patch.object(engine.llm_provider, 'generate_remediation', return_value=None):
        res = engine.get_remediation(finding)
        
        assert res.title == "No Rate Limiting"
        assert res.description == "Endpoint lacks rate limit controls"
        assert res.impact == "L'impatto esatto di questa vulnerabilità non è stato analizzato."
        assert res.remediation_steps == ["Ensure rate limits are enforced."]
        assert res.source == "knowledge_base_fallback"
        assert res.confidence == 0.5

def test_get_remediation_source_fast(mock_kb_dir):
    engine = RemediationEngine(kb_directory=str(mock_kb_dir))
    
    finding_kb = Finding.create(
        source=FindingSource.CHECKOV,
        category=FindingCategory.MISCONFIGURATION,
        title="Insecure Bucket",
        description="Bucket public",
        severity=Severity.HIGH,
        confidence=0.9,
        rule_id="CKV_AWS_20",
        target_identifier="aws_s3_bucket.bucket"
    )
    
    finding_llm = Finding.create(
        source=FindingSource.SEMGREP,
        category=FindingCategory.RATE_LIMITING,
        title="No Rate Limiting",
        description="Endpoint lacks rate limit controls",
        severity=Severity.MEDIUM,
        confidence=0.6,
        rule_id="NO_RATE_LIMIT_FAST",
        target_identifier="/login"
    )
    
    # Check KB match
    assert engine.get_remediation_source_fast(finding_kb) == "knowledge_base"
    
    # Check LLM / Offline fallback match
    with patch.object(engine.llm_provider, 'get_available_model', return_value="llama3.1:8b"):
        assert engine.get_remediation_source_fast(finding_llm) == "llm"
        
    with patch.object(engine.llm_provider, 'get_available_model', return_value=None):
        assert engine.get_remediation_source_fast(finding_llm) == "fallback"

