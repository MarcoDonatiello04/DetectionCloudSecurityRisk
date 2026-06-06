from cloud_security_analyzer.models.finding_model import FindingModel
from cloud_security_analyzer.controllers.findings_controller import FindingsController
from cloud_security_analyzer.services.state_service import StateService
from src.domain.entities import Finding, FindingSource, FindingCategory, Severity

f = Finding.create(
    source=FindingSource.CHECKOV,
    category=FindingCategory.MISCONFIGURATION,
    title="Test",
    description="Test",
    severity=Severity.HIGH,
    confidence=1.0,
    rule_id="CKV_1",
    target_identifier="test"
)

fm = FindingModel(f)

state = StateService()
state._findings = [fm]

ctrl = FindingsController(state, {"source": ["CHECKOV"]})
res = ctrl.get_filtered_findings()
print(f"Findings count: {len(res)}")
