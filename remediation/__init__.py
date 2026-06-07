"""
Modulo di Remediation Intelligence.
Fornisce strumenti di mitigazione automatica offline, KB locali ed integrazione con LLM locali (Ollama).
"""

from remediation.remediation_engine import RemediationEngine
from remediation.models.remediation_model import RemediationModel
from remediation.llm_provider import LlmProvider
