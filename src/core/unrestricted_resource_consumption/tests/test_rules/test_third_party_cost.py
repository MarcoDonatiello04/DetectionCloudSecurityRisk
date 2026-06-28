"""Smoke test and custom tests — third_party_cost rule module."""

from pathlib import Path
from tree_sitter import Language, Parser
import tree_sitter_python as tspython
from src.core.unrestricted_resource_consumption.rules.third_party_cost import ThirdPartyCostRule

def test_rule_has_analyze_python():
    assert callable(getattr(ThirdPartyCostRule, "analyze_python", None))

def test_rule_has_analyze_javascript():
    assert callable(getattr(ThirdPartyCostRule, "analyze_javascript", None))

def test_rule_ids_defined():
    assert ThirdPartyCostRule.rule_id.startswith("RC-")
    assert ThirdPartyCostRule.cwe_id.startswith("CWE-")
    assert ThirdPartyCostRule.severity in ("HIGH", "MEDIUM", "LOW")

def analyze_rule(content: str, file_path: Path):
    lang = Language(tspython.language())
    parser = Parser(lang)
    tree = parser.parse(content.encode())
    return ThirdPartyCostRule.analyze_python(tree.root_node, str(file_path))

def test_rc006_requires_sdk_import():
    """File senza import SDK non deve produrre RC-006, anche se il nome è sospetto"""
    content = '''
# File: otpForm.py — nessun import SDK
def send_otp_form(phone):
    session['pending_phone'] = phone
    return redirect('/verify')
'''
    findings = analyze_rule(content, file_path=Path("otpForm.py"))
    assert len(findings) == 0, "FP: RC-006 senza import SDK"


def test_rc006_tp_with_twilio_import():
    """Import Twilio + call senza rate limit → RC-006 con evidence corretta"""
    content = '''
from twilio.rest import Client

client = Client(SID, TOKEN)

@app.post("/sms")
def send_sms():
    client.messages.create(to=request.json['phone'], body="OTP: 123456")
    return "ok"
'''
    findings = analyze_rule(content, file_path=Path("sms.py"))
    assert len(findings) == 1
    assert "messages.create" in findings[0].evidence


def test_rc006_tn_with_rate_limit_decorator():
    """Import Twilio + call CON rate limit → nessun finding"""
    content = '''
from twilio.rest import Client

client = Client(SID, TOKEN)

@app.post("/sms")
@rate_limit("3/hour")
def send_sms():
    client.messages.create(to=request.json['phone'], body="OTP: 123456")
    return "ok"
'''
    findings = analyze_rule(content, file_path=Path("sms.py"))
    assert len(findings) == 0


def test_rc006_set_cookie_is_not_finding():
    """set_cookie non è una chiamata a provider a pagamento"""
    content = '''
@app.after_request
def after_index(response):
    response.set_cookie(SESSION_COOKIE, generate_session())
    return response
'''
    findings = analyze_rule(content, file_path=Path("session_service.py"))
    assert len(findings) == 0
