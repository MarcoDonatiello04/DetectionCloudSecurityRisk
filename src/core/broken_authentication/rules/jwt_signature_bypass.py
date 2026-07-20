"""
Regola statica S01 — JWT Signature Verification Bypass (CWE-347).

Categoria OWASP API2 "Token Validation & Signatures". Rileva la decodifica manuale
del payload di un JWT senza verifica della firma: pattern tipico dei fallback che,
quando la validazione crittografica fallisce o l'IdP e irraggiungibile, ricadono
sulla lettura del solo payload Base64. Un attaccante puo forgiare un token con
qualunque claim (es. preferred_username: admin) e ottenere l'identita desiderata.

Segnale rilevato dentro una singola funzione:
  - split del token sui punti (`token.split(".")`), estrazione delle parti JWT;
  - decodifica Base64 di una parte (`base64.urlsafe_b64decode` / `b64decode`);
  - parsing JSON del risultato (`json.loads`).

La presenza dei tre elementi identifica una lettura del payload JWT che non passa
mai da una libreria di verifica firma. E un'analisi statica: non richiede una
sessione autenticata, quindi copre il caso (come `repo_target`) in cui l'auth e
delegata a un IdP esterno e i test dinamici non sono eseguibili.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

RULE_ID = "S01"
CATEGORY = "token_signature_bypass"
CWE_ID = "CWE-347"


@dataclass
class JwtSignatureBypassFinding:
    rule_id: str
    category: str
    cwe_id: str
    file_path: str
    line_number: int
    function_name: str
    evidence: str


def _is_dotted_split(node: ast.AST) -> bool:
    """True per una chiamata `<expr>.split(".")`."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "split"
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == "."
    )


def _is_base64_decode(node: ast.AST) -> bool:
    """True per una chiamata a un decoder Base64 (urlsafe_b64decode / b64decode)."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    name = (
        func.attr
        if isinstance(func, ast.Attribute)
        else (func.id if isinstance(func, ast.Name) else "")
    )
    return name in {"urlsafe_b64decode", "b64decode", "standard_b64decode"}


def _is_json_loads(node: ast.AST) -> bool:
    """True per una chiamata `json.loads(...)` o `loads(...)`."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr == "loads"
    return isinstance(func, ast.Name) and func.id == "loads"


def _analyze_function(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True se la funzione decodifica manualmente un payload JWT senza verifica firma."""
    has_split = has_b64 = has_json = False
    for node in ast.walk(func):
        if _is_dotted_split(node):
            has_split = True
        elif _is_base64_decode(node):
            has_b64 = True
        elif _is_json_loads(node):
            has_json = True
    return has_split and has_b64 and has_json


def analyze(source_code: str, file_path: str) -> list[JwtSignatureBypassFinding]:
    """Analizza il sorgente Python e ritorna i finding S01."""
    findings: list[JwtSignatureBypassFinding] = []
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _analyze_function(node):
            findings.append(
                JwtSignatureBypassFinding(
                    rule_id=RULE_ID,
                    category=CATEGORY,
                    cwe_id=CWE_ID,
                    file_path=file_path,
                    line_number=node.lineno,
                    function_name=node.name,
                    evidence=(
                        f"La funzione '{node.name}' decodifica manualmente il payload JWT "
                        "(split '.', Base64, json.loads) senza verificare la firma."
                    ),
                )
            )
    return findings
