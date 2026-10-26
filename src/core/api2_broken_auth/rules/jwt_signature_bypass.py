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

La presenza dei tre elementi identifica una lettura manuale del payload JWT. La
funzione non viene segnalata se la lettura manuale e protetta da una verifica
della firma, cioe se una chiamata `jwt.decode` / `jws.verify`:
  - non disattiva la verifica (`verify_signature: False`, `verify=False`,
    algoritmo `none`);
  - precede la decodifica manuale;
  - non sta in un `try` il cui `except` inghiotte l'errore e prosegue, perche in
    quel caso la decodifica manuale puo eseguire anche con firma non valida.
Una decodifica manuale dentro un `except` e sempre un fallback non verificato e
viene segnalata comunque. E un'analisi statica: non richiede una
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


def _disables_verification(call: ast.Call) -> bool:
    """True se la chiamata disattiva esplicitamente la verifica della firma."""
    for kw in call.keywords:
        value = kw.value
        if kw.arg == "verify" and isinstance(value, ast.Constant) and value.value is False:
            return True
        if kw.arg == "options" and isinstance(value, ast.Dict):
            for key, val in zip(value.keys, value.values, strict=True):
                if (
                    isinstance(key, ast.Constant)
                    and key.value == "verify_signature"
                    and isinstance(val, ast.Constant)
                    and val.value is False
                ):
                    return True
        if kw.arg == "algorithms" and isinstance(value, (ast.List, ast.Tuple)):
            if any(
                isinstance(elt, ast.Constant)
                and isinstance(elt.value, str)
                and elt.value.lower() == "none"
                for elt in value.elts
            ):
                return True
    return False


def _is_verified_jwt_decode(node: ast.AST) -> bool:
    """True per `jwt.decode(...)` / `jws.verify(...)` che non disattiva la verifica firma."""
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"decode", "verify"}
    ):
        return False
    receiver = node.func.value
    name = (
        receiver.id
        if isinstance(receiver, ast.Name)
        else (receiver.attr if isinstance(receiver, ast.Attribute) else "")
    )
    return name.lower() in {"jwt", "jws"} and not _disables_verification(node)


def _node_ids(statements: list[ast.stmt]) -> set[int]:
    return {id(n) for stmt in statements for n in ast.walk(stmt)}


def _handler_terminates(handler: ast.ExceptHandler) -> bool:
    """True se l'except interrompe il flusso (return/raise) invece di proseguire."""
    return bool(handler.body) and isinstance(handler.body[-1], (ast.Return, ast.Raise))


def _walk_own_scope(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.AST]:
    """Nodi del corpo della funzione, escluse funzioni e classi annidate.

    Le definizioni annidate vengono analizzate a parte da `analyze`: attraversarle qui
    attribuirebbe il loro pattern anche alla funzione che le contiene.
    """
    nodes: list[ast.AST] = []
    stack: list[ast.AST] = list(reversed(func.body))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        nodes.append(node)
        stack.extend(reversed(list(ast.iter_child_nodes(node))))
    return nodes


def _analyze_function(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True se la funzione decodifica manualmente un payload JWT senza verifica firma."""
    own_nodes = _walk_own_scope(func)
    splits, b64s, jsons = [], [], []
    for node in own_nodes:
        if _is_dotted_split(node):
            splits.append(node)
        elif _is_base64_decode(node):
            b64s.append(node)
        elif _is_json_loads(node):
            jsons.append(node)
    if not (splits and b64s and jsons):
        return False
    manual = splits + b64s + jsons

    in_handlers: set[int] = set()
    swallowed: set[int] = set()
    for node in own_nodes:
        if isinstance(node, ast.Try):
            for handler in node.handlers:
                in_handlers |= _node_ids(handler.body)
            if any(not _handler_terminates(h) for h in node.handlers):
                swallowed |= _node_ids(node.body)

    # Decodifica manuale nel ramo except: fallback eseguito proprio quando la verifica fallisce.
    if any(id(n) in in_handlers for n in manual):
        return True

    first_manual = min(n.lineno for n in manual)
    guarded = any(
        _is_verified_jwt_decode(node) and id(node) not in swallowed and node.lineno < first_manual
        for node in own_nodes
    )
    return not guarded


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
