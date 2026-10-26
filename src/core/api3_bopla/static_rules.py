"""
Static BOPLA findings and their correlation with the dynamic phase (OWASP API3:2023).

The static phases already deduce which properties look protected; this module turns what
they see into findings marked "to be verified", so the module reports something even when
the dynamic phase cannot run (no identity matrix, as in the integrated platform):

  BOPLA-S01  mass assignment: request body bound to an entity without an allowlist
             (see mass_assignment.py)
  BOPLA-S02  excessive exposure: an entity with protected properties serialized whole in a
             response, outside any authorization context
  BOPLA-S03  contract inconsistency: a readOnly property accepted by a request schema, or a
             writeOnly property returned by a response schema
  BOPLA-S04  undocumented property: a protected property observed in traffic but absent
             from the contract

When the dynamic phase runs, correlate_with_dynamic() confirms a static finding if a test of
the same direction (write: T02–T05, T07; read: T01, T06) proves one of its properties
vulnerable, and marks it "not_confirmed" if those properties were tested and held.

Entry points: run_static_rules(...), correlate_with_dynamic(...)
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from loguru import logger

from src.core.api3_bopla import auth_idioms, contract
from src.core.api3_bopla.discovery import PropertyDiscoveryEngine, collect_source_files
from src.core.api3_bopla.mass_assignment import (
    _python_endpoint,
    _text,
    _walk_in_order,
    canonical_entity,
    resolve_entity,
    scan_mass_assignment,
)
from src.core.api3_bopla.models import (
    DynamicPropertyFinding,
    PropertyEvidence,
    StaticPropertyFinding,
)
from src.core.api3_bopla.property_inference import PropertyAuthorizationInferenceEngine

WRITE_TESTS = {"T02", "T03", "T04", "T05", "T07"}
READ_TESTS = {"T01", "T06"}
DIRECTION_TESTS = {
    "mass_assignment": WRITE_TESTS,
    "readonly_writable": WRITE_TESTS,
    "excessive_exposure": READ_TESTS,
    "writeonly_readable": READ_TESTS,
    "undocumented_property": WRITE_TESTS | READ_TESTS,
}

# Calls that serialize a whole object: every attribute, protected ones included
PY_WHOLE_SERIALIZERS = {"vars", "asdict", "model_to_dict", "jsonable_encoder"}
PY_WHOLE_METHODS = {"to_dict", "to_json", "dict", "model_dump", "as_dict", "serialize"}
# Guards are judged exactly as in the inference phase
IDENTITY_CHECK = PropertyAuthorizationInferenceEngine.IDENTITY_CHECK
EXIT_CALLS = PropertyAuthorizationInferenceEngine.EXIT_CALLS

CONFIDENCE_EXPOSURE_PY = 0.7
CONFIDENCE_EXPOSURE_JS = 0.5
CONFIDENCE_CONTRACT = 0.6
CONFIDENCE_UNDOCUMENTED = 0.5


def _protected_by_entity(evidences: list[PropertyEvidence]) -> dict[str, list[str]]:
    protected: dict[str, list[str]] = {}
    for ev in evidences:
        # S02 is about reading: a contract readOnly (e.g. id) is legitimately returned
        if PropertyAuthorizationInferenceEngine.is_protected_property(ev, direction="read"):
            protected.setdefault(ev.object_name.lower(), []).append(ev.property)
    return {k: sorted(v) for k, v in protected.items()}


# ---------------------------------------------------------------------------
# BOPLA-S02 — excessive exposure (Python ast, JS regex)
# ---------------------------------------------------------------------------


def _is_auth(expr: ast.expr) -> bool:
    return PropertyAuthorizationInferenceEngine._is_auth_expression(_text(expr))


def _protects_properties(test: ast.expr) -> bool:
    """An authorization condition that is not just an ownership check."""
    return _is_auth(test) and not IDENTITY_CHECK.search(_text(test))


def _exits(body: list[ast.stmt]) -> bool:
    """The block leaves the function: return, raise, or a call such as Flask's abort(403)."""
    if not body:
        return False
    last = body[-1]
    if isinstance(last, (ast.Return, ast.Raise, ast.Continue)):
        return True
    return (
        isinstance(last, ast.Expr)
        and isinstance(last.value, ast.Call)
        and _text(last.value.func).split(".")[-1] in EXIT_CALLS
    )


def _whole_serialization(expr: ast.expr) -> ast.expr | None:
    """The object serialized whole by expr (vars(user), user.to_dict(), user.__dict__...)."""
    for node in ast.walk(expr):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in PY_WHOLE_SERIALIZERS and node.args:
                return node.args[0]
            if (
                isinstance(func, ast.Attribute)
                and func.attr in PY_WHOLE_METHODS
                and not node.args
                and isinstance(func.value, ast.Name)
            ):
                return func.value
        if isinstance(node, ast.Attribute) and node.attr == "__dict__":
            return node.value
    return None


def _python_exposures(path: Path, protected: dict[str, list[str]]) -> list[dict]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
    except SyntaxError:
        return []
    results: list[dict] = []

    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if auth_idioms.is_reserved_python_function(func, tree):
            continue  # the whole function is reserved to a role
        assigned_from: dict[str, ast.expr] = {}
        for node in _walk_in_order(func):
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
            ):
                assigned_from[node.targets[0].id] = node.value

        def visit(stmts: list[ast.stmt], guarded: bool):
            for stmt in stmts:
                if guarded:
                    return
                if isinstance(stmt, ast.If):
                    if PropertyAuthorizationInferenceEngine.is_denying_guard(
                        _text(stmt.test),
                        "\n".join(_text(x) for x in stmt.body),
                        _exits(stmt.body),
                    ):
                        guarded = True  # `if not is_admin: abort(403)` protects what follows
                        continue
                    yield from visit(stmt.body, _protects_properties(stmt.test))
                    yield from visit(stmt.orelse, False)
                    continue
                if isinstance(stmt, (ast.For, ast.While, ast.With, ast.Try)):
                    for field in ("body", "orelse", "finalbody"):
                        yield from visit(getattr(stmt, field, []) or [], False)
                    for handler in getattr(stmt, "handlers", []):
                        yield from visit(handler.body, False)
                    continue
                if isinstance(stmt, ast.Return) and stmt.value is not None:
                    target = _whole_serialization(stmt.value)
                    if target is not None:
                        yield stmt, target

        for stmt, target in visit(func.body, False):
            entity = canonical_entity(resolve_entity(target, assigned_from))
            at_risk = protected.get((entity or "").lower())
            if not at_risk:
                continue
            results.append(
                {
                    "line": stmt.lineno,
                    "entity": entity,
                    "sink": _text(stmt),
                    "properties": at_risk,
                    "endpoint": _python_endpoint(func),
                    "confidence": CONFIDENCE_EXPOSURE_PY,
                }
            )
    return results


_JS_SEND = re.compile(r"\bres\.(?:json|send)\(\s*([\w$]+)\s*\)")


def _js_exposures(path: Path, protected: dict[str, list[str]]) -> list[dict]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    origins: dict[str, str] = {}
    results: list[dict] = []
    for number, line in enumerate(lines, 1):
        origin = re.search(
            r"(?:const|let|var)\s+([\w$]+)\s*=\s*(?:await\s+)?([A-Z][\w$]*)\."
            r"(?:findById|findOne|findByPk|findUnique|findFirst|get)\(",
            line,
        )
        if origin:
            origins[origin.group(1)] = origin.group(2)
        send = _JS_SEND.search(line)
        if send and send.group(1) in origins:
            entity = canonical_entity(origins[send.group(1)])
            at_risk = protected.get((entity or "").lower())
            if at_risk:
                results.append(
                    {
                        "line": number,
                        "entity": entity,
                        "sink": line.strip(),
                        "properties": at_risk,
                        "endpoint": None,
                        "confidence": CONFIDENCE_EXPOSURE_JS,
                    }
                )
    return results


def scan_excessive_exposure(
    repo_path: str, evidences: list[PropertyEvidence]
) -> list[StaticPropertyFinding]:
    protected = _protected_by_entity(evidences)
    if not protected:
        return []
    scanners = {
        "python": _python_exposures,
        "javascript": _js_exposures,
        "typescript": _js_exposures,
    }
    findings: list[StaticPropertyFinding] = []
    root = Path(repo_path)
    for file_path, language in collect_source_files(repo_path):
        scanner = scanners.get(language)
        if scanner is None:
            continue
        try:
            items = scanner(file_path, protected)
        except Exception as exc:
            logger.warning(f"BOPLA-S02: analisi fallita su {file_path}: {exc}")
            continue
        for item in items:
            findings.append(
                StaticPropertyFinding(
                    rule_id="BOPLA-S02",
                    kind="excessive_exposure",
                    file_path=str(file_path.relative_to(root)),
                    line=item["line"],
                    language=language,
                    endpoint=item["endpoint"],
                    entity=item["entity"],
                    source=f"oggetto {item['entity']} serializzato per intero",
                    sink=item["sink"],
                    properties_at_risk=item["properties"],
                    severity="HIGH",
                    confidence=item["confidence"],
                    evidence=[
                        f"La risposta contiene l'intero oggetto {item['entity']}, senza scegliere "
                        "i campi e fuori da un controllo sui ruoli.",
                        f"Proprietà inferite come protette esposte in lettura: "
                        f"{', '.join(item['properties'])}.",
                    ],
                )
            )
    return findings


# ---------------------------------------------------------------------------
# BOPLA-S03 — readOnly / writeOnly contradicted by the contract itself
# ---------------------------------------------------------------------------


def scan_contract(spec: dict | None) -> list[StaticPropertyFinding]:
    """
    The contract reading is shared with the inventory (contract.py): `$ref`, allOf/oneOf/anyOf,
    arrays and nested properties (dotted) are resolved, and every body is attributed to the
    schema that describes it, else to the object the operation is about.
    """
    if not spec:
        return []
    # (object, property) -> where the flag is declared
    read_only: dict[tuple[str, str], str] = {}
    write_only: dict[tuple[str, str], str] = {}
    requests: list[tuple[str, str, str]] = []  # (object, property, operation)
    responses: list[tuple[str, str, str]] = []

    for obj, props in contract.component_properties(spec).items():
        for name, prop in props.items():
            if prop.get("readOnly"):
                read_only.setdefault((obj, name), f"schema {obj}")
            if prop.get("writeOnly"):
                write_only.setdefault((obj, name), f"schema {obj}")

    for operation in contract.iter_operations(spec):
        label = f"{operation.method} {operation.path}"
        for obj, props in operation.request_objects():
            for name, prop in props.items():
                if prop.get("readOnly"):
                    read_only[(obj, name)] = label
                else:
                    requests.append((obj, name, label))
                if prop.get("writeOnly"):
                    write_only[(obj, name)] = label
        for obj, props in operation.response_objects():
            for name, prop in props.items():
                if prop.get("writeOnly"):
                    write_only[(obj, name)] = label
                else:
                    responses.append((obj, name, label))
                if prop.get("readOnly"):
                    read_only[(obj, name)] = label

    findings: list[StaticPropertyFinding] = []
    seen: set[tuple[str, str, str]] = set()
    for kind, declared, uses, verb in (
        ("readonly_writable", read_only, requests, "accettata in scrittura"),
        ("writeonly_readable", write_only, responses, "restituita in lettura"),
    ):
        for obj, name, label in uses:
            if (obj, name) not in declared or (kind, obj, name) in seen:
                continue
            seen.add((kind, obj, name))
            flag = "readOnly" if kind == "readonly_writable" else "writeOnly"
            findings.append(
                StaticPropertyFinding(
                    rule_id="BOPLA-S03",
                    kind=kind,
                    file_path="openapi_spec",
                    line=0,
                    language="openapi",
                    endpoint=label,
                    entity=obj,
                    source=f"{flag} in {declared[(obj, name)]}",
                    sink=f"{name} {verb} da {label}",
                    properties_at_risk=[name],
                    severity="MEDIUM",
                    confidence=CONFIDENCE_CONTRACT,
                    evidence=[
                        f"Il contratto dichiara {obj}.{name} {flag} in {declared[(obj, name)]}, "
                        f"ma la stessa proprietà è {verb} da {label}."
                    ],
                )
            )
    return findings


# ---------------------------------------------------------------------------
# BOPLA-S04 — protected property travelling outside the contract
# ---------------------------------------------------------------------------


def scan_undocumented(evidences: list[PropertyEvidence]) -> list[StaticPropertyFinding]:
    findings = []
    for ev in evidences:
        if not ev.documentation_issues:
            continue
        if not PropertyAuthorizationInferenceEngine.is_protected_property(ev):
            continue
        findings.append(
            StaticPropertyFinding(
                rule_id="BOPLA-S04",
                kind="undocumented_property",
                file_path="runtime_traffic",
                line=0,
                language="traffic",
                endpoint=", ".join(ev.write_endpoints + ev.read_endpoints) or None,
                entity=ev.object_name,
                source="traffico osservato",
                sink=f"{ev.object_name}.{ev.property} assente dal contratto",
                properties_at_risk=[ev.property],
                severity="LOW",
                confidence=CONFIDENCE_UNDOCUMENTED,
                evidence=[
                    f"{ev.object_name}.{ev.property} è inferita come protetta e compare nel "
                    "traffico, ma il contratto non la dichiara: chi legge il contratto non sa "
                    "che viaggia, né con quali vincoli."
                ],
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_static_rules(
    repo_path: str,
    evidences: list[PropertyEvidence],
    openapi_spec: dict | None = None,
) -> list[StaticPropertyFinding]:
    """All static BOPLA rules, each isolated so one failure does not hide the others."""
    findings: list[StaticPropertyFinding] = []
    for name, rule in (
        ("BOPLA-S01", lambda: scan_mass_assignment(repo_path, evidences)),
        ("BOPLA-S02", lambda: scan_excessive_exposure(repo_path, evidences)),
        ("BOPLA-S03", lambda: scan_contract(openapi_spec)),
        ("BOPLA-S04", lambda: scan_undocumented(evidences)),
    ):
        try:
            findings.extend(rule())
        except Exception as exc:
            logger.error(f"{name}: regola non eseguita ({exc})")
    return findings


def correlate_with_dynamic(
    static_findings: list[StaticPropertyFinding],
    dynamic_findings: list[DynamicPropertyFinding],
) -> None:
    """
    Updates static findings in place with the outcome of the dynamic phase: "confirmed"
    (verified, confidence 1, severity CRITICAL) when a test of the same direction proves one
    of their properties vulnerable on the same entity, "not_confirmed" when the properties
    were tested and held.
    """
    for finding in static_findings:
        if not finding.properties_at_risk:
            continue  # nothing the dynamic phase could have tested
        tests = DIRECTION_TESTS.get(finding.kind, set())
        entity = (finding.entity or "").lower()
        relevant = [
            d
            for d in dynamic_findings
            if d.test_id in tests
            and d.property_name in finding.properties_at_risk
            and (
                not entity
                or PropertyDiscoveryEngine.get_object_name_from_path(d.endpoint).lower() == entity
            )
        ]
        confirmed = sorted({f"{d.test_id}:{d.property_name}" for d in relevant if d.verified})
        if confirmed:
            finding.status = "confirmed"
            finding.verified = True
            finding.confirmed_by = confirmed
            finding.confidence = 1.0
            finding.severity = "CRITICAL"
        elif relevant:
            finding.status = "not_confirmed"
