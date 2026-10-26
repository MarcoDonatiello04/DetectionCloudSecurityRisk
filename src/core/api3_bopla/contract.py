"""
Reading of the OpenAPI contract for BOPLA (limits B.6, B.9, B.11 of the API3 report).

The contract is the application's own statement of intent, so the module may use what it
declares without being told which properties are protected:

- every operation is associated with the SCHEMA that describes it (`$ref` resolved, name
  cleaned with the canonical object name), not only with the object guessed from the path:
  `/staff/{id}` described by `#/components/schemas/Employee` reads and writes `Employee`,
  and `/me` or `/profile` read the object of their response schema;
- `allOf`, `oneOf`, `anyOf` and arrays (`items`) are followed;
- nested properties are recorded with a dotted path (`address.city`, `manager.salary`),
  first-level keys unchanged;
- `readOnly` / `writeOnly` are kept per property, to be used as authorization evidence
  (a readOnly property must be refused in writing, a writeOnly one must never be returned).

Entry points: iter_operations(spec), schema_properties(schema, spec),
component_properties(spec), contract_flags(spec), operation_for(spec, method, path).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

HTTP_METHODS = ("get", "put", "post", "patch", "delete", "head", "options", "trace")
WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
# Nesting levels followed below the first one (`a.b.c.d`): enough for real contracts, and
# a bound against recursive schemas reached through inline definitions.
MAX_DEPTH = 3

Props = dict[str, dict]  # dotted property name -> {"readOnly": bool, "writeOnly": bool}


# ---------------------------------------------------------------------------
# Schema resolution
# ---------------------------------------------------------------------------


def ref_name(ref: str) -> str:
    return ref.rsplit("/", 1)[-1]


def resolve(schema: Any, spec: dict) -> tuple[dict, str | None]:
    """Follows a chain of local `$ref`; returns the node and the name of the last reference."""
    name = None
    seen: set[str] = set()
    while isinstance(schema, dict) and isinstance(schema.get("$ref"), str):
        ref = schema["$ref"]
        if not ref.startswith("#/") or ref in seen:
            return {}, name
        seen.add(ref)
        name = ref_name(ref)
        node: Any = spec
        for part in ref[2:].split("/"):
            node = node.get(part, {}) if isinstance(node, dict) else {}
        schema = node
    return (schema if isinstance(schema, dict) else {}), name


def _unwrap_array(node: dict, name: str | None, spec: dict) -> tuple[dict, str | None]:
    """The schema of the elements of an array (the innermost named one wins)."""
    guard = 0
    while (node.get("type") == "array" or "items" in node) and guard < 5:
        inner, inner_name = resolve(node.get("items"), spec)
        node, name = inner, inner_name or name
        guard += 1
    return node, name


def _flags(raw: dict, resolved: dict) -> dict:
    return {
        "readOnly": bool(raw.get("readOnly") or resolved.get("readOnly")),
        "writeOnly": bool(raw.get("writeOnly") or resolved.get("writeOnly")),
    }


def schema_properties(
    schema: Any,
    spec: dict,
    prefix: str = "",
    depth: int = 0,
    seen: frozenset[str] = frozenset(),
) -> Props:
    """
    Properties described by a schema, with their readOnly/writeOnly flags. `allOf`, `oneOf`
    and `anyOf` are merged, arrays are unwrapped and nested objects are recorded with a
    dotted path. A schema already being expanded (recursive `$ref`) is not expanded again.
    """
    node, name = resolve(schema, spec)
    node, name = _unwrap_array(node, name, spec)
    if name:
        if name in seen:
            return {}
        seen = seen | {name}
    props: Props = {}
    for key in ("allOf", "oneOf", "anyOf"):
        for part in node.get(key) or []:
            props.update(schema_properties(part, spec, prefix, depth, seen))
    for prop_name, raw in (node.get("properties") or {}).items():
        raw = raw if isinstance(raw, dict) else {}
        resolved, _ = resolve(raw, spec)
        dotted = f"{prefix}{prop_name}"
        props[dotted] = _flags(raw, resolved)
        if depth < MAX_DEPTH:
            props.update(schema_properties(raw, spec, f"{dotted}.", depth + 1, seen))
    return props


def schema_objects(schema: Any, spec: dict) -> list[tuple[str | None, Props]]:
    """
    The objects a request or response schema describes: (raw schema name or None when the
    schema is inline, properties). `oneOf`/`anyOf` of distinct schemas are distinct objects;
    `allOf` describes one object, named after its first referenced part.
    """
    node, name = resolve(schema, spec)
    node, name = _unwrap_array(node, name, spec)
    if not node:
        return []
    alternatives = (node.get("oneOf") or []) + (node.get("anyOf") or [])
    if alternatives and not node.get("properties") and not node.get("allOf"):
        objects: list[tuple[str | None, Props]] = []
        for alternative in alternatives:
            objects.extend(schema_objects(alternative, spec))
        return objects
    if name is None:
        for part in node.get("allOf") or []:
            _, part_name = resolve(part, spec)
            if part_name:
                name = part_name
                break
    props = schema_properties(schema, spec)
    return [(name, props)] if props or name else []


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------


def _object_name(raw: str) -> str:
    # Imported lazily: discovery.py imports this module.
    from src.core.api3_bopla.discovery import PropertyDiscoveryEngine

    return PropertyDiscoveryEngine.clean_object_name(raw)


def _path_object(path: str) -> str:
    from src.core.api3_bopla.discovery import PropertyDiscoveryEngine

    return PropertyDiscoveryEngine.get_object_name_from_path(path)


def _is_success(status: Any) -> bool:
    code = str(status).strip().upper()
    return code.startswith("2") or code == "DEFAULT"


def _media_schemas(body: Any, spec: dict) -> list[Any]:
    body, _ = resolve(body, spec)
    schemas = [(media or {}).get("schema") for media in (body.get("content") or {}).values()]
    if body.get("schema") is not None:  # Swagger 2 response
        schemas.append(body["schema"])
    return [s for s in schemas if s]


@dataclass
class ContractOperation:
    method: str  # "GET"
    path: str  # as written in the contract
    label: str  # "GET /normalized/{id}"
    path_object: str  # object guessed from the path (fallback)
    request: list[tuple[str | None, Props]] = field(default_factory=list)
    response: list[tuple[str | None, Props]] = field(default_factory=list)

    @property
    def resource_object(self) -> str:
        """
        Object the operation is about: its named success response (so /me and /profile read
        User), else the object of the path. A named request body is not used here: it often
        describes an input (POST /orders taking a ProductQuantity creates an Order).
        """
        for name, _ in self.response:
            if name:
                return _object_name(name)
        return self.path_object

    def request_objects(self) -> list[tuple[str, Props]]:
        """
        An inline request body belongs to the named response only when the two share a
        property (an update returning the updated resource); a generic envelope such as
        `{message, status}` does not own the request, which then goes to the path object.
        """
        objects: list[tuple[str, Props]] = []
        for name, props in self.request:
            if name:
                objects.append((_object_name(name), props))
                continue
            owner = self.path_object
            for response_name, response_props in self.response:
                if response_name and set(props) & set(response_props):
                    owner = _object_name(response_name)
                    break
            objects.append((owner, props))
        return objects

    def response_objects(self) -> list[tuple[str, Props]]:
        return [(_object_name(n) if n else self.resource_object, p) for n, p in self.response]

    def object_for(self, direction: str) -> str:
        """Object of the request ("write") or response ("read") body of this operation."""
        objects = self.request_objects() if direction == "write" else self.response_objects()
        return objects[0][0] if objects else self.resource_object


def _build_operations(spec: dict) -> list[ContractOperation]:
    from src.normalization.normalizer import APIEndpointNormalizer

    operations: list[ContractOperation] = []
    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        path_object = _path_object(path)
        for method, op in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(op, dict):
                continue
            operation = ContractOperation(
                method=method.upper(),
                path=path,
                label=f"{method.upper()} {APIEndpointNormalizer.normalize_path(path)}",
                path_object=path_object,
            )
            bodies = [op.get("requestBody")]
            # Swagger 2: body parameter
            bodies.extend(
                {"schema": p.get("schema")}
                for p in op.get("parameters") or []
                if isinstance(p, dict) and p.get("in") == "body"
            )
            for body in bodies:
                for schema in _media_schemas(body, spec):
                    operation.request.extend(schema_objects(schema, spec))
            for status, response in (op.get("responses") or {}).items():
                if not _is_success(status):
                    continue  # error envelopes do not describe the resource
                for schema in _media_schemas(response, spec):
                    operation.response.extend(schema_objects(schema, spec))
            operations.append(operation)
    return operations


class _SpecKey:
    """Identity wrapper, so a (unhashable) spec dict can key the operations cache."""

    __slots__ = ("spec",)

    def __init__(self, spec: dict):
        self.spec = spec

    def __hash__(self) -> int:
        return id(self.spec)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _SpecKey) and other.spec is self.spec


@lru_cache(maxsize=8)
def _cached_operations(key: _SpecKey) -> tuple[ContractOperation, ...]:
    return tuple(_build_operations(key.spec))


def iter_operations(spec: dict | None) -> list[ContractOperation]:
    if not spec:
        return []
    return list(_cached_operations(_SpecKey(spec)))


def _path_regex(path: str) -> re.Pattern:
    parts = re.split(r"(\{[^}/]+\})", path.rstrip("/") or "/")
    pattern = "".join("[^/]+" if p.startswith("{") else re.escape(p) for p in parts)
    return re.compile(f"^{pattern}/?$")


def operation_for(spec: dict | None, method: str, path: str) -> ContractOperation | None:
    """The contract operation matching an observed request (templates matched literally)."""
    if not spec or not path:
        return None
    method = (method or "GET").upper()
    path = path.split("?", 1)[0]
    candidates = [op for op in iter_operations(spec) if op.method == method]
    # Literal segments first: /users/me beats /users/{id}
    candidates.sort(key=lambda op: op.path.count("{"))
    for op in candidates:
        if _path_regex(op.path).match(path):
            return op
    return None


# ---------------------------------------------------------------------------
# Whole-contract views
# ---------------------------------------------------------------------------


def component_properties(spec: dict | None) -> dict[str, Props]:
    """Properties of the named schemas (OpenAPI 3 components, Swagger 2 definitions)."""
    results: dict[str, Props] = {}
    if not spec:
        return results
    named = dict(spec.get("definitions") or {})
    named.update((spec.get("components") or {}).get("schemas") or {})
    for raw_name in named:
        props = schema_properties({"$ref": _component_ref(spec, raw_name)}, spec)
        if props:
            results.setdefault(_object_name(raw_name), {}).update(props)
    return results


def _component_ref(spec: dict, raw_name: str) -> str:
    if raw_name in ((spec.get("components") or {}).get("schemas") or {}):
        return f"#/components/schemas/{raw_name}"
    return f"#/definitions/{raw_name}"


def contract_properties(spec: dict | None) -> dict[str, Props]:
    """Named schemas plus the inline schemas of the operations, by canonical object."""
    results = component_properties(spec)
    for op in iter_operations(spec):
        for obj, props in op.request_objects() + op.response_objects():
            if obj and obj != "Unknown" and props:
                target = results.setdefault(obj, {})
                for name, flags in props.items():
                    merged = target.setdefault(name, {"readOnly": False, "writeOnly": False})
                    merged["readOnly"] |= flags["readOnly"]
                    merged["writeOnly"] |= flags["writeOnly"]
    return results


def contract_flags(spec: dict | None) -> dict[tuple[str, str], set[str]]:
    """(object, property) -> {"readOnly", "writeOnly"} declared anywhere in the contract."""
    flags: dict[tuple[str, str], set[str]] = {}
    for obj, props in contract_properties(spec).items():
        for name, prop in props.items():
            declared = {flag for flag in ("readOnly", "writeOnly") if prop.get(flag)}
            if declared:
                flags.setdefault((obj, name), set()).update(declared)
    return flags
