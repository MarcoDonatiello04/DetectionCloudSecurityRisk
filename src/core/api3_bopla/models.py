from typing import Any

from pydantic import BaseModel, Field, RootModel


# --- Phase 1 models ---
class PropertyInfo(BaseModel):
    name: str
    sources: list[str]  # e.g., ["openapi", "ast", "runtime"]


class ObjectProperties(BaseModel):
    properties: list[PropertyInfo]


class PropertyInventory(RootModel[dict[str, ObjectProperties]]):
    pass


# --- Phase 2 models ---
class PropertyEvidence(BaseModel):
    object_name: str
    property: str
    found_in_ast: bool = False
    found_in_openapi: bool = False
    found_runtime: bool = False
    read_endpoints: list[str] = Field(default_factory=list)
    write_endpoints: list[str] = Field(default_factory=list)
    authorization_contexts: list[str] = Field(default_factory=list)
    cross_model_occurrences: list[str] = Field(
        default_factory=list
    )  # raw class names (e.g. UserDTO, UserEntity)
    documentation_issues: list[str] = Field(
        default_factory=list
    )  # e.g. ["Property observed at runtime but absent from API specification."]
    # Flags the contract declares for the property ("readOnly", "writeOnly"): the application's
    # own expectation of which direction is reserved (writing refused, value never returned).
    contract_flags: list[str] = Field(default_factory=list)
    confidence: float = 0.0


class PropertyGraphNode(BaseModel):
    property_name: str
    read_operations: list[str] = Field(default_factory=list)  # e.g., ["GET /profile"]
    write_operations: list[str] = Field(default_factory=list)  # e.g., ["PATCH /profile"]
    authorization_contexts: list[str] = Field(
        default_factory=list
    )  # e.g. ["@roles_required(admin)", "if(current_user...)"]


class ObjectGraphNode(BaseModel):
    object_name: str
    properties: dict[str, PropertyGraphNode] = Field(default_factory=dict)


class PropertyAuthorizationGraph(BaseModel):
    objects: dict[str, ObjectGraphNode] = Field(default_factory=dict)


# --- Phase 3 models ---
class DynamicPropertyFinding(BaseModel):
    test_id: str  # e.g., "T01"
    endpoint: str
    method: str
    property_name: str
    evidence: list[str] = Field(default_factory=list)
    request: Any  # request details, payload or headers
    response: Any  # response body or details
    response_code: int | None = None
    verified: bool  # True if the vulnerability is confirmed
    confidence: float  # confidence score


# --- Static rules (no dynamic confirmation) ---
class StaticPropertyFinding(BaseModel):
    """A property-level weakness read in the code, to be confirmed by the dynamic phase."""

    rule_id: str  # e.g. "BOPLA-S01"
    kind: str  # e.g. "mass_assignment"
    file_path: str
    line: int
    language: str
    endpoint: str | None = None  # "PUT /users/<id>" when the enclosing route is known
    entity: str | None = None  # inventory object bound to the request data, if resolved
    source: str  # request data expression, e.g. "request.json"
    sink: str  # binding expression, e.g. "setattr(user, field, value)"
    guard: str | None = None  # denylist found on the keys, if any
    properties_at_risk: list[str] = Field(default_factory=list)  # inferred protected properties
    severity: str  # "HIGH" | "MEDIUM"
    confidence: float
    evidence: list[str] = Field(default_factory=list)
    verified: bool = False  # True only when a dynamic test confirms it
    # "unverified" (no dynamic phase or nothing to test), "confirmed" (a dynamic test proved
    # it), "not_confirmed" (the dynamic phase tested these properties and found them protected)
    status: str = "unverified"
    confirmed_by: list[str] = Field(default_factory=list)  # e.g. ["T03:role"]
