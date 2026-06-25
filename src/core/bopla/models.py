from pydantic import BaseModel, RootModel, Field
from typing import List, Dict, Optional, Any

# --- Phase 1 models ---
class PropertyInfo(BaseModel):
    name: str
    sources: List[str]  # e.g., ["openapi", "ast", "runtime"]

class ObjectProperties(BaseModel):
    properties: List[PropertyInfo]

class PropertyInventory(RootModel[Dict[str, ObjectProperties]]):
    pass

# --- Phase 2 models ---
class PropertyEvidence(BaseModel):
    object_name: str
    property: str
    found_in_ast: bool = False
    found_in_openapi: bool = False
    found_runtime: bool = False
    read_endpoints: List[str] = Field(default_factory=list)
    write_endpoints: List[str] = Field(default_factory=list)
    authorization_contexts: List[str] = Field(default_factory=list)
    cross_model_occurrences: List[str] = Field(default_factory=list)  # raw class names (e.g. UserDTO, UserEntity)
    documentation_issues: List[str] = Field(default_factory=list)  # e.g. ["Property observed at runtime but absent from API specification."]
    confidence: float = 0.0

class PropertyGraphNode(BaseModel):
    property_name: str
    read_operations: List[str] = Field(default_factory=list)  # e.g., ["GET /profile"]
    write_operations: List[str] = Field(default_factory=list)  # e.g., ["PATCH /profile"]
    authorization_contexts: List[str] = Field(default_factory=list)  # e.g. ["@roles_required(admin)", "if(current_user...)"]

class ObjectGraphNode(BaseModel):
    object_name: str
    properties: Dict[str, PropertyGraphNode] = Field(default_factory=dict)

class PropertyAuthorizationGraph(BaseModel):
    objects: Dict[str, ObjectGraphNode] = Field(default_factory=dict)


# --- Phase 3 models ---
class DynamicPropertyFinding(BaseModel):
    test_id: str  # e.g., "T01"
    endpoint: str
    method: str
    property_name: str
    evidence: List[str] = Field(default_factory=list)
    request: Any  # request details, payload or headers
    response: Any  # response body or details
    response_code: Optional[int] = None
    verified: bool  # True if the vulnerability is confirmed
    confidence: float  # confidence score

