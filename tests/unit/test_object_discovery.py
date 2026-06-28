import pytest
from src.core.object_level_authorization.discovery.object_discovery import ObjectReferenceDiscoveryEngine

def test_object_reference_discovery():
    request_data = {
        "method": "POST",
        "path": "/api/v1/users/123/documents",
        "full_url": "http://api-server:5000/api/v1/users/123/documents?tenantId=tenant-abc&limit=10",
        "headers": {},
        "body_params": {
            "accountId": 999,
            "nested": {
                "ownerId": "owner-xyz",
                "custom_id": "custom-val"
            },
            "items": [
                {"orderId": 500},
                {"someOtherField": "value"}
            ]
        }
    }

    refs = ObjectReferenceDiscoveryEngine.extract_references(request_data)

    # Convert to a dictionary of (location, name) -> value for easy assertion
    ref_map = {(r["location"], r["name"]): r["value"] for r in refs}

    # 1. Path check (123 should be extracted as users_id or similar depending on parent segment)
    assert ("path", "users_id") in ref_map
    assert ref_map[("path", "users_id")] == "123"

    # 2. Query parameter check (tenantId)
    assert ("query", "tenantId") in ref_map
    assert ref_map[("query", "tenantId")] == "tenant-abc"
    # Ensure limit is not extracted (not matching ID pattern)
    assert ("query", "limit") not in ref_map

    # 3. Body parameter check (accountId, nested.ownerId, nested.custom_id, items[0].orderId)
    assert ("body", "accountId") in ref_map
    assert ref_map[("body", "accountId")] == 999

    assert ("body", "nested.ownerId") in ref_map
    assert ref_map[("body", "nested.ownerId")] == "owner-xyz"

    assert ("body", "nested.custom_id") in ref_map
    assert ref_map[("body", "nested.custom_id")] == "custom-val"

    assert ("body", "items[0].orderId") in ref_map
    assert ref_map[("body", "items[0].orderId")] == 500
