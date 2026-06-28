import re
import urllib.parse
from typing import List, Dict, Any

class ObjectReferenceDiscoveryEngine:
    """
    ObjectReferenceDiscoveryEngine parses incoming requests and searches for
    potential object references in paths, query parameters, and JSON bodies.
    """
    
    ID_PATTERN = re.compile(r'(.*id|.*Id|.*_id|uuid|guid)$', re.IGNORECASE)
    
    # Specific fields to look for directly
    SPECIFIC_ID_FIELDS = {
        "id", "userid", "ownerid", "accountid", "tenantid", "resourceid",
        "orderid", "customerid", "documentid", "uuid", "guid"
    }

    @classmethod
    def is_id_field(cls, key: str) -> bool:
        """Determines if a field name matches an ID pattern/name."""
        key_lower = key.lower()
        if key_lower in cls.SPECIFIC_ID_FIELDS:
            return True
        return bool(cls.ID_PATTERN.match(key))

    @classmethod
    def parse_json_recursive(cls, data: Any, prefix: str = "") -> List[Dict[str, Any]]:
        """
        Recursively walks a JSON object/list to find ID fields and their values.
        Returns a list of dicts: {"path": "...", "value": ...}
        """
        results = []
        if isinstance(data, dict):
            for k, v in data.items():
                current_path = f"{prefix}.{k}" if prefix else k
                if cls.is_id_field(k) and isinstance(v, (str, int)):
                    results.append({
                        "path": current_path,
                        "value": v,
                        "location": "body"
                    })
                if isinstance(v, (dict, list)):
                    results.extend(cls.parse_json_recursive(v, current_path))
        elif isinstance(type(data), list) or isinstance(data, list):
            for index, item in enumerate(data):
                current_path = f"{prefix}[{index}]"
                results.extend(cls.parse_json_recursive(item, current_path))
        return results

    @classmethod
    def extract_references(cls, request_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extracts all candidate object references from the request.
        A request is a dict representing the traffic entry:
        {
            "method": str,
            "path": str,
            "full_url": str,
            "headers": dict,
            "body_params": dict/str/None
        }
        """
        references = []
        
        # 1. Path segment extraction (if it contains uuid/numbers/etc.)
        # E.g. /api/orders/101 or /api/orders/f81d4fae-...
        path = request_data.get("path", "")
        # Split path by /
        segments = [s for s in path.split("/") if s]
        uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
        for idx, segment in enumerate(segments):
            # Check if segment looks like an ID (numeric or UUID)
            if segment.isdigit() or uuid_pattern.match(segment):
                # We can name the reference by the parent segment or index
                parent_name = segments[idx - 1] if idx > 0 else "path"
                references.append({
                    "name": f"{parent_name}_id",
                    "value": segment,
                    "location": "path",
                    "index": idx
                })

        # 2. Query Parameter extraction
        full_url = request_data.get("full_url", "")
        if full_url:
            parsed_url = urllib.parse.urlparse(full_url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            for key, values in query_params.items():
                if cls.is_id_field(key):
                    for val in values:
                        references.append({
                            "name": key,
                            "value": val,
                            "location": "query"
                        })

        # 3. Body Parameter extraction
        body_params = request_data.get("body_params")
        if body_params:
            if isinstance(body_params, str):
                try:
                    body_params = json.loads(body_params)
                except Exception:
                    pass
            
            if isinstance(body_params, (dict, list)):
                body_refs = cls.parse_json_recursive(body_params)
                for r in body_refs:
                    references.append({
                        "name": r["path"],
                        "value": r["value"],
                        "location": "body"
                    })
                    
        return references
