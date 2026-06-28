import logging
import re
import jwt
from typing import List, Dict, Any, Set

logger = logging.getLogger("SecurityPlatform.BOLA.OwnershipInference")

class OwnershipInferenceEngine:
    """
    OwnershipInferenceEngine analyzes network traffic logs to build a map of
    user identities and their associated (owned) resource IDs.
    This enables BOLA testing in non-production environments (like staging or prod)
    where database seeding and state rollback are not available.
    """
    def __init__(self):
        # Maps user identifier (e.g., sub/username) to their details and owned resources
        # Structure:
        # {
        #    "user_uuid": {
        #        "role": "user",
        #        "username": "alice",
        #        "token": "Bearer ...",
        #        "resources": {
        #            "orders": {"101", "102"},
        #            "invoices": {"100"}
        #        }
        #    }
        # }
        self.ownership_map = {}

    def _extract_user_info(self, auth_header: str) -> Dict[str, Any]:
        """Extracts identity info (sub, username, role) from a JWT token."""
        if not auth_header or not auth_header.lower().startswith("bearer "):
            return {}
        
        try:
            token = auth_header.split(" ")[1]
            # Decode JWT without verifying signature since we are analyzing traffic
            payload = jwt.decode(token, options={"verify_signature": False})
            sub = payload.get("sub")
            username = payload.get("preferred_username") or payload.get("name")
            roles = payload.get("roles", [])
            
            role = "user"
            if "admin" in roles:
                role = "admin"
            elif "manager" in roles:
                role = "manager"
                
            if sub:
                return {"uid": sub, "username": username, "role": role}
        except Exception as e:
            logger.debug(f"Failed to decode token for ownership inference: {e}")
        return {}

    def _parse_resource_from_path(self, path: str) -> tuple:
        """
        Parses resource type and resource ID from a REST path.
        E.g., /api/orders/101 -> ('orders', '101')
        """
        pattern = r"/api/([^/]+)/([^/]+)/?$"
        match = re.search(pattern, path)
        if match:
            return match.group(1), match.group(2)
        return None, None

    def analyze_traffic(self, traffic_data: List[Dict[str, Any]]) -> None:
        """
        Processes a list of HTTP transactions to infer ownership relations and extract tokens.
        """
        if not traffic_data:
            return

        for entry in traffic_data:
            status = entry.get("status")
            # Only infer from successful requests (2xx status codes)
            if not status or not (200 <= status < 300):
                continue

            auth_header = entry.get("auth_header") or entry.get("headers", {}).get("Authorization", "")
            user_info = self._extract_user_info(auth_header)
            if not user_info:
                continue

            uid = user_info["uid"]
            role = user_info["role"]
            username = user_info["username"]

            # Initialize user entry if not exists
            if uid not in self.ownership_map:
                self.ownership_map[uid] = {
                    "role": role,
                    "username": username,
                    "token": auth_header,
                    "resources": {}
                }
            else:
                # Keep token fresh if new one is seen
                self.ownership_map[uid]["token"] = auth_header

            # 1. Infer from Path
            path = entry.get("path", "")
            res_type, res_id = self._parse_resource_from_path(path)
            if res_type and res_id:
                # Exclude administrative/non-resource paths
                if not res_id.startswith("test") and res_id not in ("seed", "snapshot", "rollback"):
                    if res_type not in self.ownership_map[uid]["resources"]:
                        self.ownership_map[uid]["resources"][res_type] = set()
                    self.ownership_map[uid]["resources"][res_type].add(res_id)

            # 2. Infer from Request body (if JSON is present)
            body_params = entry.get("body_params")
            if isinstance(body_params, dict):
                for k, v in body_params.items():
                    if k in ("id", "resourceId", "uuid", "guid") and isinstance(v, (str, int)):
                        path_segments = [s for s in path.split("/") if s]
                        if len(path_segments) >= 2:
                            inferred_type = path_segments[-2] if path_segments[-1] == str(v) else path_segments[-1]
                            if inferred_type not in self.ownership_map[uid]["resources"]:
                                self.ownership_map[uid]["resources"][inferred_type] = set()
                            self.ownership_map[uid]["resources"][inferred_type].add(str(v))

    def get_inferred_identities(self) -> tuple:
        """
        Selects userA (Alice - regular user), userB (Bob - regular user), and userC (Charlie - admin)
        from the inferred traffic data.
        Returns: (uuid_alice, uuid_bob, uuid_charlie, role_map, headers_matrix)
        """
        uuid_alice = None
        uuid_bob = None
        uuid_charlie = None
        role_map = {}
        headers_matrix = {
            "userA": {},
            "userB": {},
            "userC": {},
            "anonymous": {}
        }

        users = list(self.ownership_map.keys())
        
        # 1. Find Alice and Bob (two users with 'user' role)
        regular_users = [uid for uid in users if self.ownership_map[uid]["role"] == "user"]
        if len(regular_users) >= 1:
            uuid_alice = regular_users[0]
            headers_matrix["userA"] = {"Authorization": self.ownership_map[uuid_alice]["token"]}
            role_map[uuid_alice] = "user"
        if len(regular_users) >= 2:
            uuid_bob = regular_users[1]
            headers_matrix["userB"] = {"Authorization": self.ownership_map[uuid_bob]["token"]}
            role_map[uuid_bob] = "user"
        else:
            # Fallback if only one user is found
            uuid_bob = "mock-bob-uuid"
            headers_matrix["userB"] = {"Authorization": "Bearer mock-bob-token"}
            role_map[uuid_bob] = "user"

        # 2. Find Charlie (an admin or manager)
        admins = [uid for uid in users if self.ownership_map[uid]["role"] in ("admin", "manager")]
        if admins:
            uuid_charlie = admins[0]
            headers_matrix["userC"] = {"Authorization": self.ownership_map[uuid_charlie]["token"]}
            role_map[uuid_charlie] = self.ownership_map[uuid_charlie]["role"]
        else:
            uuid_charlie = "mock-charlie-uuid"
            headers_matrix["userC"] = {"Authorization": "Bearer mock-charlie-token"}
            role_map[uuid_charlie] = "admin"

        if not uuid_alice:
            uuid_alice = "mock-alice-uuid"
            headers_matrix["userA"] = {"Authorization": "Bearer mock-alice-token"}
            role_map[uuid_alice] = "user"

        return uuid_alice, uuid_bob, uuid_charlie, role_map, headers_matrix
