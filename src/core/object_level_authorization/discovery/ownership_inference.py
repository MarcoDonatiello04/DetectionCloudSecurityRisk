import logging
import re
from typing import Any

import jwt

logger = logging.getLogger("SecurityPlatform.BOLA.OwnershipInference")


class OwnershipInferenceEngine:
    """
    OwnershipInferenceEngine analyzes network traffic logs to build a map of
    user identities and their associated (owned) resource IDs.
    This enables BOLA testing in non-production environments (like staging or prod)
    where database seeding and state rollback are not available.
    """

    # Field names in the body considered as resource identifiers.
    # Kept in sync with ObjectReferenceDiscoveryEngine's ID heuristics.
    ID_FIELD_PATTERN = re.compile(r"(.*id|.*Id|.*_id|uuid|guid)$", re.IGNORECASE)
    SPECIFIC_ID_FIELDS = {
        "id",
        "userid",
        "ownerid",
        "accountid",
        "tenantid",
        "resourceid",
        "orderid",
        "customerid",
        "documentid",
        "uuid",
        "guid",
    }

    EXCLUDED_RESOURCE_IDS = {"seed", "snapshot", "rollback"}

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
        self.ownership_map: dict[str, dict[str, Any]] = {}

    @classmethod
    def _is_id_field(cls, key: str) -> bool:
        key_lower = key.lower()
        if key_lower in cls.SPECIFIC_ID_FIELDS:
            return True
        return bool(cls.ID_FIELD_PATTERN.match(key))

    def _extract_user_info(self, auth_header: str) -> dict[str, Any]:
        """Extracts identity info (sub, username, role) from a JWT token."""
        if not auth_header or not auth_header.lower().startswith("bearer "):
            return {}

        try:
            token = auth_header.split(" ", 1)[1]
            # Decode JWT without verifying signature since we are analyzing traffic
            payload = jwt.decode(token, options={"verify_signature": False})
            sub = payload.get("sub")
            username = payload.get("preferred_username") or payload.get("name")
            roles = payload.get("roles", []) or []
            roles_lower = {str(r).lower() for r in roles}

            role = "user"
            if "admin" in roles_lower:
                role = "admin"
            elif "manager" in roles_lower:
                role = "manager"

            if sub:
                return {"uid": sub, "username": username, "role": role}
        except Exception as e:
            logger.debug(f"Failed to decode token for ownership inference: {e}")
        return {}

    def _parse_resource_from_path(self, path: str) -> tuple[str | None, str | None]:
        """
        Parses the resource type and resource ID closest to the end of a REST path.
        Handles nested paths by walking segments from the end, e.g.:
          /api/orders/101/items/55 -> ('items', '55')
          /api/orders/101          -> ('orders', '101')
        """
        segments = [s for s in path.split("/") if s]
        if segments and segments[0].lower() == "api":
            segments = segments[1:]

        if len(segments) >= 2:
            return segments[-2], segments[-1]
        return None, None

    def analyze_traffic(self, traffic_data: list[dict[str, Any]]) -> None:
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

            auth_header = entry.get("auth_header") or entry.get("headers", {}).get(
                "Authorization", ""
            )
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
                    "resources": {},
                }
            else:
                # Keep token fresh if new one is seen
                self.ownership_map[uid]["token"] = auth_header

            # 1. Infer from Path
            path = entry.get("path", "")
            res_type, res_id = self._parse_resource_from_path(path)
            if (
                res_type
                and res_id
                and (
                    not res_id.lower().startswith("test")
                    and res_id.lower() not in self.EXCLUDED_RESOURCE_IDS
                )
            ):
                self.ownership_map[uid]["resources"].setdefault(res_type, set()).add(res_id)

            # 2. Infer from Request body (if JSON is present)
            body_params = entry.get("body_params")
            if isinstance(body_params, dict):
                path_segments = [s for s in path.split("/") if s]
                for k, v in body_params.items():
                    if not self._is_id_field(k) or not isinstance(v, (str, int)):
                        continue
                    if path_segments:
                        if path_segments[-1] == str(v) and len(path_segments) >= 2:
                            inferred_type = path_segments[-2]
                        else:
                            inferred_type = path_segments[-1]
                    else:
                        inferred_type = k
                    self.ownership_map[uid]["resources"].setdefault(inferred_type, set()).add(
                        str(v)
                    )

    def get_inferred_identities(self) -> tuple:
        """
        Selects userA (Alice - regular user), userB (Bob - regular user), and userC (Charlie - admin)
        from the inferred traffic data.
        Returns: (uuid_alice, uuid_bob, uuid_charlie, role_map, headers_matrix)
        """
        role_map: dict[str, str] = {}
        headers_matrix = {"userA": {}, "userB": {}, "userC": {}, "anonymous": {}}

        users = list(self.ownership_map.keys())
        regular_users = [uid for uid in users if self.ownership_map[uid]["role"] == "user"]

        # 1. Alice: first real regular user, if any
        if regular_users:
            uuid_alice = regular_users[0]
            headers_matrix["userA"] = {"Authorization": self.ownership_map[uuid_alice]["token"]}
            role_map[uuid_alice] = "user"
        else:
            uuid_alice = "mock-alice-uuid"
            headers_matrix["userA"] = {"Authorization": "Bearer mock-alice-token"}
            role_map[uuid_alice] = "user"

        # 2. Bob: second real regular user, if any; otherwise a mock distinct from Alice
        if len(regular_users) >= 2:
            uuid_bob = regular_users[1]
            headers_matrix["userB"] = {"Authorization": self.ownership_map[uuid_bob]["token"]}
            role_map[uuid_bob] = "user"
        else:
            uuid_bob = "mock-bob-uuid"
            headers_matrix["userB"] = {"Authorization": "Bearer mock-bob-token"}
            role_map[uuid_bob] = "user"

        # 3. Charlie: an admin or manager, if any; otherwise a mock admin
        admins = [uid for uid in users if self.ownership_map[uid]["role"] in ("admin", "manager")]
        if admins:
            uuid_charlie = admins[0]
            headers_matrix["userC"] = {"Authorization": self.ownership_map[uuid_charlie]["token"]}
            role_map[uuid_charlie] = self.ownership_map[uuid_charlie]["role"]
        else:
            uuid_charlie = "mock-charlie-uuid"
            headers_matrix["userC"] = {"Authorization": "Bearer mock-charlie-token"}
            role_map[uuid_charlie] = "admin"

        return uuid_alice, uuid_bob, uuid_charlie, role_map, headers_matrix
