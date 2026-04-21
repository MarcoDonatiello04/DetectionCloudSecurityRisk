from typing import List, Any
from src.rules.bucket_policies.base_policy_rule import BasePolicyRule

class ReadAccessRule(BasePolicyRule):
    def evaluate_policy_statement(self, statement: Dict[str, Any]) -> List[str]:
        risks = []
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        
        read_actions = ["s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"]
        has_read_action = any(action in actions for action in read_actions)
        if not has_read_action:
            return risks
        
        principal = statement.get("Principal", {})
        is_public_principal = self._is_principal_public(principal)
        if is_public_principal:
            risks.append(
                f"RISCHIO: Trovata azione di lettura ({', '.join(actions)}) verso un Principal pubblico ('{principal}')."
            )
            
        return risks
    
    def _is_principal_public(self, principal: Any) -> bool:
        """Determina se il Principal è pubblico."""
        if not principal:
            return True
            
        if isinstance(principal, dict):
            aws_val = principal.get("AWS")
            if aws_val == "*" or (isinstance(aws_val, list) and "*" in aws_val):
                return True
        
        elif isinstance(principal, str) and principal == "*":
            return True
            
        return False