from typing import List, Any
from src.rules.bucket_policies.base_policy_rule import BasePolicyRule

class NoPublicAccessRule(BasePolicyRule):
    """
    Verifica che non ci siano Statement con Principal="*", Effect="Allow".
    """
    
    def evaluate(self, bucket_entity: Any) -> List[str]:
        risks = []
        
        policy_dict = self.extract_policy_dict(bucket_entity.policies)
        if not policy_dict:
            return risks
            
        statements = self.get_statements(policy_dict)
        for i, stmt in enumerate(statements):
            effect = stmt.get("Effect")
            principal = stmt.get("Principal")
            
            if effect == "Allow":
                is_public = False
                if principal == "*":
                    is_public = True
                elif isinstance(principal, dict):
                    if principal.get("AWS") == "*":
                        
                        is_public = True
                        
                if is_public:
                    risks.append(f"RISCHIO: La policy (Statement #{i+1}) permette l'accesso pubblico (Principal: '*'). Si raccomanda di restringere l'accesso.")
                    
        return risks
