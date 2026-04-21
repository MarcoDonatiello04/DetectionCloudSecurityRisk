import json
from typing import Dict, Any, List
from src.interfaces.rule_interface import IPolicyRule

class BasePolicyRule(IPolicyRule):
    """
    Classe base che offre metodi di utilità per analizzare il JSON o i dizionari delle Policy.
    """
    
    def extract_policy_dict(self, policy_data: Any) -> Dict[str, Any]:
        """
        Tenta di convertire l'attributo policy in un dizionario Python.
        Gestisce stringhe JSON, dict o liste.
        """
        if not policy_data:
            return {}
            
        if isinstance(policy_data, dict):
            return policy_data
            
        if isinstance(policy_data, str):
            try:
                return json.loads(policy_data)
            except json.JSONDecodeError:
                return {}
                
        # Terraform a volte restituisce una lista per la policy
        if isinstance(policy_data, list) and len(policy_data) > 0:
            return self.extract_policy_dict(policy_data[0])
            
        return {}
        
    def get_statements(self, policy_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Estrae l'array 'Statement' dalla policy.
        """
        statements = policy_dict.get("Statement", [])
        if isinstance(statements, dict):
            return [statements]
        return statements if isinstance(statements, list) else []

    def evaluate(self, bucket_entity: Any) -> List[str]:
        """Da implementare nelle classi figlie"""
        raise NotImplementedError
