from typing import List, Any
from src.interfaces.rule_interface import IPolicyRule

class PolicyEngine:
    """
    Motore che esegue un set di regole (IPolicyRule) contro un'entità.
    """
    def __init__(self):
        self.rules: List[IPolicyRule] = []
        
    def register_rule(self, rule: IPolicyRule):
        """Aggiunge una regola al motore."""
        self.rules.append(rule)
        
    def evaluate_entity(self, entity: Any) -> List[str]:
        """
        Esegue tutte le regole registrate sull'entità passata.
        Restituisce la somma di tutti i rischi trovati.
        """
        all_risks = []
        for rule in self.rules:
            risks = rule.evaluate(entity)
            if risks:
                all_risks.extend(risks)
        return all_risks
