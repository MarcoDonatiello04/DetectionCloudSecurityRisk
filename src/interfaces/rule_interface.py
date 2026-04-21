from abc import ABC, abstractmethod
from typing import List, Any

class IPolicyRule(ABC):
    """
    Interfaccia per le regole di validazione delle policy.
    """
    
    @abstractmethod
    def evaluate(self, bucket_entity: Any) -> List[str]:
        """
        Valuta la policy del bucket e restituisce una lista di rischi (stringhe).
        Ritorna una lista vuota se la policy è conforme a questa regola.
        """
        pass
