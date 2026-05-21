from abc import ABC, abstractmethod
from typing import List, Any

class ScannerInterface(ABC):
    @abstractmethod
    def scan(self, target_dir: str) -> List[Any]:
        """Execute scan on target_dir and return a list of findings."""
        pass
