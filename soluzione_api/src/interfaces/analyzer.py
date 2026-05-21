from abc import ABC, abstractmethod
from typing import List, Any

class AnalyzerInterface(ABC):
    @abstractmethod
    def run_analysis(self) -> List[Any]:
        """Execute analysis on target or captured traffic and return findings."""
        pass
