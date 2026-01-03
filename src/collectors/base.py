from abc import ABC, abstractmethod
from ..models import VulnerabilityRiskTree

class BaseCollector(ABC):
    @abstractmethod
    def collect(self, cve_id: str, tree: VulnerabilityRiskTree) -> VulnerabilityRiskTree:
        """
        Collect data for the given CVE ID and update the tree.
        """
        pass
