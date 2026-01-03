import requests
from .base import BaseCollector
from ..models import VulnerabilityRiskTree

class EPSSCollector(BaseCollector):
    API_URL = "https://api.first.org/data/v1/epss"

    def collect(self, cve_id: str, tree: VulnerabilityRiskTree) -> VulnerabilityRiskTree:
        try:
            # Fetch time-series (last 30 days) to support LEV calculation
            response = requests.get(self.API_URL, params={"cve": cve_id, "scope": "time-series"})
            response.raise_for_status()
            data = response.json()
            
            if data.get("data"):
                latest = data["data"][0]
                tree.threat.likelihood.epss.score = float(latest.get("epss", 0.0))
                tree.threat.likelihood.epss.percentile = float(latest.get("percentile", 0.0))
                
                # The time-series data is nested within the 'time-series' key of the latest item
                history_items = latest.get("time-series", [])
                if history_items:
                    tree.threat.likelihood.epss.history = [float(i.get("epss", 0.0)) for i in history_items]
                else:
                    # Fallback if time-series field is missing
                    tree.threat.likelihood.epss.history = [tree.threat.likelihood.epss.score]
        except Exception as e:
            print(f"Error fetching EPSS: {e}")
        
        return tree
