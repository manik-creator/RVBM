import requests
import json
import os
from .base import BaseCollector
from ..models import VulnerabilityRiskTree

class CisaKevCollector(BaseCollector):
    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    CACHE_FILE = "data/cisa_kev.json"

    def __init__(self):
        self._ensure_data_dir()

    def _ensure_data_dir(self):
        if not os.path.exists("data"):
            os.makedirs("data")

    def _get_kev_data(self):
        # simple caching strategy
        if os.path.exists(self.CACHE_FILE):
             # check age if needed, but for now just load if exists to save time
             with open(self.CACHE_FILE, 'r') as f:
                 return json.load(f)
        
        try:
            response = requests.get(self.KEV_URL)
            response.raise_for_status()
            data = response.json()
            with open(self.CACHE_FILE, 'w') as f:
                json.dump(data, f)
            return data
        except Exception as e:
            print(f"Error fetching CISA KEV: {e}")
            return {"vulnerabilities": []}

    def collect(self, cve_id: str, tree: VulnerabilityRiskTree) -> VulnerabilityRiskTree:
        data = self._get_kev_data()
        cve_upper = cve_id.upper()
        
        is_kev = False
        description = ""
        
        for vuln in data.get("vulnerabilities", []):
            if vuln.get("cveID") == cve_upper:
                is_kev = True
                description = vuln.get("shortDescription", "")
                break
        
        tree.threat.likelihood.known_evidence.cisa_kev = is_kev
        if is_kev:
            tree.threat.likelihood.known_evidence.details += f"Listed in CISA KEV: {description}\n"
            tree.threat.likelihood.known_evidence.in_wild = True # Logic for 'Known Actively Exploited in the Wild'

        return tree
