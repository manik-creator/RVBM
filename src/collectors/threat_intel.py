import requests
import os
import json
from .base import BaseCollector
from ..models import VulnerabilityRiskTree

class ThreatIntelCollector(BaseCollector):
    GITHUB_API_URL = "https://api.github.com/search/repositories"
    
    def collect(self, cve_id: str, tree: VulnerabilityRiskTree) -> VulnerabilityRiskTree:
        # 1. Nuclei (Check Raw URL)
        if self._check_nuclei(cve_id):
            tree.threat.likelihood.weaponized_exploit.nuclei = True
            tree.threat.likelihood.weaponized_exploit.details += "Found Nuclei template. "

        # 2. ExploitDB (Check CSV)
        if self._check_exploitdb(cve_id):
            tree.threat.likelihood.poc_exploit.exploit_db = True
            tree.threat.likelihood.poc_exploit.details += "Found ExploitDB entry. "

        # 3. Metasploit (GitHub Search API - requires token, or fallback)
        # Note: robust checking without a full clone is hard. 
        # We try a best-effort API check if token exists, else we rely on CISA KEV or manual verification.
        if "GITHUB_TOKEN" in os.environ:
             if self._search_repo_for_cve("rapid7/metasploit-framework", cve_id):
                tree.threat.likelihood.weaponized_exploit.metasploit = True
                tree.threat.likelihood.weaponized_exploit.details += "Found Metasploit module (via API). "

        # 4. Generic GitHub POC search
        if not tree.threat.likelihood.poc_exploit.github:
             self._check_generic_github_pocs(cve_id, tree)

        return tree

    def _check_nuclei(self, cve_id: str) -> bool:
        """
        Checks for Nuclei template by predicting the raw GitHub URL.
        Pattern: https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/cves/YEAR/CVE-YEAR-ID.yaml
        """
        try:
            year = cve_id.split('-')[1]
            # Try HTTP templates (most common)
            url = f"https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/cves/{year}/{cve_id}.yaml"
            response = requests.head(url, timeout=5)
            if response.status_code == 200:
                return True
            
            # Additional check for 'network' or other categories could be added here
            return False
        except Exception as e:
            print(f"  [!] Error checking Nuclei: {e}")
            return False

    def _check_exploitdb(self, cve_id: str) -> bool:
        """
        Checks ExploitDB by parsing the official files_exploits.csv
        """
        csv_path = "data/exploitdb_files.csv"
        csv_url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
        
        try:
            # Download/Cache CSV
            if not os.path.exists("data"):
                os.makedirs("data")
                
            if not os.path.exists(csv_path):
                print("  [*] Downloading ExploitDB CSV index...")
                r = requests.get(csv_url, timeout=10)
                if r.status_code == 200:
                    with open(csv_path, 'w') as f:
                        f.write(r.text)
            
            # Search CSV
            if os.path.exists(csv_path):
                with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        if cve_id.upper() in line.upper(): # grep
                            return True
        except Exception as e:
            print(f"  [!] Error checking ExploitDB: {e}")
            
        return False

    def _search_repo_for_cve(self, repo_fullname: str, cve_id: str) -> bool:
        # ... (Existing API logic kept for Metasploit if Token exists)
        try:
            query = f"{cve_id} repo:{repo_fullname}"
            params = {"q": query}
            headers = {"Accept": "application/vnd.github.v3+json"}
            if "GITHUB_TOKEN" in os.environ:
                headers["Authorization"] = f"token {os.environ['GITHUB_TOKEN']}"
            
            url = "https://api.github.com/search/code" 
            response = requests.get(url, params=params, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                return data.get("total_count", 0) > 0
        except:
            pass
        return False


    def _check_generic_github_pocs(self, cve_id: str, tree: VulnerabilityRiskTree):
        try:
            # Search for Repositories (not code) to save on stricter Code Search rate limits for the generic check
            params = {"q": f"{cve_id} poc", "sort": "updated", "order": "desc"}
            headers = {"Accept": "application/vnd.github.v3+json"}
            
            if "GITHUB_TOKEN" in os.environ:
                headers["Authorization"] = f"token {os.environ['GITHUB_TOKEN']}"
                
            response = requests.get(self.GITHUB_API_URL, params=params, headers=headers)
            if response.status_code == 200:
                data = response.json()
                if data.get("total_count", 0) > 0:
                    tree.threat.likelihood.poc_exploit.github = True
                    tree.threat.likelihood.poc_exploit.details += "Found generic POC repos on GitHub. "
        except Exception as e:
            print(f"Error generic GitHub check: {e}")


class LocalContextCollector(BaseCollector):
    CONFIG_FILE = "org_context.json"
    
    def collect(self, cve_id: str, tree: VulnerabilityRiskTree) -> VulnerabilityRiskTree:
        if not os.path.exists(self.CONFIG_FILE):
            return tree
            
        try:
            with open(self.CONFIG_FILE, 'r') as f:
                config = json.load(f)
                
            known = config.get("known_exploited_in_org", {})
            bug_bounty = known.get("bug_bounty_hits", [])
            ir = known.get("incident_response_hits", [])
            
            if cve_id in bug_bounty:
                tree.threat.likelihood.known_evidence.org_specific.bug_bounty = True
                tree.threat.likelihood.known_evidence.org_specific.details += "Found in Bug Bounty hits. "
            
            if cve_id in ir:
                tree.threat.likelihood.known_evidence.org_specific.incident_response = True
                tree.threat.likelihood.known_evidence.org_specific.details += "Found in Incident Response history. "
                
        except Exception as e:
            print(f"Error loading local context: {e}")
            
        return tree
