import requests
from .base import BaseCollector
from ..models import VulnerabilityRiskTree, ExploitabilityMetrics, SystemImpact, ReportConfidence

class NVDCollector(BaseCollector):
    API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def collect(self, cve_id: str, tree: VulnerabilityRiskTree) -> VulnerabilityRiskTree:
        try:
            response = requests.get(self.API_URL, params={"cveId": cve_id}, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                return tree
            
            cve_item = vulnerabilities[0].get("cve", {})
            
            # Description
            descriptions = cve_item.get("descriptions", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    tree.description = desc.get("value", "")
                    break
            
            # Metrics
            metrics = cve_item.get("metrics", {})
            # Prefer CVSS v3.1, then v3.0, then v2
            cvss_data = None
            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
            elif "cvssMetricV30" in metrics:
                cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
            
            if cvss_data:
                tree.base_score = cvss_data.get("baseScore", 0.0)
                tree.severity = cvss_data.get("baseSeverity", "UNKNOWN")
                
                # Exploitability
                tree.threat.exploitability_metrics.attack_vector = cvss_data.get("attackVector", "Unknown")
                tree.threat.exploitability_metrics.attack_complexity = cvss_data.get("attackComplexity", "Unknown")
                tree.threat.exploitability_metrics.privileges_required = cvss_data.get("privilegesRequired", "Unknown")
                tree.threat.exploitability_metrics.user_interaction = cvss_data.get("userInteraction", "Unknown")
                tree.threat.exploitability_metrics.scope = cvss_data.get("scope", "Unknown")
                
                # Impact
                tree.impact.system_impact.confidentiality = cvss_data.get("confidentialityImpact", "None")
                tree.impact.system_impact.integrity = cvss_data.get("integrityImpact", "None")
                tree.impact.system_impact.availability = cvss_data.get("availabilityImpact", "None")
            
            # Report Confidence (NVD doesn't explicitly have this in V3 standard in the same way, 
            # usually it's "Confirmed" if in NVD, but we can map "descriptions" existence or status)
            if cve_item.get("vulnStatus") == "Analyzed":
                tree.threat.report_confidence.level = "Confirmed"
            else:
                tree.threat.report_confidence.level = "Reasonable" # or Unknown

        except Exception as e:
            print(f"Error fetching NVD data: {e}")
            
        return tree
