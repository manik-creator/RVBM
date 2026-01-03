import json
import os
import sys
from src.agent import RiskAnalysisAgent

# List of diverse CVEs for testing
TEST_CVES = [
    "CVE-2021-44228",  # Log4Shell (Critical, KEV, High EPSS)
    "CVE-2023-23397",  # Outlook EoP (Critical, KEV)
    "CVE-2017-0144",   # EternalBlue (Critical, KEV)
    "CVE-2024-21413",  # Outlook MonikerLink (Critical, High EPSS)
    "CVE-2024-38063",  # Windows TCP/IP RCE (Critical, High EPSS)
    "CVE-2021-34473",  # ProxyShell (Critical, KEV)
    "CVE-2014-0160",   # Heartbleed (High impact, High LEV, low current EPSS?)
    "CVE-2022-22965",  # Spring4Shell (Critical, High EPSS)
    "CVE-2020-1472",   # Zerologon (Critical, KEV)
    "CVE-2023-34362",  # MOVEit (Critical, KEV)
    "CVE-1999-0524",   # Info-level Legacy (Low impact, Low likelihood)
    "CVE-2024-23113",  # Fortinet RCE (Critical, High EPSS)
    "CVE-2021-31166",  # HTTP.sys RCE (Critical, No KEV?)
    "CVE-2022-30190",  # Follina (High, KEV)
    "CVE-2024-21406",  # Recent low-risk / low-prob item
]

def run_bulk_test():
    agent = RiskAnalysisAgent()
    # Mock AI analyst to save tokens and time for bulk testing
    class MockAI:
        def run(self, data): return "SKIPPED FOR BULK TEST"
    agent.ai_agent = MockAI()
    
    results = []
    
    print(f"{'CVE_ID':<15} | {'Score':<6} | {'Priority':<12} | {'Prob':<6} | {'KEV':<5} | {'LEV':<6}")
    print("-" * 70)
    
    for cve in TEST_CVES:
        try:
            tree = agent.analyze(cve)
            priority = f"{tree.ssvc.decision} ({tree.ssvc.priority_score})"
            prob = tree.threat.likelihood.composite_prob
            kev = tree.threat.likelihood.known_evidence.cisa_kev
            lev = tree.lev.probability
            
            print(f"{cve:<15} | {tree.rbp_score:<6.1f} | {priority:<12} | {prob:<6.2f} | {str(kev):<5} | {lev:<6.2f}")
            
            results.append({
                "cve_id": cve,
                "rbp_score": tree.rbp_score,
                "priority": tree.ssvc.decision,
                "priority_score": tree.ssvc.priority_score,
                "comp_prob": prob,
                "kev": kev,
                "lev": lev
            })
        except Exception as e:
            print(f"{cve:<15} | ERROR: {e}")
            
    # Save results to a file for analysis
    with open("rbp_test_results.json", "w") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    run_bulk_test()
