from .models import VulnerabilityRiskTree
from .collectors.base import BaseCollector
from .collectors.cisa import CisaKevCollector
from .collectors.epss import EPSSCollector
from .collectors.nvd import NVDCollector
from .collectors.threat_intel import ThreatIntelCollector, LocalContextCollector
from .collectors.lev import LEVCollector
from .analysis.ssvc import SSVCAnalyzer
from .analysis.rbp_planner import RBPPlanner
from typing import List

from .ai_agent import AXRiskAgent

class RiskAnalysisAgent:
    def __init__(self):
        self.collectors: List[BaseCollector] = [
            LocalContextCollector(), # Local context first
            CisaKevCollector(),
            EPSSCollector(),
            NVDCollector(),
            ThreatIntelCollector(),
            LEVCollector() # Added LEV
        ]
        self.ssvc_analyzer = SSVCAnalyzer() # Added SSVC
        self.rbp_planner = RBPPlanner()
        # Initialize AI Agent
        self.ai_agent = AXRiskAgent()

    def analyze(self, cve_id: str) -> VulnerabilityRiskTree:
        # Initialize empty tree
        tree = VulnerabilityRiskTree(cve_id=cve_id)
        
        # 1. Run Collectors
        print(f"[*] Starting analysis for {cve_id}...")
        for collector in self.collectors:
            try:
                name = collector.__class__.__name__
                print(f"  - Running {name}...")
                tree = collector.collect(cve_id, tree)
            except Exception as e:
                print(f"  [!] Error in {name}: {e}")
        
        # 2. Final Severity/Risk Calculation
        if tree.severity == "UNKNOWN":
             if tree.base_score >= 9.0: tree.severity = "CRITICAL"
             elif tree.base_score >= 7.0: tree.severity = "HIGH"
             elif tree.base_score >= 4.0: tree.severity = "MEDIUM"
             else: tree.severity = "LOW"
        
        # 3. Run SSVC Analyzer
        try:
            print("  - Running SSVC Analyzer...")
            tree = self.ssvc_analyzer.analyze(tree)
        except Exception as e:
            print(f"  [!] Error in SSVC Analyzer: {e}")

        # 4. Run RBP Planner & Scoring
        try:
            print("  - Running RBP Planner...")
            tree = self.rbp_planner.analyze(tree)
        except Exception as e:
            print(f"  [!] Error in RBP Planner: {e}")

        # 5. Run AI Analysis
        print("  - Running AI Analyst (Groq Llama-3)...")
        try:
            tree_json = tree.to_json()
            tree.ai_analysis = self.ai_agent.run(tree_json)
        except Exception as e:
            print(f"  [!] Error in AI Analyst: {e}")
            tree.ai_analysis = f"AI Analysis Failed: {str(e)}"

        return tree
