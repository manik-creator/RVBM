import argparse
import sys
import json
from src.agent import RiskAnalysisAgent
from src.models import VulnerabilityRiskTree
from rich.console import Console
from rich.tree import Tree
from rich.panel import Panel
from rich.text import Text

console = Console()

def display_risk_tree(risk: VulnerabilityRiskTree):
    """
    Visualizes the VulnerabilityRiskTree using Rich.
    """
    root = Tree(f"[bold red]{risk.cve_id}[/bold red] - {risk.severity} (RBP Score: {risk.rbp_score:.1f}/100)")
    
    if risk.description:
        root.add(f"[italic]{risk.description[:100]}...[/italic]")

    # Threat Branch
    threat_node = root.add("[bold]Threat[/bold]")
    
    # Likelihood
    likelihood = risk.threat.likelihood
    like_node = threat_node.add("Likelihood of Exploitation")
    
    # Known Evidence
    evidence = likelihood.known_evidence
    ev_node = like_node.add("Known Evidence/Activity")
    
    # Org specific
    org = evidence.org_specific
    org_color = "red" if (org.bug_bounty or org.incident_response) else "green"
    ev_node.add(f"[{org_color}]Org Specific: Bug Bounty={org.bug_bounty}, IR={org.incident_response}[/{org_color}]")
    
    # In Wild
    wild_color = "red" if (evidence.cisa_kev or evidence.cyber_threat_intelligence) else "green" 
    ev_node.add(f"[{wild_color}]In Wild: CISA KEV={evidence.cisa_kev}[/{wild_color}]")
    
    # Weaponized
    weap = likelihood.weaponized_exploit
    weap_color = "orange1" if (weap.metasploit or weap.nuclei) else "green"
    like_node.add(f"[{weap_color}]Weaponized: Metasploit={weap.metasploit}, Nuclei={weap.nuclei}[/{weap_color}]")
    
    # POC
    poc = likelihood.poc_exploit
    poc_color = "yellow" if (poc.github or poc.exploit_db) else "green"
    like_node.add(f"[{poc_color}]POC: GitHub={poc.github}, ExploitDB={poc.exploit_db}[/{poc_color}]")

    # EPSS
    epss_color = "red" if likelihood.epss.score > 0.1 else "green"
    like_node.add(f"[{epss_color}]EPSS: {likelihood.epss.score:.4f} (Composite Prob: {likelihood.composite_prob:.2%})[/{epss_color}]")
    
    # SSVC
    ssvc = risk.ssvc
    ssvc_node = root.add("[bold]SSVC Decision[/bold]")
    ssvc_node.add(f"Decision: [bold cyan]{ssvc.decision}[/bold cyan] (Priority: {ssvc.priority_score})")
    ssvc_node.add(f"Exploitation: {ssvc.exploitation_status}")
    ssvc_node.add(f"Automatable: {ssvc.automatable}")
    ssvc_node.add(f"Technical Impact: {ssvc.technical_impact}")

    # Exploitability Metrics
    metrics = risk.threat.exploitability_metrics
    met_node = threat_node.add("Exploitability Metrics")
    met_node.add(f"Attack Vector: {metrics.attack_vector}")
    met_node.add(f"Complexity: {metrics.attack_complexity}")
    met_node.add(f"Privileges: {metrics.privileges_required}")
    met_node.add(f"Interaction: {metrics.user_interaction}")
    
    # Impact Branch
    impact_node = root.add("[bold]Impact[/bold]")
    sys_impact = risk.impact.system_impact
    impact_node.add(f"Confidentiality: {sys_impact.confidentiality}")
    impact_node.add(f"Integrity: {sys_impact.integrity}")
    impact_node.add(f"Availability: {sys_impact.availability}")

    console.print(Panel(root, title="Vulnerability Risk Analysis", border_style="blue"))

def main():
    parser = argparse.ArgumentParser(description="Agentic CVE Risk Analysis Tool")
    parser.add_argument("cve_id", nargs='?', help="The CVE ID to analyze (e.g., CVE-2021-44228)", default="CVE-2021-44228")
    parser.add_argument("--json", action="store_true", help="Output raw JSON",default=False)
    args = parser.parse_args()

    agent = RiskAnalysisAgent()
    risk_tree = agent.analyze(args.cve_id)
    
    if args.json:
        print(risk_tree.to_json(indent=2))
    else:
        display_risk_tree(risk_tree)
        
        # Recommendation Logic
        rec_color = "green"
        rec_text = "Standard remediation."
        
        if risk_tree.threat.likelihood.known_evidence.cisa_kev:
            rec_color = "bold red blink"
            rec_text = "CRITICAL: ACTIVE EXPLOITATION DETECTED (CISA KEV). PATCH IMMEDIATELY."
        elif risk_tree.severity == "CRITICAL" or risk_tree.base_score >= 9.0:
            rec_color = "bold red"
            rec_text = "CRITICAL SEVERITY. Patch within 24-48 hours."
        elif risk_tree.severity == "HIGH":
            rec_color = "orange1"
            rec_text = "HIGH SEVERITY. Patch within 7 days."
            
        console.print(Panel(f"[{rec_color}]{rec_text}[/{rec_color}]", title="Recommendation", border_style="red"))

        # AI Analysis Display
        if risk_tree.ai_analysis:
            console.print(Panel(Text(risk_tree.ai_analysis), title="AI Analyst Report (Groq/Llama3)", border_style="magenta"))



if __name__ == "__main__":
    main()
