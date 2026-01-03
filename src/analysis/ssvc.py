from ..models import VulnerabilityRiskTree, SSVCDecision

class SSVCAnalyzer:
    """
    Implements CISA Stakeholder-Specific Vulnerability Categorization (SSVC).
    Decision Tree:
    1. Exploitation: [Active, PoC, None]
    2. Automatable: [Yes, No]
    3. Technical Impact: [High, Low]
    
    Output: [Act, Attend, Track*, Track]
    """
    
    def analyze(self, tree: VulnerabilityRiskTree) -> VulnerabilityRiskTree:
        # Step 1: Determine Exploitation Status
        # Active: CISA KEV or Weaponized (Nuclei/Metasploit) or High EPSS (>10%)
        # PoC: GitHub/ExploitDB
        # None: No evidence
        
        exploitation = "None"
        ev = tree.threat.likelihood.known_evidence
        weap = tree.threat.likelihood.weaponized_exploit
        poc = tree.threat.likelihood.poc_exploit
        epss = tree.threat.likelihood.epss.score
        
        if ev.cisa_kev or weap.metasploit or weap.nuclei or epss >= 0.1:
            exploitation = "Active"
        elif poc.github or poc.exploit_db:
            exploitation = "PoC"
        else:
            exploitation = "None"
            
        # Step 2: Determine Automatable
        # We use a heuristic here properly later, but for now:
        # If Attack Vector is Network and Complexity is Low/None -> Automatable = Yes
        metrics = tree.threat.exploitability_metrics
        automatable = "No"
        if metrics.attack_vector == "NETWORK" and metrics.attack_complexity == "LOW" and metrics.user_interaction == "NONE":
            automatable = "Yes"

        # Step 3: Determine Technical Impact
        # If total Confidentiality/Integrity/Availability is High -> High
        impact_metrics = tree.impact.system_impact
        technical_impact = "Low"
        if (impact_metrics.confidentiality == "HIGH" or 
            impact_metrics.integrity == "HIGH" or 
            impact_metrics.availability == "HIGH"):
            technical_impact = "High"

        # Step 4: Decision Tree Logic
        decision = "Track"
        priority = 4
        
        if exploitation == "Active":
            # Active Exploitation Branch
            if technical_impact == "High":
                decision = "Act"
                priority = 1
            else:
                decision = "Attend"
                priority = 2
                
        elif exploitation == "PoC":
            # PoC Branch
            if automatable == "Yes" and technical_impact == "High":
                decision = "Attend"
                priority = 2
            else:
                decision = "Track Closely"
                priority = 3
        else:
            # None Branch
            if automatable == "Yes" and technical_impact == "High":
                decision = "Track Closely"
                priority = 3
            else:
                decision = "Track"
                priority = 4

        # Update Tree
        tree.ssvc.decision = decision
        tree.ssvc.priority_score = priority
        tree.ssvc.exploitation_status = exploitation
        tree.ssvc.automatable = automatable
        tree.ssvc.technical_impact = technical_impact
        
        return tree
