from ..models import VulnerabilityRiskTree

class RBPPlanner:
    """
    Orchestrates the final Risk Based Prioritization (RBP) metrics.
    Calculates:
    1. Composite Exploitation Probability: max(EPSS, KEV, LEV)
    2. CVSS Temporal Metric E (Exploit Code Maturity)
    3. Unified RBP Score (0-100)
    """

    def analyze(self, tree: VulnerabilityRiskTree) -> VulnerabilityRiskTree:
        # 1. Calculate Composite Probability
        # KEV flag is essentially probability 1.0 (Known Exploited)
        kev_val = 1.0 if tree.threat.likelihood.known_evidence.cisa_kev else 0.0
        epss_val = tree.threat.likelihood.epss.score
        lev_val = tree.lev.probability
        
        composite_prob = max(epss_val, kev_val, lev_val)
        tree.threat.likelihood.composite_prob = composite_prob

        # 2. Determine CVSS Temporal Metric E
        # [UNPROVEN, POC, FUNCTIONAL, HIGH]
        # HIGH: CISA KEV or Weaponized (Metasploit)
        # FUNCTIONAL: Nuclei or High EPSS (>0.1)
        # POC: GitHub/ExploitDB
        # UNPROVEN: Default
        
        weap = tree.threat.likelihood.weaponized_exploit
        poc = tree.threat.likelihood.poc_exploit
        
        if tree.threat.likelihood.known_evidence.cisa_kev or weap.metasploit:
            tree.temporal_e = "HIGH"
        elif weap.nuclei or epss_val >= 0.1:
            tree.temporal_e = "FUNCTIONAL"
        elif poc.github or poc.exploit_db:
            tree.temporal_e = "POC"
        else:
            tree.temporal_e = "UNPROVEN"

        # 3. Calculate Unified RBP Score (0-100)
        # Formula: BaseScore * CompositeProb * 10
        # This creates the "wedge" where even a 10.0 CVE with 0.1 prob only gets a 10/100.
        # It requires high impact AND high probability to hit the top tiers.
        
        tree.rbp_score = tree.base_score * composite_prob * 10
        
        return tree
