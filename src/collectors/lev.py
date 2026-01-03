from .base import BaseCollector
from ..models import VulnerabilityRiskTree, LEVScore

class LEVCollector(BaseCollector):
    """
    Estimates NIST Likely Exploited Vulnerabilities (LEV).
    
    NOTE: Real LEV requires historical EPSS data (time series) to calculate:
    LEV = 1 - product(1 - EPSS_t) over time.
    
    Since we don't have a historical database in this demo app, we will use a 
    PROJECTION HEURISTIC:
    - If EPSS is High (>0.2), we assume it has been high for some time.
    - We project LEV as slightly higher than current EPSS to simulate time-exposure.
    """

    def collect(self, cve_id: str, tree: VulnerabilityRiskTree) -> VulnerabilityRiskTree:
        history = tree.threat.likelihood.epss.history
        current_epss = tree.threat.likelihood.epss.score
        
        if not history:
            # Fallback to simple heuristic if history is unavailable
            lev_prob = current_epss + (current_epss * 0.05)
            tree.lev.details = f"Heuristic (No History): {lev_prob:.4f}"
        else:
            # According to the Guide: LEV = 1 - product(1 - EPSS_i * window_fraction)
            # Since EPSS is a 30-day probability, daily window_fraction = 1/30.
            # This compounds the daily probability of exploitation over the history period.
            
            prob_no_exploit = 1.0
            for score in history:
                prob_no_exploit *= (1.0 - (score / 30.0))
            
            lev_prob = 1.0 - prob_no_exploit
            tree.lev.details = f"Calculated from {len(history)} days of EPSS history."
            
        if lev_prob > 0.9999:
            lev_prob = 0.9999
            
        tree.lev.probability = float(lev_prob)
        return tree
