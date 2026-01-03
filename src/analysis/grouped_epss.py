from typing import List
from functools import reduce

class GroupedEPSS:
    """
    Calculates the 'Grouped EPSS' score for a set of vulnerabilities (e.g., on a single asset or group of assets).
    
    Formula:
    P(at least one exploit) = 1 - product(1 - P_i) for all i in group.
    
    This assumes independence between exploit events, which is the standard EPSS guidance 
    unless specific correlation data is available.
    """
    
    @staticmethod
    def calculate(epss_scores: List[float]) -> float:
        if not epss_scores:
            return 0.0
            
        # P(no exploits) = (1 - P1) * (1 - P2) * ...
        prob_no_exploit = reduce(lambda x, y: x * (1 - y), epss_scores, 1.0)
        
        # P(at least one) = 1 - P(no exploits)
        prob_at_least_one = 1.0 - prob_no_exploit
        
        return float(prob_at_least_one)
