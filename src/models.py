from dataclasses import dataclass, field
from typing import List, Optional
from dataclasses_json import dataclass_json

@dataclass_json
@dataclass
class OrgSpecific:
    bug_bounty: bool = False
    incident_response: bool = False
    details: str = ""

@dataclass_json
@dataclass
class KnownEvidence:
    org_specific: OrgSpecific = field(default_factory=OrgSpecific)
    cisa_kev: bool = False
    cyber_threat_intelligence: bool = False
    details: str = ""

@dataclass_json
@dataclass
class WeaponizedExploit:
    metasploit: bool = False
    nuclei: bool = False
    vendor_dbs: bool = False
    details: str = ""

@dataclass_json
@dataclass
class POCExploit:
    exploit_db: bool = False
    github: bool = False
    vendor_dbs: bool = False
    details: str = ""

@dataclass_json
@dataclass
class EPSSScore:
    score: float = 0.0
    percentile: float = 0.0
    history: List[float] = field(default_factory=list)

@dataclass_json
@dataclass
class LikelihoodOfExploitation:
    known_evidence: KnownEvidence = field(default_factory=KnownEvidence)
    weaponized_exploit: WeaponizedExploit = field(default_factory=WeaponizedExploit)
    poc_exploit: POCExploit = field(default_factory=POCExploit)
    epss: EPSSScore = field(default_factory=EPSSScore)
    composite_prob: float = 0.0 # max(EPSS, KEV, LEV)

@dataclass_json
@dataclass
class ExploitabilityMetrics:
    attack_vector: str = "Unknown"
    attack_complexity: str = "Unknown"
    privileges_required: str = "Unknown"
    user_interaction: str = "Unknown"
    scope: str = "Unknown" # CVSS v3 scope

@dataclass_json
@dataclass
class ReportConfidence:
    level: str = "Unknown" # Not Defined, Unknown, Confirmed, Reasonable

@dataclass_json
@dataclass
class Threat:
    likelihood: LikelihoodOfExploitation = field(default_factory=LikelihoodOfExploitation)
    exploitability_metrics: ExploitabilityMetrics = field(default_factory=ExploitabilityMetrics)
    report_confidence: ReportConfidence = field(default_factory=ReportConfidence)

@dataclass_json
@dataclass
class SystemImpact:
    confidentiality: str = "None"
    integrity: str = "None"
    availability: str = "None"

@dataclass_json
@dataclass
class Impact:
    system_impact: SystemImpact = field(default_factory=SystemImpact)

@dataclass_json
@dataclass
class LEVScore:
    probability: float = 0.0
    details: str = "Not Calculated"

@dataclass_json
@dataclass
class SSVCDecision:
    decision: str = "Track"  # "Act", "Attend", "Track Closely", "Track"
    priority_score: int = 4  # 1 (Act) to 4 (Track)
    exploitation_status: str = "None"
    automatable: str = "No"
    technical_impact: str = "Low"

@dataclass_json
@dataclass
class VulnerabilityRiskTree:
    cve_id: str
    threat: Threat = field(default_factory=Threat)
    impact: Impact = field(default_factory=Impact)
    description: str = ""
    base_score: float = 0.0
    severity: str = "UNKNOWN"
    lev: LEVScore = field(default_factory=LEVScore)
    ssvc: SSVCDecision = field(default_factory=SSVCDecision)
    rbp_score: float = 0.0 # 0-100 score
    temporal_e: str = "NOT_DEFINED" # CVSS Temporal Metric E: [UNPROVEN, POC, FUNCTIONAL, HIGH]
    ai_analysis: str = ""
