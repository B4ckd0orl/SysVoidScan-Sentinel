from typing import Dict, Optional
from dataclasses import dataclass

@dataclass
class CVSSScore:
    """CVSS v3.1 score calculator."""
    score: float = 0.0
    severity: str = "info"
    vector: str = ""
    
    attack_vector: str = "N"
    attack_complexity: str = "L"
    privileges_required: str = "N"
    user_interaction: str = "N"
    scope: str = "U"
    confidentiality: str = "N"
    integrity: str = "N"
    availability: str = "N"
    
    def calculate(self):
        """Calculate CVSS score from vector components."""
        av_scores = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
        ac_scores = {"L": 0.77, "H": 0.44}
        pr_scores_u = {"N": 0.85, "L": 0.62, "H": 0.27}
        pr_scores_c = {"N": 0.85, "L": 0.68, "H": 0.50}
        ui_scores = {"N": 0.85, "R": 0.62}
        cia_scores = {"N": 0.00, "L": 0.22, "H": 0.56}
        
        av = av_scores.get(self.attack_vector, 0.85)
        ac = ac_scores.get(self.attack_complexity, 0.77)
        pr = (pr_scores_c if self.scope == "C" else pr_scores_u).get(self.privileges_required, 0.85)
        ui = ui_scores.get(self.user_interaction, 0.85)
        c = cia_scores.get(self.confidentiality, 0.0)
        i = cia_scores.get(self.integrity, 0.0)
        a = cia_scores.get(self.availability, 0.0)
        
        if self.scope == "U":
            impact = 6.42 * ((1 - (1 - c) * (1 - i) * (1 - a)))
        else:
            impact = 7.52 * ((1 - (1 - c) * (1 - i) * (1 - a)))
        
        exploitability = 8.22 * av * ac * pr * ui
        
        if impact <= 0:
            self.score = 0.0
        elif self.scope == "U":
            self.score = min(impact + exploitability, 10.0)
        else:
            self.score = min(1.08 * (impact + exploitability), 10.0)
        
        self.score = round(self.score, 1)
        self._calculate_severity()
        self.vector = f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}/PR:{self.privileges_required}/UI:{self.user_interaction}/S:{self.scope}/C:{self.confidentiality}/I:{self.integrity}/A:{self.availability}"
    
    def _calculate_severity(self):
        if self.score >= 9.0:
            self.severity = "critical"
        elif self.score >= 7.0:
            self.severity = "high"
        elif self.score >= 4.0:
            self.severity = "medium"
        elif self.score >= 0.1:
            self.severity = "low"
        else:
            self.severity = "info"
    
    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "severity": self.severity,
            "vector": self.vector,
            "components": {
                "AV": self.attack_vector,
                "AC": self.attack_complexity,
                "PR": self.privileges_required,
                "UI": self.user_interaction,
                "S": self.scope,
                "C": self.confidentiality,
                "I": self.integrity,
                "A": self.availability,
            }
        }

class CVSSCalculator:
    """Calculate CVSS scores for different vulnerability types."""
    
    PROFILES = {
        "sqli": {"attack_vector": "N", "attack_complexity": "L", "privileges_required": "N", "user_interaction": "N", "scope": "C", "confidentiality": "H", "integrity": "H", "availability": "H"},
        "xss_reflected": {"attack_vector": "N", "attack_complexity": "L", "privileges_required": "N", "user_interaction": "R", "scope": "U", "confidentiality": "L", "integrity": "L", "availability": "N"},
        "xss_stored": {"attack_vector": "N", "attack_complexity": "L", "privileges_required": "N", "user_interaction": "R", "scope": "C", "confidentiality": "H", "integrity": "H", "availability": "H"},
        "ssrf": {"attack_vector": "N", "attack_complexity": "L", "privileges_required": "N", "user_interaction": "N", "scope": "U", "confidentiality": "H", "integrity": "L", "availability": "N"},
        "cmdi": {"attack_vector": "N", "attack_complexity": "L", "privileges_required": "N", "user_interaction": "N", "scope": "C", "confidentiality": "H", "integrity": "H", "availability": "H"},
        "lfi": {"attack_vector": "N", "attack_complexity": "L", "privileges_required": "N", "user_interaction": "N", "scope": "U", "confidentiality": "H", "integrity": "N", "availability": "N"},
        "ssti": {"attack_vector": "N", "attack_complexity": "L", "privileges_required": "N", "user_interaction": "N", "scope": "C", "confidentiality": "H", "integrity": "H", "availability": "H"},
        "xxe": {"attack_vector": "N", "attack_complexity": "L", "privileges_required": "N", "user_interaction": "N", "scope": "U", "confidentiality": "H", "integrity": "L", "availability": "N"},
        "file_upload": {"attack_vector": "N", "attack_complexity": "L", "privileges_required": "N", "user_interaction": "N", "scope": "C", "confidentiality": "H", "integrity": "H", "availability": "H"},
        "jwt_bypass": {"attack_vector": "N", "attack_complexity": "L", "privileges_required": "N", "user_interaction": "N", "scope": "U", "confidentiality": "H", "integrity": "H", "availability": "N"},
        "idor": {"attack_vector": "N", "attack_complexity": "L", "privileges_required": "L", "user_interaction": "N", "scope": "U", "confidentiality": "H", "integrity": "N", "availability": "N"},
        "csrf": {"attack_vector": "N", "attack_complexity": "L", "privileges_required": "N", "user_interaction": "R", "scope": "U", "confidentiality": "N", "integrity": "L", "availability": "N"},
        "open_redirect": {"attack_vector": "N", "attack_complexity": "L", "privileges_required": "N", "user_interaction": "R", "scope": "U", "confidentiality": "L", "integrity": "L", "availability": "N"},
        "crlf": {"attack_vector": "N", "attack_complexity": "L", "privileges_required": "N", "user_interaction": "R", "scope": "U", "confidentiality": "L", "integrity": "L", "availability": "N"},
        "info_disclosure": {"attack_vector": "N", "attack_complexity": "L", "privileges_required": "N", "user_interaction": "N", "scope": "U", "confidentiality": "L", "integrity": "N", "availability": "N"},
    }
    
    def calculate_for_finding(self, finding_type: str, custom_params: dict = None) -> CVSSScore:
        """Calculate CVSS score for a finding type."""
        profile = self.PROFILES.get(finding_type, self.PROFILES["info_disclosure"])
        
        if custom_params:
            profile.update(custom_params)
        
        cvss = CVSSScore(
            attack_vector=profile.get("attack_vector", "N"),
            attack_complexity=profile.get("attack_complexity", "L"),
            privileges_required=profile.get("privileges_required", "N"),
            user_interaction=profile.get("user_interaction", "N"),
            scope=profile.get("scope", "U"),
            confidentiality=profile.get("confidentiality", "N"),
            integrity=profile.get("integrity", "N"),
            availability=profile.get("availability", "N"),
        )
        
        cvss.calculate()
        return cvss
    
    def calculate_from_response(self, finding_type: str, response_status: int, has_auth: bool) -> CVSSScore:
        """Calculate CVSS based on context."""
        custom = {}
        
        if has_auth:
            custom["privileges_required"] = "L"
        
        if response_status == 200:
            custom["attack_complexity"] = "L"
        
        return self.calculate_for_finding(finding_type, custom)
