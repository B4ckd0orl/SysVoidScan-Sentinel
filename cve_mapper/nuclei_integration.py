import json
import logging
import subprocess
import os
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class NucleiIntegration:
    """Integration with Nuclei vulnerability scanner for CVE exploitation."""

    def __init__(self, templates_dir: str = None):
        self.templates_dir = templates_dir or os.path.expanduser("~/nuclei-templates")
        self.exploit_templates = []

    def scan_target(self, target: str, severity: str = "critical,high", 
                    tags: List[str] = None) -> List[Dict]:
        """Run Nuclei scan on target."""
        try:
            cmd = [
                "nuclei", "-u", target,
                "-severity", severity,
                "-json", "-silent",
                "-timeout", "10",
                "-rate-limit", "50",
            ]
            
            if tags:
                cmd.extend(["-tags", ",".join(tags)])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            findings = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        finding = json.loads(line)
                        findings.append(self._parse_nuclei_finding(finding))
                    except Exception as e:
                        logging.exception("Operation failed")
        
            return findings
        except Exception as e:
            logger.error(f"Nuclei scan failed: {e}")
            return []

    def _parse_nuclei_finding(self, finding: Dict) -> Dict:
        """Parse Nuclei finding into standardized format."""
        return {
            "template_id": finding.get("template-id", ""),
            "name": finding.get("info", {}).get("name", ""),
            "severity": finding.get("info", {}).get("severity", "info"),
            "description": finding.get("info", {}).get("description", ""),
            "matched_at": finding.get("matched-at", ""),
            "extracted_results": finding.get("extracted-results", []),
            "curl_command": finding.get("curl-command", ""),
            "tags": finding.get("info", {}).get("tags", []),
            "references": finding.get("info", {}).get("reference", []),
            "cve_ids": self._extract_cves(finding.get("info", {}).get("reference", [])),
            "cvss_score": self._extract_cvss(finding.get("info", {})),
        }

    def _extract_cves(self, references: List[str]) -> List[str]:
        """Extract CVE IDs from references."""
        cves = []
        for ref in references:
            matches = re.findall(r'CVE-\d{4}-\d{4,}', ref, re.IGNORECASE)
            cves.extend(matches)
        return list(set(cves))

    def _extract_cvss(self, info: Dict) -> Optional[float]:
        """Extract CVSS score from template info."""
        if "classification" in info:
            classif = info["classification"]
            if "cvss-score" in classif:
                try:
                    return float(classif["cvss-score"])
                except Exception as e:
                    logging.exception("Operation failed")
            if "cvss-metrics" in classif:
                metrics = classif["cvss-metrics"]
                if metrics.startswith("CVSS:3."):
                    # Parse CVSS vector
                    try:
                        parts = metrics.split('/')
                        for part in parts:
                            if part.startswith('AV:') or part.startswith('AC:'):
                                pass
                    except Exception as e:
                        logging.exception("Operation failed")
            return None

    def get_exploit_templates(self) -> List[Dict]:
        """Get templates that have exploit capabilities."""
        if self.exploit_templates:
            return self.exploit_templates
        
        exploit_tags = ["exploit", "rce", "injection", "sqli", "xss", "ssrf", "lfi", "rfi", "ssti", "xxe", "deserialization"]
        
        try:
            cmd = ["nuclei", "-tl", "-tags", ",".join(exploit_tags), "-json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        template = json.loads(line)
                        self.exploit_templates.append({
                            "id": template.get("id", ""),
                            "name": template.get("info", {}).get("name", ""),
                            "severity": template.get("info", {}).get("severity", "info"),
                            "tags": template.get("info", {}).get("tags", []),
                            "description": template.get("info", {}).get("description", ""),
                        })
                    except Exception as e:
                        logging.exception("Operation failed")
        except Exception as e:
            logger.error(f"Failed to get exploit templates: {e}")
        
        return self.exploit_templates

    def run_exploit_template(self, target: str, template_id: str) -> Dict:
        """Run a specific exploit template."""
        try:
            cmd = [
                "nuclei", "-u", target,
                "-t", template_id,
                "-json", "-silent",
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            results = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        results.append(json.loads(line))
                    except Exception as e:
                        logging.exception("Operation failed")
            
            return {"success": len(results) > 0, "results": results}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def generate_exploit_template(self, cve_id: str, vuln_details: Dict) -> str:
        """Generate Nuclei exploit template for a CVE."""
        template = f"""id: {cve_id.lower()}-exploit

info:
  name: {vuln_details.get('name', cve_id)} Exploit
  author: sysvoidscan
  severity: {vuln_details.get('severity', 'high')}
  description: {vuln_details.get('description', 'Auto-generated exploit template')}
  reference:
    - https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}
  classification:
    cve-id: {cve_id}
    cvss-score: {vuln_details.get('cvss_score', '0.0')}
  tags: exploit,{vuln_details.get('type', 'injection')}

http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}/vulnerable-endpoint"
    
    matchers:
      - type: word
        words:
          - "vulnerable"
        condition: or
"""
        return template