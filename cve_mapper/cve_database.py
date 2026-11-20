import json
import logging
import os
import requests
import gzip
import shutil
from typing import Any, Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class CVEDatabase:
    """Local CVE database synchronized from NVD."""

    def __init__(self, db_path: str = "data/cve_database.json"):
        self.db_path = db_path
        self.cves: Dict[str, Dict] = {}
        self._load()

    def _load(self):
        """Load CVE database from disk."""
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, 'r') as f:
                    self.cves = json.load(f)
                logger.info(f"Loaded {len(self.cves)} CVEs from database")
            except Exception as e:
                logger.error(f"Failed to load CVE database: {e}")
                self.cves = {}

    def save(self):
        """Save CVE database to disk."""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            with open(self.db_path, 'w') as f:
                json.dump(self.cves, f, indent=2)
            logger.info(f"Saved {len(self.cves)} CVEs to database")
        except Exception as e:
            logger.error(f"Failed to save CVE database: {e}")

    def sync_nvd(self, years: List[int] = None) -> Dict[str, Any]:
        """Synchronize with NVD CVE feeds."""
        if years is None:
            current_year = datetime.now().year
            years = list(range(2002, current_year + 1))
        
        results = {"synced": 0, "errors": [], "years": []}
        
        for year in years:
            try:
                url = f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"
                logger.info(f"Downloading NVD feed for {year}...")
                
                response = requests.get(url, stream=True, timeout=60)
                if response.status_code != 200:
                    results["errors"].append(f"Year {year}: HTTP {response.status_code}")
                    continue
                
                # Decompress and parse
                with gzip.GzipFile(fileobj=response.raw) as gz:
                    data = json.load(gz)
                
                cve_items = data.get("CVE_Items", [])
                for item in cve_items:
                    cve_id = item["cve"]["CVE_data_meta"]["ID"]
                    self.cves[cve_id] = self._parse_cve_item(item)
                
                results["synced"] += len(cve_items)
                results["years"].append(year)
                logger.info(f"Synced {len(cve_items)} CVEs for {year}")
                
            except Exception as e:
                logger.error(f"Failed to sync year {year}: {e}")
                results["errors"].append(f"Year {year}: {e}")
        
        self.save()
        return results

    def _parse_cve_item(self, item: Dict) -> Dict:
        """Parse NVD CVE item into standardized format."""
        cve = item["cve"]
        cve_id = cve["CVE_data_meta"]["ID"]
        
        # Description
        desc_data = cve["description"]["description_data"]
        description = " ".join([d["value"] for d in desc_data if d["lang"] == "en"])
        
        # CVSS v3
        cvss_v3 = None
        if "impact" in item and "baseMetricV3" in item["impact"]:
            cvss_v3 = item["impact"]["baseMetricV3"]["cvssV3"]
        
        # CVSS v2
        cvss_v2 = None
        if "impact" in item and "baseMetricV2" in item["impact"]:
            cvss_v2 = item["impact"]["baseMetricV2"]["cvssV2"]
        
        # References
        references = []
        for ref in cve.get("references", {}).get("reference_data", []):
            references.append(ref["url"])
        
        # CWE
        cwes = []
        for problem in cve.get("problemtype", {}).get("problemtype_data", []):
            for desc in problem.get("description", []):
                cwes.append(desc["value"])
        
        # Affected products (CPE)
        affected = []
        if "configurations" in item:
            for config in item["configurations"]["nodes"]:
                affected.extend(self._extract_cpes(config))
        
        return {
            "id": cve_id,
            "description": description,
            "cvss_v3": cvss_v3,
            "cvss_v2": cvss_v2,
            "severity": cvss_v3["baseSeverity"] if cvss_v3 else (cvss_v2["baseSeverity"] if cvss_v2 else "UNKNOWN"),
            "score": cvss_v3["baseScore"] if cvss_v3 else (cvss_v2["baseScore"] if cvss_v2 else 0),
            "references": references,
            "cwes": cwes,
            "affected_products": affected,
            "published": cve.get("publishedDate"),
            "last_modified": cve.get("lastModifiedDate"),
        }

    def _extract_cpes(self, node: Dict) -> List[str]:
        """Extract CPEs from configuration node."""
        cpes = []
        for match in node.get("cpe_match", []):
            if match.get("vulnerable", False):
                cpes.append(match["cpe23Uri"])
        for child in node.get("children", []):
            cpes.extend(self._extract_cpes(child))
        return cpes

    def get_cve(self, cve_id: str) -> Optional[Dict]:
        """Get CVE by ID."""
        return self.cves.get(cve_id.upper())

    def search_cves(self, keyword: str = "", severity: str = "", min_score: float = 0, 
                    product: str = "", year: int = 0) -> List[Dict]:
        """Search CVEs with filters."""
        results = []
        keyword = keyword.lower()
        severity = severity.upper()
        product = product.lower()
        
        for cve in self.cves.values():
            if keyword and keyword not in cve["description"].lower():
                continue
            if severity and cve["severity"] != severity:
                continue
            if cve["score"] < min_score:
                continue
            if product and product not in " ".join(cve["affected_products"]).lower():
                continue
            if year and cve["published"] and not cve["published"].startswith(str(year)):
                continue
            results.append(cve)
        
        # Sort by score descending
        results.sort(key=lambda x: x["score"], reverse=True)
        return results

    def get_exploitable_cves(self, min_score: float = 7.0) -> List[Dict]:
        """Get CVEs with known exploits (high severity)."""
        return self.search_cves(min_score=min_score)


class ExploitMatcher:
    """Match CVEs to exploit modules."""

    # Mapping of CVE patterns to exploit modules
    CVE_TO_EXPLOIT = {
        # SQL Injection
        "CVE-2021-44228": "ssti",  # Log4Shell - actually deserialization
        "CVE-2021-45046": "ssti",
        "CVE-2021-4104": "ssti",
        
        # Remote Code Execution
        "CVE-2020-1472": "ad",  # Zerologon
        "CVE-2019-0708": "rdp",  # BlueKeep
        "CVE-2017-0144": "smb",  # EternalBlue
        "CVE-2021-34527": "ad",  # PrintNightmare
        
        # Web vulnerabilities
        "CVE-2021-41773": "path_traversal",
        "CVE-2021-42013": "path_traversal",
        "CVE-2022-22965": "ssti",  # Spring4Shell
        "CVE-2022-26134": "ssti",  # Confluence
        
        # Deserialization
        "CVE-2020-2551": "deserialization",  # WebLogic
        "CVE-2020-2555": "deserialization",  # WebLogic
        "CVE-2019-2725": "deserialization",  # WebLogic
        "CVE-2019-2729": "deserialization",  # WebLogic
        
        # Injection
        "CVE-2021-42392": "sqli",  # H2 Database
        "CVE-2022-22963": "ssti",  # Spring Cloud Function
        
        # File Upload
        "CVE-2022-22965": "file_upload",
        
        # SSRF
        "CVE-2021-21972": "ssrf",  # vCenter
        "CVE-2021-22005": "ssrf",
        
        # Authentication bypass
        "CVE-2020-1472": "ad",  # Zerologon
        "CVE-2020-0688": "ad",  # Exchange
        "CVE-2021-26855": "ssrf",  # ProxyLogon
        "CVE-2021-26857": "deserialization",
        "CVE-2021-26858": "file_upload",
        "CVE-2021-27065": "file_upload",
    }

    # CWE to exploit module mapping
    CWE_TO_EXPLOIT = {
        "CWE-89": "sqli",      # SQL Injection
        "CWE-79": "xss",       # XSS
        "CWE-22": "lfi",       # Path Traversal
        "CWE-94": "ssti",      # Code Injection (SSTI)
        "CWE-502": "deserialization",  # Deserialization
        "CWE-434": "file_upload",      # Unrestricted Upload
        "CWE-918": "ssrf",             # SSRF
        "CWE-78": "cmdi",              # OS Command Injection
        "CWE-611": "xxe",              # XXE
        "CWE-287": "auth_bypass",      # Auth Bypass
        "CWE-200": "info_disclosure",  # Info Disclosure
        "CWE-284": "auth_bypass",      # Improper Access Control
        "CWE-352": "csrf",             # CSRF
        "CWE-862": "auth_bypass",      # Missing Authorization
        "CWE-639": "idor",             # IDOR
        "CWE-400": "dos",              # DoS
        "CWE-501": "info_disclosure",  # Information Exposure
    }

    def __init__(self, cve_db: CVEDatabase):
        self.cve_db = cve_db

    def match_cve_to_exploit(self, cve_id: str) -> Optional[str]:
        """Get exploit module for a specific CVE."""
        cve_id = cve_id.upper()
        
        # Direct mapping
        if cve_id in self.CVE_TO_EXPLOIT:
            return self.CVE_TO_EXPLOIT[cve_id]
        
        # CWE-based mapping
        cve = self.cve_db.get_cve(cve_id)
        if cve and cve.get("cwes"):
            for cwe in cve["cwes"]:
                if cwe in self.CWE_TO_EXPLOIT:
                    return self.CWE_TO_EXPLOIT[cwe]
        
        # Keyword-based fallback
        if cve:
            desc = cve["description"].lower()
            if any(kw in desc for kw in ["sql injection", "sqli"]):
                return "sqli"
            if any(kw in desc for kw in ["cross-site scripting", "xss"]):
                return "xss"
            if any(kw in desc for kw in ["path traversal", "directory traversal", "lfi"]):
                return "lfi"
            if any(kw in desc for kw in ["server-side template injection", "ssti"]):
                return "ssti"
            if any(kw in desc for kw in ["deserialization", "object injection"]):
                return "deserialization"
            if any(kw in desc for kw in ["file upload", "unrestricted upload"]):
                return "file_upload"
            if any(kw in desc for kw in ["server-side request forgery", "ssrf"]):
                return "ssrf"
            if any(kw in desc for kw in ["command injection", "rce", "remote code execution"]):
                return "cmdi"
            if any(kw in desc for kw in ["xml external entity", "xxe"]):
                return "xxe"
        
        return None

    def get_exploit_module(self, cve_id: str) -> Optional[str]:
        """Get the exploit module class name."""
        exploit_type = self.match_cve_to_exploit(cve_id)
        if exploit_type:
            return f"{exploit_type.capitalize()}Exploiter" if exploit_type != "cmdi" else "CommandInjectionExploiter"
        return None


class AutoExploit:
    """Automatic exploitation of confirmed CVEs."""

    def __init__(self, cve_db: CVEDatabase, exploit_matcher: ExploitMatcher, orchestrator):
        self.cve_db = cve_db
        self.exploit_matcher = exploit_matcher
        self.orchestrator = orchestrator

    def auto_exploit_cves(self, target: str, session, cve_ids: List[str] = None, 
                          min_score: float = 7.0) -> Dict[str, Any]:
        """Automatically exploit confirmed CVEs."""
        results = {
            "target": target,
            "attempted": 0,
            "successful": 0,
            "failed": 0,
            "exploits": [],
        }
        
        if cve_ids is None:
            # Get all high-severity CVEs
            cves = self.cve_db.get_exploitable_cves(min_score)
            cve_ids = [cve["id"] for cve in cves]
        
        for cve_id in cve_ids:
            exploit_result = self._exploit_cve(cve_id, target, session)
            results["attempted"] += 1
            results["exploits"].append(exploit_result)
            
            if exploit_result.get("success"):
                results["successful"] += 1
            else:
                results["failed"] += 1
        
        return results

    def _exploit_cve(self, cve_id: str, target: str, session) -> Dict[str, Any]:
        """Exploit a specific CVE."""
        exploit_type = self.exploit_matcher.match_cve_to_exploit(cve_id)
        if not exploit_type:
            return {"cve": cve_id, "success": False, "error": "No exploit module found"}
        
        exploiter = self.orchestrator._exploiters.get(exploit_type)
        if not exploiter:
            return {"cve": cve_id, "success": False, "error": f"Exploiter {exploit_type} not available"}
        
        # Create a finding for the CVE
        cve = self.cve_db.get_cve(cve_id)
        finding = {
            "url": target,
            "type": exploit_type,
            "cve": cve_id,
            "description": cve["description"] if cve else "",
            "severity": cve["severity"] if cve else "high",
            "confirmed": True,
        }
        
        try:
            result = exploiter.run_exploitation(finding, target, session)
            return {
                "cve": cve_id,
                "exploit_type": exploit_type,
                "success": result.get("success", False),
                "result": result,
            }
        except Exception as e:
            return {"cve": cve_id, "success": False, "error": str(e)}