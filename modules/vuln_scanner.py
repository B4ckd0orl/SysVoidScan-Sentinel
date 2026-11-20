"""
VulnScannerModule - Automated vulnerability scanning using Nuclei.

Runs Nuclei templates against the target, deduplicates findings,
and stores structured results with severity-based summaries.
"""

from typing import Any, Dict, List

from core.utils import print_info, print_good, print_warning, print_error
from tools.nuclei_tool import NucleiTool


class VulnScannerModule:

    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config
        self.nuclei = NucleiTool()

    def run(self, target: str, session=None):
        print_info(f"Running Nuclei vulnerability scan on {target}...")
        results: Dict[str, Any] = {
            "target": target,
            "findings": [],
            "summary": {},
        }

        if not self.nuclei.ensure_installed():
            print_warning("Nuclei is not installed. Skipping vulnerability scan.")
            self.scanner.scan_data["nuclei_findings"] = []
            self.scanner.scan_data["nuclei_summary"] = {}
            return results

        raw = self.nuclei.scan(target, session=session)
        if not raw:
            print_warning("Nuclei returned empty output.")
            self.scanner.scan_data["nuclei_findings"] = []
            self.scanner.scan_data["nuclei_summary"] = {}
            return results

        raw_findings = self.nuclei.parse_results(raw)
        normalized = self._normalize_findings(raw_findings)
        deduped = self._deduplicate(normalized)
        deduped.sort(key=lambda x: (self.SEVERITY_ORDER.get(x["severity"], 99), x["template_id"]))

        summary = self._build_summary(deduped)

        results["findings"] = deduped
        results["summary"] = summary
        results["total"] = len(deduped)

        self.scanner.scan_data["nuclei_findings"] = deduped
        self.scanner.scan_data["nuclei_summary"] = summary

        self._report_findings(deduped, summary)
        self._add_to_global_findings(deduped)

        print_good(f"Nuclei scan completed: {len(deduped)} finding(s)")
        return results

    def _normalize_findings(self, raw_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        normalized = []
        for item in raw_findings:
            entry = {
                "template_id": item.get("template_id", "unknown"),
                "name": item.get("name", ""),
                "severity": (item.get("severity") or "unknown").lower(),
                "matched_at": item.get("matched_at", ""),
                "type": item.get("type", ""),
                "description": item.get("description", ""),
                "reference": item.get("reference", []),
                "tags": item.get("tags", []),
                "curl_command": item.get("curl_command", ""),
            }
            normalized.append(entry)
        return normalized

    def _deduplicate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        deduped = []
        for f in findings:
            key = (f["template_id"], f["matched_at"], f["severity"])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(f)
        return deduped

    def _build_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        summary: Dict[str, List[str]] = {}
        for f in findings:
            sev = f["severity"]
            if sev not in summary:
                summary[sev] = []
            if f["template_id"] not in summary[sev]:
                summary[sev].append(f["template_id"])
        return summary

    def _report_findings(self, findings: List[Dict[str, Any]], summary: Dict[str, List[str]]):
        if not findings:
            print_info("No vulnerabilities found by Nuclei.")
            return

        for sev in sorted(summary.keys(), key=lambda s: self.SEVERITY_ORDER.get(s, 99)):
            count = len(summary[sev])
            templates = ", ".join(sorted(set(summary[sev])))
            print_info(f"  {sev.upper()}: {count} ({templates})")

        critical_high = [f for f in findings if f["severity"] in ("critical", "high")]
        if critical_high:
            print_warning(f"Found {len(critical_high)} critical/high severity finding(s)!")

    def _add_to_global_findings(self, findings: List[Dict[str, Any]]):
        for f in findings:
            severity = f["severity"].upper()
            label = f["template_id"]
            name = f["name"]
            matched = f["matched_at"]
            finding_str = f"[NUCLEI:{severity}] {label}"
            if name:
                finding_str += f" - {name}"
            if matched:
                finding_str += f" @ {matched}"
            self.scanner.findings.append(finding_str)
