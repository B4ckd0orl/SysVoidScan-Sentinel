"""
PortscanModule - Port scanning and service detection using Nmap.

Performs basic port scanning followed by NSE vulnerability scripts
against discovered open ports.
"""

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from core.utils import print_info, print_good, print_warning, print_error, print_vuln
from tools.nmap_tool import NmapTool
import logging


class PortscanModule:

    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config
        self.nmap = NmapTool()

    def run(self, target: str, session=None):
        print_info(f"Running port scan on {target}...")
        results: Dict[str, Any] = {
            "target": target,
            "host_info": {},
            "ports": [],
            "nse": {},
        }

        if not self.nmap.ensure_installed():
            print_warning("Nmap is not installed. Skipping port scan.")
            self.scanner.scan_data["nmap"] = results
            return results

        host = urlparse(target).hostname or target
        if not host:
            print_error("Could not extract host from target URL.")
            return results

        print_info(f"Running Nmap service scan on {host}...")
        xml_output = self.nmap.scan_basic(host)
        if not xml_output:
            print_error("Nmap returned empty output.")
            return results

        host_info, ports = self.nmap.parse_xml(xml_output, include_scripts=False)
        open_ports = [p for p in ports if p["state"] == "open"]

        results["host_info"] = host_info
        results["ports"] = ports
        results["open_port_count"] = len(open_ports)

        if open_ports:
            print_good(f"Found {len(open_ports)} open port(s)")
            for p in open_ports:
                version_parts = [p.get("product", ""), p.get("version", "")]
                version_str = " ".join(v for v in version_parts if v).strip()
                print_info(
                    f"  {p['port']}/{p['protocol']} - {p['service']}"
                    + (f" ({version_str})" if version_str else "")
                )
                self.scanner.findings.append(
                    f"[PORT] {host}:{p['port']}/{p['protocol']} {p['service']}"
                    + (f" ({version_str})" if version_str else "")
                )
        else:
            print_info("No open ports found.")

        if open_ports:
            port_spec = ",".join(str(p["port"]) for p in open_ports)
            print_info(f"Running NSE vulnerability scripts on {len(open_ports)} port(s)...")
            try:
                nse_xml = self.nmap.scan_nse(host, port_spec, session=session)
                if nse_xml:
                    _, nse_ports = self.nmap.parse_xml(nse_xml, include_scripts=True)
                    nse_results = []
                    for p in nse_ports:
                        for script in p.get("scripts", []):
                            output = script.get("output", "")
                            if not output:
                                continue
                            entry = {
                                "port": p["port"],
                                "protocol": p["protocol"],
                                "service": p["service"],
                                "script_id": script["id"],
                                "output": output[:2000],
                            }
                            nse_results.append(entry)

                            output_lower = output.lower()
                            interesting = any(
                                ind in output_lower
                                for ind in ("vulnerable", "cve-", "exploit", "state: vulnerable", "backdoor")
                            )
                            if interesting:
                                first_line = output.splitlines()[0][:160]
                                print_vuln(
                                    f"NSE {script['id']} on port {p['port']}: {first_line}"
                                )
                                self.scanner.findings.append(
                                    f"[NMAP:NSE] {host}:{p['port']}/{p['protocol']} "
                                    f"{script['id']} - {first_line}"
                                )

                    results["nse"] = {
                        "executed": True,
                        "results": nse_results,
                    }
                    if nse_results:
                        print_good(f"NSE scripts returned {len(nse_results)} result(s)")
                    else:
                        print_info("NSE scripts completed with no notable findings.")
                else:
                    results["nse"] = {"executed": False, "reason": "empty output"}
            except Exception as e:
                logging.exception("portscan.py: operation failed")
                print_error(f"NSE scan failed: {e}")
                results["nse"] = {"executed": False, "error": str(e)}
        else:
            results["nse"] = {"executed": False, "reason": "no open ports"}

        self.scanner.scan_data["nmap"] = results
        print_good("Port scan completed.")
        return results
