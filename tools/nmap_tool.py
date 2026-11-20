import json
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple

from tools.base import ToolWrapper


class NmapTool(ToolWrapper):

    name = "nmap"
    binary = "nmap"
    install_cmd = ["sudo", "apt-get", "install", "-y", "nmap"]

    def scan_basic(self, host: str) -> str:
        result = self.run(["-sV", "-oX", "-", host], timeout=300)
        return result.stdout

    def scan_nse(self, host: str, ports: str, session=None) -> str:
        cmd_args = ["-sV", "--script", "default,vuln,safe", "-p", ports, "-oX", "-", host]
        result = self.run(cmd_args, timeout=600)
        return result.stdout

    def parse_xml(self, xml_output: str, include_scripts: bool = False) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        host_info: Dict[str, Any] = {}
        ports: List[Dict[str, Any]] = []

        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError:
            return host_info, ports

        host_el = root.find(".//host")
        if host_el is None:
            return host_info, ports

        addr_el = host_el.find("address")
        if addr_el is not None:
            host_info["ip"] = addr_el.get("addr", "")
            host_info["addr_type"] = addr_el.get("addrtype", "")

        hostname_el = host_el.find(".//hostname")
        if hostname_el is not None:
            host_info["hostname"] = hostname_el.get("name", "")

        ports_el = host_el.find("ports")
        if ports_el is None:
            return host_info, ports

        for port_el in ports_el.findall("port"):
            port_data: Dict[str, Any] = {
                "port": int(port_el.get("portid", 0)),
                "protocol": port_el.get("protocol", "tcp"),
                "state": "",
                "service": "",
                "version": "",
                "product": "",
                "scripts": [],
            }

            state_el = port_el.find("state")
            if state_el is not None:
                port_data["state"] = state_el.get("state", "")

            svc_el = port_el.find("service")
            if svc_el is not None:
                port_data["service"] = svc_el.get("name", "")
                port_data["product"] = svc_el.get("product", "")
                port_data["version"] = svc_el.get("version", "")

            if include_scripts:
                for script_el in port_el.findall("script"):
                    port_data["scripts"].append({
                        "id": script_el.get("id", ""),
                        "output": script_el.get("output", ""),
                    })

            ports.append(port_data)

        return host_info, ports

    def run(self, cmd_args: List[str], timeout: int = 600, capture_output: bool = True):
        return super().run(cmd_args, timeout=timeout, capture_output=capture_output)

    def run_scan(self, target: str, session=None) -> Dict[str, Any]:
        if not self.ensure_installed():
            return {"error": f"{self.name} not installed"}

        from core.utils import print_info, print_good
        print_info(f"Ejecutando NSE scan en {target}...")
        xml_output = self.scan_nse(target, "1-10000", session=session)

        host_info, ports = self.parse_xml(xml_output, include_scripts=True)

        open_ports = [p for p in ports if p["state"] == "open"]
        print_good(f"Puertos abiertos encontrados: {len(open_ports)}")

        return {
            "target": target,
            "host_info": host_info,
            "ports": ports,
            "open_port_count": len(open_ports),
        }

    def parse_results(self, raw_output: str) -> Any:
        return self.parse_xml(raw_output, include_scripts=True)
