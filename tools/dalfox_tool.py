import json
import tempfile
import os
from typing import Any, Dict, List

from tools.base import ToolWrapper


class DalfoxTool(ToolWrapper):

    name = "dalfox"
    binary = "dalfox"
    install_cmd = [
        "go", "install",
        "github.com/hahwul/dalfox/v2@latest",
    ]

    def scan_url(self, url: str, param: str, session=None) -> str:
        cmd_args = ["url", url, "-p", param, "--silence", "--format", "json"]
        result = self.run(cmd_args, timeout=600)
        return result.stdout

    def scan_pipe(self, urls_file: str) -> str:
        cmd_args = ["pipe", "-l", urls_file, "--silence", "--format", "json"]
        result = self.run(cmd_args, timeout=600)
        return result.stdout

    def parse_results(self, json_output: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        for line in json_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            findings.append({
                "type": item.get("type", "XSS"),
                "poc": item.get("poc", ""),
                "param": item.get("param", ""),
                "payload": item.get("payload", ""),
                "method": item.get("method", "GET"),
                "url": item.get("url", ""),
                "title": item.get("title", ""),
                "severity": item.get("severity", "medium"),
                "dvawa_type": item.get("dvawa_type", ""),
            })

        return findings

    def run_scan(self, url: str, param: str, session=None) -> Dict[str, Any]:
        if not self.ensure_installed():
            return {"error": f"{self.name} not installed"}

        from core.utils import print_info, print_good
        print_info(f"Escaneando XSS en {url} (param={param}) con Dalfox...")
        raw = self.scan_url(url, param, session=session)
        findings = self.parse_results(raw)
        print_good(f"Dalfox: {len(findings)} hallazgos XSS encontrados")

        return {
            "url": url,
            "param": param,
            "findings": findings,
            "total": len(findings),
        }
