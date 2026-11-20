import re
from typing import Any, Dict, List

from tools.base import ToolWrapper


class SqlmapTool(ToolWrapper):

    name = "sqlmap"
    binary = "sqlmap"
    install_cmd = ["sudo", "apt-get", "install", "-y", "sqlmap"]

    def test_url(self, url: str, param: str, method: str = "GET", session=None) -> str:
        cmd_args = [
            "-u", url,
            "-p", param,
            "--batch",
            "--random-agent",
            "--threads", "4",
            "--output-dir=-",
        ]
        if method.upper() == "POST":
            cmd_args.extend(["--data", f"{param}=test"])

        result = self.run(cmd_args, timeout=900)
        return result.stdout + "\n" + result.stderr

    def parse_results(self, raw_output: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        param_pattern = re.compile(r"Parameter:\s+(\S+)\s+\((\w+)\)", re.IGNORECASE)
        type_pattern = re.compile(r"Type:\s+(.+)", re.IGNORECASE)
        title_pattern = re.compile(r"Title:\s+(.+)", re.IGNORECASE)
        payload_pattern = re.compile(r"Payload:\s+(.+)", re.IGNORECASE)

        current_param = None
        current_type = None
        current_title = None

        for line in raw_output.splitlines():
            line = line.strip()

            pm = param_pattern.search(line)
            if pm:
                current_param = pm.group(1)
                current_type = pm.group(2)
                current_title = None
                continue

            tm = type_pattern.search(line)
            if tm:
                current_type = tm.group(1).strip()
                continue

            ttm = title_pattern.search(line)
            if ttm:
                current_title = ttm.group(1).strip()
                continue

            plm = payload_pattern.search(line)
            if plm and current_param:
                findings.append({
                    "param": current_param,
                    "type": current_type or "",
                    "title": current_title or "",
                    "payload": plm.group(1).strip(),
                })
                current_title = None

            if "is vulnerable" in line.lower() or "injectable" in line.lower():
                if not any(f.get("param") == current_param for f in findings) and current_param:
                    findings.append({
                        "param": current_param,
                        "type": current_type or "",
                        "title": "Vulnerable",
                        "payload": "",
                    })

        return findings

    def run_test(self, url: str, param: str, method: str = "GET", session=None) -> Dict[str, Any]:
        if not self.ensure_installed():
            return {"error": f"{self.name} not installed"}

        from core.utils import print_info, print_good
        print_info(f"Probando SQL Injection en {url} (param={param}) con sqlmap...")
        raw = self.test_url(url, param, method=method, session=session)
        findings = self.parse_results(raw)
        print_good(f"sqlmap: {len(findings)} inyecciones SQL encontradas")

        return {
            "url": url,
            "param": param,
            "findings": findings,
            "total": len(findings),
            "raw": raw,
        }
