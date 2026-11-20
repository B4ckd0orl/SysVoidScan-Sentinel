import re
from typing import Any, Dict, List

from tools.base import ToolWrapper


class GobusterTool(ToolWrapper):

    name = "gobuster"
    binary = "gobuster"
    install_cmd = ["sudo", "apt-get", "install", "-y", "gobuster"]

    def dir_mode(self, target: str, wordlist: str, session=None) -> str:
        cmd_args = [
            "dir",
            "-u", target,
            "-w", wordlist,
            "-q",
            "--no-color",
            "-t", "10",
            "-b", "404",
        ]
        result = self.run(cmd_args, timeout=600)
        return result.stdout

    def dns_mode(self, domain: str, wordlist: str) -> str:
        cmd_args = [
            "dns",
            "-d", domain,
            "-w", wordlist,
            "-q",
            "--no-color",
        ]
        result = self.run(cmd_args, timeout=600)
        return result.stdout

    def parse_results(self, raw_output: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        dir_pattern = re.compile(
            r"(/\S+)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]"
        )
        sub_pattern = re.compile(
            r"Found:\s+(\S+)\s*"
        )
        sub_pattern2 = re.compile(
            r"(\S+\.\S+)\s*"
        )

        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            dm = dir_pattern.search(line)
            if dm:
                findings.append({
                    "type": "directory",
                    "path": dm.group(1),
                    "status": int(dm.group(2)),
                    "size": int(dm.group(3)),
                })
                continue

            sm = sub_pattern.search(line)
            if sm:
                findings.append({
                    "type": "subdomain",
                    "subdomain": sm.group(1),
                })
                continue

            sm2 = sub_pattern2.search(line)
            if sm2 and "." in sm2.group(1) and "Status" not in line:
                findings.append({
                    "type": "subdomain",
                    "subdomain": sm2.group(1),
                })

        return findings

    def run_scan(self, target: str, wordlist: str, mode: str = "dir", session=None) -> Dict[str, Any]:
        if not self.ensure_installed():
            return {"error": f"{self.name} not installed"}

        from core.utils import print_info, print_good
        print_info(f"Gobuster ({mode}) en {target}...")

        if mode == "dns":
            domain = target.replace("http://", "").replace("https://", "").split("/")[0]
            raw = self.dns_mode(domain, wordlist)
        else:
            raw = self.dir_mode(target, wordlist, session=session)

        findings = self.parse_results(raw)
        print_good(f"Gobuster: {len(findings)} resultados encontrados")

        return {
            "target": target,
            "mode": mode,
            "findings": findings,
            "total": len(findings),
        }
