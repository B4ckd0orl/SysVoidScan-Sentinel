import re
from typing import Any, Dict, List

from tools.base import ToolWrapper


class KerbruteTool(ToolWrapper):

    name = "kerbrute"
    binary = "kerbrute"
    install_cmd = []

    def user_enum(self, domain: str, dc: str, userlist: str) -> str:
        cmd_args = [
            "userenum",
            "--dc", dc,
            "-d", domain,
            userlist,
            "--silent",
        ]
        result = self.run(cmd_args, timeout=300)
        return result.stdout

    def password_spray(self, domain: str, dc: str, users: str, password: str) -> str:
        cmd_args = [
            "passwordspray",
            "--dc", dc,
            "-d", domain,
            users,
            password,
            "--silent",
        ]
        result = self.run(cmd_args, timeout=300)
        return result.stdout

    def parse_results(self, raw_output: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        valid_pattern = re.compile(r"\[\+\]\s+(\S+)")
        cred_pattern = re.compile(r"\[\+\]\s+(\S+):(\S+)")

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            cm = cred_pattern.search(line)
            if cm:
                findings.append({
                    "type": "credential",
                    "username": cm.group(1),
                    "password": cm.group(2),
                })
                continue

            vm = valid_pattern.search(line)
            if vm:
                findings.append({
                    "type": "valid_user",
                    "username": vm.group(1),
                })

        return findings

    def run_enum(self, domain: str, dc: str, userlist: str) -> Dict[str, Any]:
        if not self.ensure_installed():
            return {"error": f"{self.name} not installed"}

        from core.utils import print_info, print_good
        print_info(f"Enumerando usuarios Kerberos en {domain}...")
        raw = self.user_enum(domain, dc, userlist)
        findings = self.parse_results(raw)
        print_good(f"Kerbrute: {len(findings)} usuarios validos encontrados")

        return {
            "domain": domain,
            "dc": dc,
            "findings": findings,
            "total": len(findings),
        }

    def run_spray(self, domain: str, dc: str, users: str, password: str) -> Dict[str, Any]:
        if not self.ensure_installed():
            return {"error": f"{self.name} not installed"}

        from core.utils import print_info, print_good
        print_info(f"Password spraying en {domain}...")
        raw = self.password_spray(domain, dc, users, password)
        findings = self.parse_results(raw)
        print_good(f"Kerbrute: {len(findings)} credenciales encontradas")

        return {
            "domain": domain,
            "dc": dc,
            "credentials": findings,
            "total": len(findings),
        }
