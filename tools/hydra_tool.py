import re
from typing import Any, Dict, List, Optional

from tools.base import ToolWrapper


class HydraTool(ToolWrapper):

    name = "hydra"
    binary = "hydra"
    install_cmd = ["sudo", "apt-get", "install", "-y", "hydra"]

    def bruteforce(
        self,
        target: str,
        service: str,
        usernames: List[str],
        passwords: List[str],
        extra_args: Optional[List[str]] = None,
    ) -> str:
        import tempfile
        import os

        user_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
        pass_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
        try:
            for u in usernames:
                user_file.write(u + "\n")
            user_file.close()

            for p in passwords:
                pass_file.write(p + "\n")
            pass_file.close()

            cmd_args = [
                "-L", user_file.name,
                "-P", pass_file.name,
                "-t", "4",
                "-f",
                "-o", "/dev/stdout",
            ]
            if extra_args:
                cmd_args.extend(extra_args)
            cmd_args.append(target)
            cmd_args.append(service)

            result = self.run(cmd_args, timeout=600)
            return result.stdout + "\n" + result.stderr
        finally:
            os.unlink(user_file.name)
            os.unlink(pass_file.name)

    def parse_results(self, raw_output: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        pattern = re.compile(
            r"\[(\d+)\]\[(\S+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)"
        )

        for line in raw_output.splitlines():
            line = line.strip()
            m = pattern.search(line)
            if m:
                findings.append({
                    "port": int(m.group(1)),
                    "service": m.group(2),
                    "host": m.group(3),
                    "username": m.group(4),
                    "password": m.group(5),
                })

        return findings

    def run_bruteforce(
        self,
        target: str,
        service: str,
        usernames: List[str],
        passwords: List[str],
        extra_args: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        if not self.ensure_installed():
            return {"error": f"{self.name} not installed"}

        from core.utils import print_info, print_good
        print_info(f"Bruteforcing {service} en {target} con Hydra...")
        raw = self.bruteforce(target, service, usernames, passwords, extra_args=extra_args)
        findings = self.parse_results(raw)
        print_good(f"Hydra: {len(findings)} credenciales encontradas")

        return {
            "target": target,
            "service": service,
            "credentials": findings,
            "total": len(findings),
        }
