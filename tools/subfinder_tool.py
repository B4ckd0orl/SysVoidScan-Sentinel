from typing import Any, Dict, List

from tools.base import ToolWrapper


class SubfinderTool(ToolWrapper):

    name = "subfinder"
    binary = "subfinder"
    install_cmd = [
        "go", "install", "-v",
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    ]

    def enumerate(self, domain: str) -> str:
        result = self.run(["-d", domain, "-silent"], timeout=300)
        return result.stdout

    def parse_results(self, raw_output: str) -> List[str]:
        subdomains: List[str] = []
        for line in raw_output.strip().splitlines():
            line = line.strip()
            if line and not line.startswith("["):
                subdomains.append(line)
        return subdomains

    def run_enumeration(self, domain: str) -> Dict[str, Any]:
        if not self.ensure_installed():
            return {"error": f"{self.name} not installed"}

        from core.utils import print_info, print_good
        print_info(f"Enumerando subdominios de {domain} con Subfinder...")
        raw = self.enumerate(domain)
        subdomains = self.parse_results(raw)
        print_good(f"Subfinder: {len(subdomains)} subdominios encontrados")

        return {
            "domain": domain,
            "subdomains": subdomains,
            "total": len(subdomains),
        }
