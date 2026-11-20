from typing import Any, Dict, List

from tools.base import ToolWrapper


class KatanaTool(ToolWrapper):

    name = "katana"
    binary = "katana"
    install_cmd = [
        "go", "install",
        "github.com/projectdiscovery/katana/cmd/katana@latest",
    ]

    def crawl(self, target: str, depth: int = 3, session=None) -> str:
        cmd_args = [
            "-u", target,
            "-d", str(depth),
            "-silent",
            "-jc",
        ]
        result = self.run(cmd_args, timeout=600)
        return result.stdout

    def parse_results(self, raw_output: str) -> List[str]:
        urls: List[str] = []
        for line in raw_output.strip().splitlines():
            line = line.strip()
            if line and line.startswith(("http://", "https://")):
                if line not in urls:
                    urls.append(line)
        return urls

    def run_crawl(self, target: str, depth: int = 3, session=None) -> Dict[str, Any]:
        if not self.ensure_installed():
            return {"error": f"{self.name} not installed"}

        from core.utils import print_info, print_good
        print_info(f"Crawling {target} (depth={depth}) con Katana...")
        raw = self.crawl(target, depth=depth, session=session)
        urls = self.parse_results(raw)
        print_good(f"Katana: {len(urls)} URLs descubiertas")

        return {
            "target": target,
            "urls": urls,
            "total": len(urls),
        }
