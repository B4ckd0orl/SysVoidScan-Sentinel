import json
from typing import Any, Dict, List

from tools.base import ToolWrapper


class WhatwebTool(ToolWrapper):

    name = "whatweb"
    binary = "whatweb"
    install_cmd = ["sudo", "apt-get", "install", "-y", "whatweb"]

    def scan(self, target: str, session=None) -> str:
        cmd_args = [
            target,
            "--color=never",
            "-q",
            "-v",
        ]
        result = self.run(cmd_args, timeout=300)
        return result.stdout

    def parse_results(self, raw_output: str) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        import re

        plugin_pattern = re.compile(r"(\w[\w\s]*\w)\s+\[([^\]]*)\]")

        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            if line.startswith("http"):
                parts = line.split(" ", 1)
                if len(parts) < 2:
                    continue
                detail_str = parts[1]
            else:
                detail_str = line

            matches = plugin_pattern.findall(detail_str)
            for plugin_name, detail_str_inner in matches:
                detail = {}
                for item in detail_str_inner.split(", "):
                    item = item.strip()
                    if "=" in item:
                        k, v = item.split("=", 1)
                        detail[k.strip()] = v.strip()
                    elif item:
                        detail[item] = True

                entries.append({
                    "name": plugin_name.strip(),
                    "detail": detail,
                })

        return entries

    def run_scan(self, target: str, session=None) -> Dict[str, Any]:
        if not self.ensure_installed():
            return {"error": f"{self.name} not installed"}

        from core.utils import print_info, print_good
        print_info(f"Escaneando tecnologias en {target} con WhatWeb...")
        raw = self.scan(target, session=session)
        entries = self.parse_results(raw)
        unique_techs = list({e["name"] for e in entries})
        print_good(f"WhatWeb: {len(unique_techs)} tecnologias detectadas")

        return {
            "target": target,
            "technologies": entries,
            "unique_technologies": unique_techs,
            "total": len(entries),
        }
