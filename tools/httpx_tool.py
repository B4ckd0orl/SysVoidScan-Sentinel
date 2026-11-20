import json
from typing import Any, Dict, List, Optional

from tools.base import ToolWrapper


class HttpxTool(ToolWrapper):

    name = "httpx"
    binary = "httpx"
    install_cmd = [
        "go", "install", "-v",
        "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    ]

    def probe(self, targets: List[str], session=None) -> str:
        import tempfile
        import os

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tmp:
            for t in targets:
                tmp.write(t + "\n")
            tmp_path = tmp.name

        try:
            cmd_args = [
                "-l", tmp_path,
                "-json",
                "-silent",
                "-status-code",
                "-title",
                "-tech-detect",
                "-follow-redirects",
                "-timeout", "10",
            ]
            result = self.run(cmd_args, timeout=300)
            return result.stdout
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def parse_results(self, json_output: str) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        for line in json_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            entries.append({
                "url": item.get("url", ""),
                "status_code": item.get("status_code", 0),
                "title": item.get("title", ""),
                "technologies": item.get("tech", []),
                "content_length": item.get("content_length", 0),
                "content_type": item.get("content_type", ""),
                "webserver": item.get("webserver", ""),
                "host": item.get("host", ""),
                "port": item.get("port", ""),
                "scheme": item.get("scheme", ""),
                "method": item.get("method", ""),
                "path": item.get("path", ""),
                "final_url": item.get("final_url", ""),
                "response_time": item.get("response_time", ""),
            })

        return entries

    def run_probe(self, targets: List[str], session=None) -> Dict[str, Any]:
        if not self.ensure_installed():
            return {"error": f"{self.name} not installed"}

        from core.utils import print_info, print_good
        print_info(f"Sondeando {len(targets)} targets con httpx...")
        raw = self.probe(targets, session=session)
        entries = self.parse_results(raw)
        print_good(f"httpx: {len(entries)} hosts activos encontrados")

        return {
            "targets": targets,
            "alive": entries,
            "total": len(entries),
        }
