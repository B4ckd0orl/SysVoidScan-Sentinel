import json
import tempfile
import os
from typing import Any, Dict, List, Optional

from tools.base import ToolWrapper


class FfufTool(ToolWrapper):

    name = "ffuf"
    binary = "ffuf"
    install_cmd = ["sudo", "apt-get", "install", "-y", "ffuf"]

    def fuzz_directories(self, target: str, wordlist: str, session=None, threads: int = 5) -> str:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
            tmp_path = tmp.name

        try:
            url = target.rstrip('/') + '/FUZZ'
            cmd_args = [
                "-u", url,
                "-w", wordlist,
                "-t", str(threads),
                "-o", tmp_path,
                "-of", "json",
                "-mc", "200,204,301,302,307,401,403,405",
                "-fs", "0",
            ]
            self.run(cmd_args, timeout=600)

            if os.path.exists(tmp_path):
                with open(tmp_path, 'r', encoding='utf-8', errors='replace') as f:
                    return f.read()
            return "{}"
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def fuzz_vhosts(self, target: str, wordlist: str, base_domain: str, session=None) -> str:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
            tmp_path = tmp.name

        try:
            cmd_args = [
                "-u", target,
                "-w", wordlist,
                "-H", "Host: FUZZ.{domain}",
                "-o", tmp_path,
                "-of", "json",
                "-mc", "200,204,301,302,307,401,403,405",
            ]
            self.run(cmd_args, timeout=600)

            if os.path.exists(tmp_path):
                with open(tmp_path, 'r', encoding='utf-8', errors='replace') as f:
                    return f.read()
            return "{}"
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def fuzz_subdomains(self, target: str, wordlist: str, session=None) -> str:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
            tmp_path = tmp.name

        try:
            domain = target.replace("http://", "").replace("https://", "").split("/")[0]
            url = f"http://FUZZ.{domain}"
            cmd_args = [
                "-u", url,
                "-w", wordlist,
                "-o", tmp_path,
                "-of", "json",
                "-mc", "200,204,301,302,307,401,403",
            ]
            self.run(cmd_args, timeout=600)

            if os.path.exists(tmp_path):
                with open(tmp_path, 'r', encoding='utf-8', errors='replace') as f:
                    return f.read()
            return "{}"
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def parse_results(self, json_output: str) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        try:
            data = json.loads(json_output)
        except json.JSONDecodeError:
            return hits

        results = data.get("results", [])
        for r in results:
            hits.append({
                "url": r.get("url", ""),
                "status": r.get("status", 0),
                "length": r.get("length", 0),
                "words": r.get("words", 0),
                "lines": r.get("lines", 0),
                "content_type": r.get("content-type", ""),
                "redirectlocation": r.get("redirectlocation", ""),
                "input": r.get("input", {}),
                "duration": r.get("duration", 0),
            })

        return hits

    def run_fuzz(self, target: str, wordlist: str, mode: str = "dir", session=None, **kwargs) -> Dict[str, Any]:
        if not self.ensure_installed():
            return {"error": f"{self.name} not installed"}

        from core.utils import print_info, print_good
        print_info(f"Fuzzing {target} ({mode} mode)...")
        if mode == "dir":
            raw = self.fuzz_directories(target, wordlist, session=session, threads=kwargs.get("threads", 5))
        elif mode == "vhost":
            raw = self.fuzz_vhosts(target, wordlist, kwargs.get("base_domain", ""), session=session)
        elif mode == "subdomain":
            raw = self.fuzz_subdomains(target, wordlist, session=session)
        else:
            raw = self.fuzz_directories(target, wordlist, session=session)

        hits = self.parse_results(raw)
        print_good(f"FFUF: {len(hits)} resultados encontrados")

        return {
            "target": target,
            "mode": mode,
            "hits": hits,
            "total": len(hits),
        }
