import json
import tempfile
import os
from typing import Any, Dict, List, Optional

from tools.base import ToolWrapper


class NucleiTool(ToolWrapper):

    name = "nuclei"
    binary = "nuclei"
    install_cmd = ["sudo", "apt-get", "install", "-y", "nuclei"]

    def scan(self, target: str, session=None, extra_args: Optional[List[str]] = None) -> str:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as tmp:
            tmp_path = tmp.name

        try:
            cmd_args = ["-u", target, "-jsonl-export", tmp_path, "-silent"]
            if extra_args:
                cmd_args.extend(extra_args)

            # Scan completo de nuclei: ~13-14 min contra un unico objetivo
            # (medido), por encima del antiguo limite de 600 s que cortaba
            # la fase 76 con TimeoutExpired.
            self.run(cmd_args, timeout=1800)

            if os.path.exists(tmp_path):
                with open(tmp_path, 'r', encoding='utf-8', errors='replace') as f:
                    return f.read()
            return ""
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def parse_results(self, raw_output: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        seen = set()

        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            template_id = item.get("template-id", "")
            matched_at = item.get("matched-at", "")
            dedup_key = f"{template_id}|{matched_at}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            findings.append({
                "template_id": template_id,
                "name": item.get("info", {}).get("name", ""),
                "severity": item.get("info", {}).get("severity", "info"),
                "matched_at": matched_at,
                "type": item.get("type", ""),
                "matcher_name": item.get("matcher-name", ""),
                "curl_command": item.get("curl-command", ""),
                "description": item.get("info", {}).get("description", ""),
                "reference": item.get("info", {}).get("reference", []),
                "tags": item.get("info", {}).get("tags", []),
            })

        return findings

    def run_scan(self, target: str, session=None, extra_args: Optional[List[str]] = None) -> Dict[str, Any]:
        if not self.ensure_installed():
            return {"error": f"{self.name} not installed"}

        from core.utils import print_info, print_good
        print_info(f"Escaneando {target} con Nuclei...")
        raw = self.scan(target, session=session, extra_args=extra_args)
        findings = self.parse_results(raw)
        print_good(f"Nuclei: {len(findings)} hallazgos encontrados")

        return {
            "target": target,
            "findings": findings,
            "total": len(findings),
        }
