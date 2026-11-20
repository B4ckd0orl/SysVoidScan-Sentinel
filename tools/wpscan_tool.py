import json
from typing import Any, Dict, List, Optional

from tools.base import ToolWrapper


class WpscanTool(ToolWrapper):

    name = "wpscan"
    binary = "wpscan"
    install_cmd = ["sudo", "gem", "install", "wpscan"]

    def enumerate(self, target: str, options: Optional[Dict[str, str]] = None, api_token: Optional[str] = None, session=None) -> str:
        cmd_args = [
            "--url", target,
            "--enumerate",
            "--format", "json",
            "--no-banner",
            "--random-user-agent",
            "--silent",
        ]

        if api_token:
            cmd_args.extend(["--api-token", api_token])

        if options:
            for key, value in options.items():
                cmd_args.extend([f"--{key}", value])

        result = self.run(cmd_args, timeout=600)
        return result.stdout

    def bruteforce(self, target: str, usernames_file: str, session=None) -> str:
        cmd_args = [
            "--url", target,
            "--passwords", "/usr/share/wordlists/rockyou.txt",
            "--usernames", usernames_file,
            "--format", "json",
            "--no-banner",
            "--random-user-agent",
            "--silent",
            "--throttle", "100",
        ]
        result = self.run(cmd_args, timeout=1200)
        return result.stdout

    def parse_results(self, json_output: str) -> Dict[str, Any]:
        normalized: Dict[str, Any] = {
            "target": "",
            "wordpress_version": "",
            "plugins": [],
            "themes": [],
            "users": [],
            "findings": [],
            "interesting_headers": [],
            "xmlrpc": False,
            "wp_cron": False,
        }

        try:
            data = json.loads(json_output)
        except json.JSONDecodeError:
            return normalized

        normalized["target"] = data.get("target_url", "")

        wp_ver = data.get("wordpress_version", {})
        if isinstance(wp_ver, dict):
            normalized["wordpress_version"] = wp_ver.get("version", "")
        elif isinstance(wp_ver, str):
            normalized["wordpress_version"] = wp_ver

        plugins = data.get("plugins", {})
        if isinstance(plugins, dict):
            for name, info in plugins.items():
                if isinstance(info, dict):
                    normalized["plugins"].append({
                        "name": name,
                        "version": info.get("version", ""),
                        "vulnerabilities": info.get("vulnerabilities", []),
                        "interesting_entries": info.get("interesting_entries", []),
                    })

        themes = data.get("themes", {})
        if isinstance(themes, dict):
            for name, info in themes.items():
                if isinstance(info, dict):
                    normalized["themes"].append({
                        "name": name,
                        "version": info.get("version", ""),
                        "vulnerabilities": info.get("vulnerabilities", []),
                    })

        users = data.get("users", {})
        if isinstance(users, dict):
            for uid, info in users.items():
                if isinstance(info, dict):
                    normalized["users"].append({
                        "id": uid,
                        "username": info.get("username", ""),
                    })

        if isinstance(data.get("interesting_findings"), list):
            for finding in data["interesting_findings"]:
                normalized["findings"].append({
                    "type": finding.get("type", ""),
                    "url": finding.get("url", ""),
                    "to_interactsh": finding.get("to_interactsh", False),
                })

        headers = data.get("interesting_headers", [])
        if isinstance(headers, list):
            for h in headers:
                if isinstance(h, dict):
                    normalized["interesting_headers"].append(h)

        normalized["xmlrpc"] = bool(data.get("xmlrpc"))
        normalized["wp_cron"] = bool(data.get("wp_cron"))

        return normalized

    def run_scan(self, target: str, api_token: Optional[str] = None, session=None) -> Dict[str, Any]:
        if not self.ensure_installed():
            return {"error": f"{self.name} not installed"}

        from core.utils import print_info, print_good
        print_info(f"Escaneando WordPress en {target} con WPScan...")
        raw = self.enumerate(target, api_token=api_token, session=session)
        data = self.parse_results(raw)
        print_good(f"WPScan: {len(data.get('plugins', []))} plugins, {len(data.get('users', []))} usuarios encontrados")

        return {
            "target": target,
            **data,
        }
