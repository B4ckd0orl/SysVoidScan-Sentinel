import re
import json
from urllib.parse import urlparse, urljoin

from core.config import Config
from core.utils import (
    print_info, print_good, print_warning, print_error, print_vuln,
    print_phase, get_session, normalize_url, _capture_command_output,
    _find_tool,
)
from lib.payloads import Payloads
from lib.wordlists import Wordlists
import logging


class WordPressModule:
    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config
        self.payloads = Payloads()
        self.wordlists = Wordlists()

    def detect_wordpress(self, target, session):
        is_wp = False
        wp_version = ""
        wp_info = {}

        print_info("Checking for WordPress...")

        whatweb_path = _find_tool("whatweb")
        if whatweb_path:
            code, stdout, stderr = _capture_command_output(
                ["whatweb", "--color=never", "-a", "3", target],
                timeout=30,
            )
            if code == 0 and "WordPress" in stdout:
                is_wp = True
                version_match = re.search(r'WordPress\[(?:version)?\[([^\]]+)\]', stdout)
                if version_match:
                    wp_version = version_match.group(1)
                print_good(f"WhatWeb detected WordPress (version: {wp_version or 'unknown'})")

        try:
            resp = session.get(target, timeout=self.config.timeout,
                               verify=self.config.verify_tls)
            body = resp.text or ""
            headers = resp.headers

            wp_indicators = [
                "wp-content/",
                "wp-includes/",
                "wp-json/",
                "wp-login.php",
                'name="generator" content="WordPress',
                "/xmlrpc.php",
                "wp-embed.min.js",
            ]

            for indicator in wp_indicators:
                if indicator.lower() in body.lower():
                    is_wp = True
                    break

            if "X-Pingback" in headers:
                is_wp = True

            if is_wp and not wp_version:
                gen_match = re.search(
                    r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([^\s"\']+)',
                    body, re.IGNORECASE,
                )
                if gen_match:
                    wp_version = gen_match.group(1)

            readme_url = urljoin(target, "/readme.html")
            try:
                readme_resp = session.get(readme_url, timeout=5,
                                          verify=self.config.verify_tls)
                if readme_resp.status_code == 200 and "WordPress" in readme_resp.text:
                    is_wp = True
                    ver_match = re.search(r'Version\s+(\d+\.\d+(?:\.\d+)?)', readme_resp.text)
                    if ver_match and not wp_version:
                        wp_version = ver_match.group(1)
            except Exception:
                logging.exception("wordpress.py: exception")
                pass
            wp_json_url = urljoin(target, "/wp-json/wp/v2/users")
            try:
                json_resp = session.get(wp_json_url, timeout=5,
                                        verify=self.config.verify_tls)
                if json_resp.status_code == 200:
                    is_wp = True
                    try:
                        users = json_resp.json()
                        if isinstance(users, list):
                            wp_info["users"] = [
                                {"id": u.get("id"), "name": u.get("name"),
                                 "slug": u.get("slug")}
                                for u in users
                            ]
                            print_info(f"  Found {len(users)} users via WP REST API")
                    except Exception:
                        logging.exception("wordpress.py: exception")
                        pass
            except Exception:
                logging.exception("wordpress.py: exception")
                pass
            xmlrpc_url = urljoin(target, "/xmlrpc.php")
            try:
                xmlrpc_body = (
                    '<?xml version="1.0"?>\n'
                    "<methodCall>\n"
                    "<methodName>system.listMethods</methodName>\n"
                    "<params></params>\n"
                    "</methodCall>"
                )
                xmlrpc_resp = session.post(
                    xmlrpc_url, data=xmlrpc_body,
                    headers={"Content-Type": "text/xml"},
                    timeout=5, verify=self.config.verify_tls,
                )
                if xmlrpc_resp.status_code == 200 and "wp.getUsersBlogs" in xmlrpc_resp.text:
                    is_wp = True
                    wp_info["xmlrpc_enabled"] = True
                    print_warning("XML-RPC enabled (wp.getUsersBlogs available)")
                elif xmlrpc_resp.status_code == 200:
                    wp_info["xmlrpc_enabled"] = True
            except Exception:
                logging.exception("wordpress.py: exception")
                pass
        except Exception as e:
            logging.exception("wordpress.py: operation failed")
            print_error(f"Error during WordPress detection: {e}")

        if is_wp:
            wp_info["detected"] = True
            wp_info["version"] = wp_version
            print_good(f"WordPress detected! Version: {wp_version or 'unknown'}")
        else:
            wp_info["detected"] = False
            print_info("No WordPress installation detected.")

        self.config.scan_data["target"]["technologies"].append(
            f"WordPress {wp_version}" if wp_version else "WordPress"
        ) if is_wp else None

        return is_wp, wp_version, wp_info

    def run_wpscan_enumeration(self, target, session, api_token=None):
        findings = []
        wpscan_path = _find_tool("wpscan")

        if not wpscan_path:
            print_warning("wpscan not found. Skipping WPScan enumeration.")
            return findings

        print_info("Running WPScan enumeration...")

        cmd = ["wpscan", "--url", target, "--no-update", "--random-user-agent",
               "--enumerate", "ap,at,u,tt,cb,dbe"]

        if api_token:
            cmd.extend(["--api-token", api_token])

        cmd.extend(["--format", "json", "--output", "-"])

        code, stdout, stderr = _capture_command_output(cmd, timeout=120)

        if code == 0 and stdout:
            try:
                data = json.loads(stdout)

                if "plugins" in data:
                    for plugin_name, plugin_data in data["plugins"].items():
                        version = plugin_data.get("version", {}).get("number", "unknown")
                        severity = "high" if plugin_data.get("vulnerabilities") else "info"
                        finding = {
                            "type": "wp_plugin",
                            "severity": severity,
                            "url": target,
                            "plugin": plugin_name,
                            "version": version,
                            "vulnerabilities": plugin_data.get("vulnerabilities", []),
                        }
                        findings.append(finding)
                        if plugin_data.get("vulnerabilities"):
                            print_vuln(
                                f"WP plugin {plugin_name} v{version} has "
                                f"{len(plugin_data['vulnerabilities'])} known vulnerabilities"
                            )
                        else:
                            print_info(f"  Plugin: {plugin_name} v{version}")

                if "themes" in data:
                    for theme_name, theme_data in data["themes"].items():
                        version = theme_data.get("version", {}).get("number", "unknown")
                        finding = {
                            "type": "wp_theme",
                            "severity": "info",
                            "url": target,
                            "theme": theme_name,
                            "version": version,
                        }
                        findings.append(finding)
                        print_info(f"  Theme: {theme_name} v{version}")

                if "users" in data:
                    for user in data["users"]:
                        finding = {
                            "type": "wp_user_enumeration",
                            "severity": "medium",
                            "url": target,
                            "username": user.get("username"),
                            "id": user.get("id"),
                        }
                        findings.append(finding)
                        print_warning(f"  User enumerated: {user.get('username')}")

            except json.JSONDecodeError:
                print_warning("Could not parse WPScan JSON output.")
                if "vulnerability" in stdout.lower():
                    finding = {
                        "type": "wp vulnerabilities",
                        "severity": "high",
                        "url": target,
                        "evidence": "WPScan found vulnerabilities (see raw output)",
                    }
                    findings.append(finding)
        else:
            print_warning(f"WPScan failed: {stderr[:200]}")

        return findings

    def run_wpscan_bruteforce(self, target, session, wordlist=None):
        findings = []
        wpscan_path = _find_tool("wpscan")

        if not wpscan_path:
            print_warning("wpscan not found. Skipping brute force.")
            return findings

        print_info("Running WPScan brute force...")

        cmd = ["wpscan", "--url", target, "--no-update", "--random-user-agent",
               "--passwords", "password123,admin,123456,letmein,test,root",
               "--usernames", "admin,administrator,test,user"]

        if wordlist:
            cmd.extend(["--passwords", wordlist])

        cmd.extend(["--format", "json", "--output", "-"])

        code, stdout, stderr = _capture_command_output(cmd, timeout=120)

        if code == 0 and stdout:
            try:
                data = json.loads(stdout)
                if "brute_progress" in data or "found" in stdout.lower():
                    finding = {
                        "type": "wp_bruteforce_result",
                        "severity": "high",
                        "url": target,
                        "evidence": "WPScan brute force completed",
                    }
                    findings.append(finding)
            except json.JSONDecodeError:
                pass

        return findings

    def run_wordpress_attacks(self, target, session):
        findings = []
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        print_info("Running WordPress-specific attacks...")

        wp_vuln_endpoints = [
            ("/wp-login.php", "POST", {"log": "admin", "pwd": "admin", "wp-submit": "Log In"}),
            ("/wp-admin/install.php", "GET", None),
            ("/wp-cron.php", "GET", None),
            ("/xmlrpc.php", "POST", (
                '<?xml version="1.0"?>\n'
                "<methodCall>\n"
                "<methodName>pingback.ping</methodName>\n"
                "<params><param><value><string>http://127.0.0.1</string></value></param></params>\n"
                "</methodCall>"
            )),
            ("/wp-json/wp/v2/users", "GET", None),
            ("/?rest_route=/wp/v2/users", "GET", None),
        ]

        for path, method, data in wp_vuln_endpoints:
            url = f"{base}{path}"
            try:
                if method == "GET":
                    resp = session.get(url, timeout=5, verify=self.config.verify_tls)
                else:
                    headers = {}
                    if isinstance(data, str):
                        headers["Content-Type"] = "text/xml"
                        resp = session.post(url, data=data, headers=headers,
                                            timeout=5, verify=self.config.verify_tls)
                    else:
                        resp = session.post(url, data=data, timeout=5,
                                            verify=self.config.verify_tls)

                if resp.status_code == 200:
                    body = resp.text or ""
                    if "wp-login" in body or "WordPress" in body:
                        finding = {
                            "type": "wp_exposed_endpoint",
                            "severity": "info",
                            "url": url,
                            "status": resp.status_code,
                            "evidence": f"WordPress endpoint accessible: {path}",
                        }
                        findings.append(finding)

            except Exception:
                logging.exception("wordpress.py: exception")
                continue
        user_enum_paths = [
            "/?author=1",
            "/?author=2",
            "/?author=3",
            "/wp-json/wp/v2/users/1",
            "/wp-json/wp/v2/users/2",
        ]

        for path in user_enum_paths:
            url = f"{base}{path}"
            try:
                resp = session.get(url, timeout=5, verify=self.config.verify_tls,
                                   allow_redirects=True)
                body = resp.text or ""

                username_match = re.search(
                    r'(?:author|user)[^"]*"[^"]*"[^"]*>([^<]+)<',
                    body, re.IGNORECASE,
                )
                if username_match:
                    finding = {
                        "type": "wp_user_enum",
                        "severity": "medium",
                        "url": url,
                        "username": username_match.group(1).strip(),
                        "evidence": f"Username enumerated: {username_match.group(1).strip()}",
                    }
                    findings.append(finding)
                    print_warning(f"WordPress user enumerated: {username_match.group(1).strip()}")

            except Exception:
                logging.exception("wordpress.py: exception")
                continue
        return findings

    def run(self, target, session=None):
        print_phase("WordPress Testing")
        self.config.target_url = normalize_url(target)

        if session is None:
            session = get_session()
        if session is None:
            print_error("Cannot proceed without a valid HTTP session.")
            return

        is_wp, wp_version, wp_info = self.detect_wordpress(target, session)

        if not is_wp:
            print_info("Not a WordPress site. Skipping WordPress tests.")
            return

        all_findings = []

        enum_findings = self.run_wpscan_enumeration(target, session)
        all_findings.extend(enum_findings)

        attack_findings = self.run_wordpress_attacks(target, session)
        all_findings.extend(attack_findings)

        all_findings.extend([
            f for f in [
                {"type": "wp_info", "severity": "info", "url": target,
                 "version": wp_version, "xmlrpc": wp_info.get("xmlrpc_enabled", False),
                 "users": wp_info.get("users", [])}
            ]
        ])

        for f in all_findings:
            if f not in self.config.findings:
                self.config.findings.append(f)

        print_good(f"WordPress testing complete: {len(all_findings)} result(s).")
