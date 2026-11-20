import os
import re
import tempfile
import time
import random
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

from core.config import Config
from core.utils import (
    print_info, print_good, print_warning, print_error, print_vuln,
    print_phase, get_session, normalize_url, _capture_command_output,
    _find_tool,
)
from lib.payloads import Payloads
from lib.wordlists import Wordlists
import logging


class BruteForceModule:
    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config
        self.payloads = Payloads()
        self.wordlists = Wordlists()

    def detect_login_form(self, target, session):
        login_info = {
            "found": False,
            "login_url": None,
            "form_action": None,
            "username_field": None,
            "password_field": None,
            "method": "POST",
            "extra_fields": {},
        }

        print_info("Detecting login forms...")

        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        login_paths = self.wordlists.LOGIN_PATHS

        for path in login_paths:
            url = f"{base}{path}"
            try:
                resp = session.get(url, timeout=self.config.timeout,
                                   verify=self.config.verify_tls)
                if resp.status_code == 200:
                    body = resp.text or ""

                    form_pattern = re.compile(
                        r'<form[^>]*>(.*?)</form>',
                        re.IGNORECASE | re.DOTALL,
                    )
                    forms = form_pattern.findall(body)

                    for form_html in forms:
                        username_patterns = [
                            r'<input[^>]*name=["\']([^"\']+)["\'][^>]*(?:placeholder|aria-label)=["\'][^"\']*(?:user|email|login|usuario)[^"\']*["\']',
                            r'<input[^>]*(?:placeholder|aria-label)=["\'][^"\']*(?:user|email|login|usuario)[^"\']*["\'][^>]*name=["\']([^"\']+)["\']',
                            r'<input[^>]*type=["\'](?:text|email)["\'][^>]*name=["\']([^"\']+)["\']',
                            r'<input[^>]*name=["\']([^"\']+)["\'][^>]*type=["\'](?:text|email)["\']',
                        ]

                        password_patterns = [
                            r'<input[^>]*name=["\']([^"\']+)["\'][^>]*type=["\']password["\']',
                            r'<input[^>]*type=["\']password["\'][^>]*name=["\']([^"\']+)["\']',
                        ]

                        username_field = None
                        for pattern in username_patterns:
                            match = re.search(pattern, form_html, re.IGNORECASE)
                            if match:
                                username_field = match.group(1)
                                break

                        password_field = None
                        for pattern in password_patterns:
                            match = re.search(pattern, form_html, re.IGNORECASE)
                            if match:
                                password_field = match.group(1)
                                break

                        if username_field and password_field:
                            action_match = re.search(
                                r'action=["\']([^"\']+)["\']',
                                form_html, re.IGNORECASE,
                            )
                            form_action = action_match.group(1) if action_match else path

                            method_match = re.search(
                                r'method=["\'](\w+)["\']',
                                form_html, re.IGNORECASE,
                            )
                            method = method_match.group(1).upper() if method_match else "POST"

                            all_inputs = re.findall(
                                r'<input[^>]*name=["\']([^"\']+)["\']',
                                form_html, re.IGNORECASE,
                            )
                            extra_fields = {}
                            for inp_name in all_inputs:
                                if inp_name not in (username_field, password_field):
                                    value_match = re.search(
                                        rf'name=["\']?{re.escape(inp_name)}["\']?[^>]*value=["\']([^"\']*)["\']',
                                        form_html, re.IGNORECASE,
                                    )
                                    if value_match:
                                        extra_fields[inp_name] = value_match.group(1)

                            login_info.update({
                                "found": True,
                                "login_url": url,
                                "form_action": form_action,
                                "username_field": username_field,
                                "password_field": password_field,
                                "method": method,
                                "extra_fields": extra_fields,
                            })

                            print_good(
                                f"Login form found at {url}: "
                                f"username='{username_field}', password='{password_field}'"
                            )
                            return login_info

            except Exception:
                logging.exception("brute_force.py: exception")
                continue
        print_info("No login form detected.")
        return login_info

    def bruteforce_hydra(self, target, service, usernames, passwords):
        findings = []
        hydra_path = _find_tool("hydra")

        if not hydra_path:
            print_warning("hydra not found. Skipping hydra brute force.")
            return findings

        parsed = urlparse(target)
        host = parsed.hostname

        username_file = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        username_file.write("\n".join(usernames))
        username_file.close()

        password_file = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        password_file.write("\n".join(passwords))
        password_file.close()

        print_info(f"Running hydra {service} brute force against {host}...")

        service_path = parsed.path.rstrip("/")
        if service == "ssh":
            cmd = [hydra_path, "-L", username_file.name, "-P", password_file.name,
                   host, service]
        elif service == "ftp":
            cmd = [hydra_path, "-L", username_file.name, "-P", password_file.name,
                   host, service]
        elif service == "http":
            cmd = [hydra_path, "-L", username_file.name, "-P", password_file.name,
                   "-s", str(parsed.port or 80),
                   host, "http-get", service_path]
        else:
            cmd = [hydra_path, "-L", username_file.name, "-P", password_file.name,
                   host, service]

        code, stdout, stderr = _capture_command_output(cmd, timeout=300)

        output = stdout + stderr
        valid_creds = re.findall(r'\[(\w+)\]\[(\S+)\]\s+host:\s+\S+\s+login:\s+(\S+)\s+password:\s+(\S+)', output)

        for proto, port, username, password in valid_creds:
            finding = {
                "type": "bruteforce",
                "severity": "critical",
                "target": target,
                "service": service,
                "username": username,
                "password": password,
                "source": "hydra",
            }
            findings.append(finding)
            print_vuln(f"Valid credentials: {username}:{password} ({service})")

        try:
            os.unlink(username_file.name)
            os.unlink(password_file.name)
        except Exception:
            logging.exception("brute_force.py: exception")
            pass
        return findings

    def bruteforce_internal(self, target, login_url, usernames, passwords, session):
        findings = []
        login_info = self.detect_login_form(target, session)

        if not login_info["found"]:
            print_warning("No login form found for internal brute force.")
            return findings

        username_field = login_info["username_field"]
        password_field = login_info["password_field"]
        form_action = login_info["form_action"]
        method = login_info["method"]
        extra_fields = login_info.get("extra_fields", {})

        if form_action:
            if form_action.startswith("http"):
                brute_url = form_action
            elif form_action.startswith("/"):
                parsed = urlparse(target)
                brute_url = f"{parsed.scheme}://{parsed.netloc}{form_action}"
            else:
                brute_url = urljoin(login_url, form_action)
        else:
            brute_url = login_url

        print_info(f"Brute forcing {brute_url} with {len(usernames)} users x {len(passwords)} passwords...")

        for username in usernames:
            for password in passwords:
                try:
                    data = {
                        username_field: username,
                        password_field: password,
                    }
                    data.update(extra_fields)

                    if method == "GET":
                        resp = session.get(
                            brute_url,
                            params=data,
                            timeout=self.config.timeout,
                            verify=self.config.verify_tls,
                            allow_redirects=True,
                        )
                    else:
                        resp = session.post(
                            brute_url,
                            data=data,
                            timeout=self.config.timeout,
                            verify=self.config.verify_tls,
                            allow_redirects=True,
                        )

                    body = (resp.text or "").lower()

                    is_failure = False
                    for marker in self.payloads.LOGIN_FAILURE_MARKERS:
                        if marker.lower() in body:
                            is_failure = True
                            break

                    for keyword in self.payloads.FAILURE_KEYWORDS:
                        if keyword.lower() in body:
                            is_failure = True
                            break

                    if not is_failure:
                        for keyword in self.payloads.SUCCESS_KEYWORDS:
                            if keyword.lower() in body:
                                finding = {
                                    "type": "bruteforce",
                                    "severity": "critical",
                                    "url": brute_url,
                                    "username": username,
                                    "password": password,
                                    "response_code": resp.status_code,
                                    "evidence": f"Success keyword '{keyword}' in response",
                                    "source": "internal",
                                }
                                findings.append(finding)
                                print_vuln(f"Valid credentials: {username}:{password}")
                                break

                    if findings:
                        break

                    time.sleep(0.05)

                except Exception:
                    logging.exception("brute_force.py: exception")
                    continue
            if findings:
                break

        if not findings:
            print_info("Internal brute force did not find valid credentials.")

        return findings

    def enumerate_users(self, target, session):
        users = set()

        print_info("Enumerating usernames...")

        api_endpoints = self.config.scan_data.get("api", {}).get("endpoints", [])
        for ep in api_endpoints:
            path = ep.get("path", "")
            url = ep.get("url", "")
            if any(kw in path.lower() for kw in ["user", "account", "profile"]):
                try:
                    resp = session.get(url, timeout=5, verify=self.config.verify_tls)
                    if resp.status_code == 200:
                        body = resp.text or ""
                        username_patterns = [
                            r'"username"\s*:\s*"([^"]+)"',
                            r'"user"\s*:\s*"([^"]+)"',
                            r'"email"\s*:\s*"([^"]+)"',
                            r'"login"\s*:\s*"([^"]+)"',
                            r'"name"\s*:\s*"([^"]+)"',
                        ]
                        for pattern in username_patterns:
                            matches = re.findall(pattern, body, re.IGNORECASE)
                            for match in matches:
                                if len(match) > 1 and len(match) < 50:
                                    users.add(match)
                except Exception:
                    logging.exception("brute_force.py: exception")
                    continue
        wp_users_url = urljoin(target, "/wp-json/wp/v2/users")
        try:
            resp = session.get(wp_users_url, timeout=5, verify=self.config.verify_tls)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    for u in data:
                        if "slug" in u:
                            users.add(u["slug"])
                        if "name" in u:
                            users.add(u["name"])
        except Exception:
            logging.exception("brute_force.py: exception")
            pass
        author_paths = ["/?author=1", "/?author=2", "/?author=3", "/?author=4", "/?author=5"]
        for path in author_paths:
            try:
                resp = session.get(f"{target}{path}", timeout=5,
                                   verify=self.config.verify_tls,
                                   allow_redirects=True)
                body = resp.text or ""
                user_match = re.search(r'/author/([^/"\s]+)', resp.url + body)
                if user_match:
                    users.add(user_match.group(1))
            except Exception:
                logging.exception("brute_force.py: exception")
                continue
        if users:
            print_good(f"Enumerated {len(users)} username(s): {', '.join(list(users)[:10])}")
        else:
            print_info("No usernames enumerated.")

        return list(users)

    def test_user_enumeration_form(self, target, session):
        findings = []

        print_info("Testing differential user enumeration via login form...")

        login_info = self.detect_login_form(target, session)
        if not login_info["found"]:
            return findings

        username_field = login_info["username_field"]
        password_field = login_info["password_field"]
        form_action = login_info["form_action"]
        method = login_info["method"]
        extra_fields = login_info.get("extra_fields", {})

        if form_action:
            if form_action.startswith("http"):
                brute_url = form_action
            elif form_action.startswith("/"):
                parsed = urlparse(target)
                brute_url = f"{parsed.scheme}://{parsed.netloc}{form_action}"
            else:
                brute_url = urljoin(target, form_action)
        else:
            brute_url = target

        test_users = [
            "admin", "administrator", "test", "nonexistentuser12345",
            "root", "user", "guest",
        ]

        user_responses = {}
        for username in test_users:
            try:
                data = {
                    username_field: username,
                    password_field: "definitelywrongpassword123",
                }
                data.update(extra_fields)

                resp = session.post(
                    brute_url, data=data,
                    timeout=self.config.timeout,
                    verify=self.config.verify_tls,
                    allow_redirects=True,
                )

                body = (resp.text or "").lower()
                content_length = len(resp.text or "")

                user_responses[username] = {
                    "status": resp.status_code,
                    "length": content_length,
                    "body_snippet": body[:500],
                }

                time.sleep(0.1)

            except Exception:
                logging.exception("brute_force.py: exception")
                continue
        if len(set(r["length"] for r in user_responses.values())) > 1:
            print_warning("Different response lengths detected - possible user enumeration")
            finding = {
                "type": "user_enumeration",
                "severity": "medium",
                "url": brute_url,
                "evidence": "Differential response lengths across usernames",
                "response_lengths": {u: r["length"] for u, r in user_responses.items()},
            }
            findings.append(finding)

        for marker in self.payloads.LOGIN_FAILURE_MARKERS:
            count = sum(1 for r in user_responses.values() if marker.lower() in r["body_snippet"])
            if 0 < count < len(user_responses):
                finding = {
                    "type": "user_enumeration",
                    "severity": "medium",
                    "url": brute_url,
                    "evidence": f"Differential error message presence: '{marker}' in {count}/{len(user_responses)} responses",
                }
                findings.append(finding)
                break

        return findings

    def run(self, target, session=None):
        print_phase("Brute Force Testing")
        self.config.target_url = normalize_url(target)

        if session is None:
            session = get_session()
        if session is None:
            print_error("Cannot proceed without a valid HTTP session.")
            return

        all_findings = []

        login_info = self.detect_login_form(target, session)
        self.config.scan_data["authentication"]["login_found"] = login_info["found"]
        if login_info["found"]:
            self.config.scan_data["authentication"]["login_paths"].append(login_info["login_url"])

        user_enum_findings = self.test_user_enumeration_form(target, session)
        all_findings.extend(user_enum_findings)

        if login_info["found"]:
            usernames = self.enumerate_users(target, session)
            if not usernames:
                usernames = ["admin", "administrator", "root", "test", "user", "guest"]

            passwords = self.wordlists.DEFAULT_PASSWORDS

            internal_findings = self.bruteforce_internal(
                target, login_info["login_url"],
                usernames[:5], passwords[:10], session,
            )
            all_findings.extend(internal_findings)

            if _find_tool("hydra"):
                parsed = urlparse(target)
                service = "ssh" if (parsed.port == 22 or not parsed.port) else "http"
                hydra_findings = self.bruteforce_hydra(
                    target, service, usernames[:5], passwords[:10],
                )
                all_findings.extend(hydra_findings)

        for f in all_findings:
            if f not in self.config.findings:
                self.config.findings.append(f)

        if all_findings:
            print_good(f"Brute force testing complete: {len(all_findings)} finding(s).")
        else:
            print_info("Brute force testing complete: no findings.")
