import os
import tempfile
from urllib.parse import urlparse

from core.config import Config
from core.utils import (
    print_info, print_good, print_warning, print_error, print_vuln,
    print_phase, print_table, _capture_command_output, _find_tool,
)
from lib.wordlists import Wordlists
import logging


class ActiveDirectoryModule:
    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config
        self.wordlists = Wordlists()

    def check_tools(self):
        tools = {
            "kerbrute": _find_tool("kerbrute"),
            "ldapsearch": _find_tool("ldapsearch"),
            "nxc": _find_tool("nxc"),
            "secretsdump": _find_tool("secretsdump"),
            "getTGT": _find_tool("getTGT"),
            "GetNPUsers": _find_tool("GetNPUsers"),
            "Kerberoast": _find_tool("Kerberoast"),
        }
        available = {k: v for k, v in tools.items() if v}
        missing = [k for k, v in tools.items() if not v]

        if missing:
            print_warning(f"Missing AD tools: {', '.join(missing)}")
        if available:
            print_info(f"Available AD tools: {', '.join(available.keys())}")

        return tools

    def run_kerbrute_userenum(self, domain, dc, userlist):
        findings = []
        kerbrute_path = _find_tool("kerbrute")

        if not kerbrute_path:
            print_warning("kerbrute not found. Skipping user enumeration.")
            return findings

        print_info(f"Running kerbrute user enumeration against {dc}...")

        if not userlist:
            userlist = self.wordlists.SECLISTS_USERS_SHORT
            if not os.path.isfile(userlist):
                tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
                common_users = [
                    "administrator", "admin", "guest", "krbtgt", "root",
                    "test", "user", "svc", "backup", "sql",
                    "www", "mail", "ftp", "ldap", "dns",
                ]
                tmp.write("\n".join(common_users))
                tmp.close()
                userlist = tmp.name

        code, stdout, stderr = _capture_command_output(
            [kerbrute_path, "userenum", "--dc", dc, "-d", domain, userlist],
            timeout=120,
        )

        output = stdout + stderr
        valid_users = []
        for line in output.split("\n"):
            if "VALID" in line or "[+]" in line:
                username = line.split()[-1] if line.split() else ""
                if username:
                    valid_users.append(username)
                    finding = {
                        "type": "ad_user_enum",
                        "severity": "medium",
                        "domain": domain,
                        "dc": dc,
                        "username": username,
                        "source": "kerbrute",
                    }
                    findings.append(finding)
                    print_good(f"  Valid user: {username}")

        if valid_users:
            print_good(f"Kerbrute found {len(valid_users)} valid user(s).")
        else:
            print_info("Kerbrute did not confirm any valid users.")

        return findings

    def run_ldap_enumeration(self, target):
        findings = []
        ldapsearch_path = _find_tool("ldapsearch")

        if not ldapsearch_path:
            print_warning("ldapsearch not found. Skipping LDAP enumeration.")
            return findings

        parsed = urlparse(target)
        host = parsed.hostname
        port = parsed.port or 389

        print_info(f"Running LDAP enumeration against {host}:{port}...")

        base_dns = [
            f"DC={domain}" for domain in host.split(".")
        ]
        base_dn = ",".join(base_dns)

        anon_queries = [
            (["-x", "-H", f"ldap://{host}:{port}", "-b", base_dn, "(objectClass=*)"],
             "Anonymous bind query"),
            (["-x", "-H", f"ldap://{host}:{port}", "-b", base_dn, "(objectClass=user)"],
             "User enumeration"),
            (["-x", "-H", f"ldap://{host}:{port}", "-b", base_dn, "(objectClass=group)"],
             "Group enumeration"),
            (["-x", "-H", f"ldap://{host}:{port}", "-b", base_dn,
              "(&(objectClass=user)(adminCount=1))"],
             "Admin accounts"),
            (["-x", "-H", f"ldap://{host}:{port}", "-b", base_dn,
              "(&(objectClass=user)(servicePrincipalName=*))"],
             "Service accounts (SPN)"),
            (["-x", "-H", f"ldap://{host}:{port}", "-b", base_dn,
              "(&(objectClass=group)(cn=Domain Admins))"],
             "Domain Admins group"),
        ]

        for args, description in anon_queries:
            code, stdout, stderr = _capture_command_output(
                [ldapsearch_path] + args, timeout=30,
            )

            if code == 0 and stdout.strip():
                entries = stdout.strip().split("\n\n")
                entry_count = len([e for e in entries if e.strip()])

                finding = {
                    "type": "ldap_enumeration",
                    "severity": "high" if "admin" in description.lower() else "medium",
                    "host": host,
                    "port": port,
                    "query": description,
                    "results_count": entry_count,
                }
                findings.append(finding)
                print_warning(f"LDAP {description}: {entry_count} result(s)")

                if "user" in description.lower() or "admin" in description.lower():
                    for entry in entries:
                        cn_match = [line for line in entry.split("\n") if line.startswith("cn:")]
                        for cn_line in cn_match:
                            cn_value = cn_line.split(":", 1)[1].strip()
                            user_finding = {
                                "type": "ldap_user",
                                "severity": "info",
                                "host": host,
                                "cn": cn_value,
                                "source": description,
                            }
                            findings.append(user_finding)

        return findings

    def run_asrep_roasting(self, domain, dc, users_file=None):
        findings = []
        getnpusers_path = _find_tool("GetNPUsers")

        if not getnpusers_path:
            print_warning("GetNPUsers (impacket) not found. Skipping AS-REP roasting.")
            return findings

        print_info(f"Running AS-REP roasting against {domain}...")

        output_file = tempfile.mktemp(suffix=".hash")

        cmd = [
            getnpusers_path,
            f"{domain}/",
            "-no-pass",
            "-dc-ip", dc,
            "-format", "hashcat",
            "-outputfile", output_file,
        ]

        if users_file and os.path.isfile(users_file):
            cmd.extend(["-usersfile", users_file])

        code, stdout, stderr = _capture_command_output(cmd, timeout=60)

        output = stdout + stderr
        if os.path.isfile(output_file):
            try:
                with open(output_file, "r") as f:
                    hashes = f.read().strip()
                if hashes:
                    finding = {
                        "type": "asrep_roasting",
                        "severity": "high",
                        "domain": domain,
                        "dc": dc,
                        "hash_count": len(hashes.split("\n")),
                        "hash_file": output_file,
                    }
                    findings.append(finding)
                    print_vuln(
                        f"AS-REP roasting: {len(hashes.split(chr(10)))} hash(es) recovered"
                    )
                    for line in hashes.split("\n")[:3]:
                        print_info(f"  {line[:80]}...")
            except Exception:
                logging.exception("active_directory.py: exception")
                pass
        if "no entries" in output.lower() or "exception" in output.lower():
            print_info("No AS-REP roastable accounts found.")
        elif not findings:
            print_warning(f"GetNPUsers output: {stderr[:200]}")

        return findings

    def run_kerberoasting(self, domain, dc):
        findings = []
        getuserspns_path = _find_tool("GetUserSPNs") or _find_tool("Kerberoast")

        if not getuserspns_path:
            print_warning("GetUserSPNs/Kerberoast not found. Skipping Kerberoasting.")
            return findings

        print_info(f"Running Kerberoasting against {domain}...")

        output_file = tempfile.mktemp(suffix=".hash")

        cmd = [
            getuserspns_path,
            f"{domain}/",
            "-dc-ip", dc,
            "-format", "hashcat",
            "-outputfile", output_file,
        ]

        code, stdout, stderr = _capture_command_output(cmd, timeout=60)

        output = stdout + stderr
        if os.path.isfile(output_file):
            try:
                with open(output_file, "r") as f:
                    hashes = f.read().strip()
                if hashes:
                    hash_lines = hashes.split("\n")
                    finding = {
                        "type": "kerberoasting",
                        "severity": "high",
                        "domain": domain,
                        "dc": dc,
                        "spn_count": len(hash_lines),
                        "hash_file": output_file,
                    }
                    findings.append(finding)
                    print_vuln(
                        f"Kerberoasting: {len(hash_lines)} SPN hash(es) recovered"
                    )
                    for line in hash_lines[:3]:
                        spn = line.split("*")[2] if "*" in line else "unknown"
                        print_info(f"  SPN: {spn[:80]}")
            except Exception:
                logging.exception("active_directory.py: exception")
                pass
        if not findings:
            if "no entries" in output.lower() or "exception" in output.lower():
                print_info("No Kerberoastable accounts found.")
            else:
                print_warning(f"Kerberoasting output: {stderr[:200]}")

        return findings

    def run_nxc_enum(self, domain, dc):
        findings = []
        nxc_path = _find_tool("nxc")

        if not nxc_path:
            print_warning("nxc (netexec) not found. Skipping NXC enumeration.")
            return findings

        print_info(f"Running NXC SMB enumeration against {dc}...")

        code, stdout, stderr = _capture_command_output(
            [nxc_path, "smb", dc, "-u", "''", "-p", "''", "--shares"],
            timeout=30,
        )

        output = stdout + stderr
        if "SMB" in output or "SHARE" in output.upper():
            finding = {
                "type": "nxc_smb_enum",
                "severity": "medium",
                "domain": domain,
                "dc": dc,
                "output": output[:500],
            }
            findings.append(finding)
            print_warning(f"NXC SMB enumeration results:\n{output[:300]}")

        code, stdout, stderr = _capture_command_output(
            [nxc_path, "ldap", dc, "-u", "''", "-p", "''", "--users"],
            timeout=30,
        )

        output = stdout + stderr
        if "user" in output.lower():
            finding = {
                "type": "nxc_ldap_enum",
                "severity": "medium",
                "domain": domain,
                "dc": dc,
                "output": output[:500],
            }
            findings.append(finding)
            print_warning(f"NXC LDAP enumeration results:\n{output[:300]}")

        return findings

    def run_nxc_bruteforce(self, domain, dc, usernames=None, passwords=None):
        findings = []
        nxc_path = _find_tool("nxc")

        if not nxc_path:
            print_warning("nxc not found. Skipping brute force.")
            return findings

        if not usernames:
            usernames = ["administrator", "admin", "guest", "test", "user"]
        if not passwords:
            passwords = self.wordlists.DEFAULT_PASSWORDS[:10]

        print_info(f"Running NXC SMB brute force against {dc}...")

        for username in usernames:
            for password in passwords:
                code, stdout, stderr = _capture_command_output(
                    [nxc_path, "smb", dc, "-u", username, "-p", password],
                    timeout=10,
                )

                output = stdout + stderr
                if "[+]" in output or "Pwn3d" in output:
                    finding = {
                        "type": "ad_bruteforce",
                        "severity": "critical",
                        "domain": domain,
                        "dc": dc,
                        "username": username,
                        "password": password,
                        "source": "nxc_smb",
                    }
                    findings.append(finding)
                    print_vuln(f"Valid credentials: {domain}\\{username}:{password}")
                    break

        if not findings:
            print_info("NXC brute force did not find valid credentials.")

        return findings

    def run(self, target, session=None, config=None):
        print_phase("Active Directory Testing")
        parsed = urlparse(target)
        dc = parsed.hostname
        domain = ".".join(dc.split(".")[1:]) if "." in dc else dc

        print_info(f"Domain: {domain}, DC: {dc}")

        tools = self.check_tools()

        all_findings = []

        user_enum = self.run_kerbrute_userenum(domain, dc, None)
        all_findings.extend(user_enum)

        ldap_enum = self.run_ldap_enumeration(target)
        all_findings.extend(ldap_enum)

        asrep = self.run_asrep_roasting(domain, dc, None)
        all_findings.extend(asrep)

        kerberoast = self.run_kerberoasting(domain, dc)
        all_findings.extend(kerberoast)

        nxc_enum = self.run_nxc_enum(domain, dc)
        all_findings.extend(nxc_enum)

        nxc_brute = self.run_nxc_bruteforce(domain, dc)
        all_findings.extend(nxc_brute)

        for f in all_findings:
            if f not in self.config.findings:
                self.config.findings.append(f)

        if all_findings:
            print_good(f"AD testing complete: {len(all_findings)} finding(s).")
        else:
            print_info("AD testing complete: no findings.")
