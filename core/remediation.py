#!/usr/bin/env python3
"""
Remediation Guidance Engine for SysVoidScan v3.0 Sentinel.
Provides actionable remediation advice per vulnerability type with references.
"""

import json
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict

from core.finding import FindingType, Finding


@dataclass
class RemediationAdvice:
    finding_type: str
    severity: str
    title: str
    description: str
    impact: str
    remediation_steps: List[str]
    references: List[str]
    compliance: Dict[str, str]
    code_example: str


REMEDIATION_DB: Dict[str, Dict[str, RemediationAdvice]] = {
    "sqli": {
        "critical": RemediationAdvice(
            finding_type="sqli",
            severity="critical",
            title="SQL Injection",
            description="User input is concatenated directly into SQL queries allowing attackers to manipulate the database.",
            impact="Full database compromise, data exfiltration, authentication bypass, remote code execution.",
            remediation_steps=[
                "Use parameterized queries (prepared statements) for ALL database interactions.",
                "Implement stored procedures with parameterized inputs.",
                "Apply input validation with whitelisting for expected data types.",
                "Deploy a Web Application Firewall (WAF) as defense-in-depth.",
                "Apply principle of least privilege to database accounts.",
                "Enable database query logging for monitoring.",
                "Perform code review on all database interaction points.",
            ],
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                "https://cwe.mitre.org/data/definitions/89.html",
            ],
            compliance={"OWASP Top 10": "A03:2021", "PCI DSS": "6.5.1", "NIST": "SA-11"},
            code_example='-- BAD: cursor.execute("SELECT * FROM users WHERE id=" + user_id)\n-- GOOD: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        ),
    },
    FindingType.XSS_STORED.value: {
        "high": RemediationAdvice(
            finding_type=FindingType.XSS_STORED.value,
            severity="high",
            title="Stored Cross-Site Scripting (XSS)",
            description="User-supplied data is stored and later rendered without proper encoding, allowing persistent script execution.",
            impact="Session hijacking, account takeover, credential theft, malware distribution, defacement.",
            remediation_steps=[
                "HTML-encode all user-supplied data before rendering (context-aware output encoding).",
                "Implement Content Security Policy (CSP) headers with nonce-based script loading.",
                "Use HttpOnly and Secure flags on session cookies.",
                "Validate and sanitize input on both client and server side.",
                "Use frameworks that auto-escape by default (React, Django templates).",
                "Deploy DOMPurify or similar sanitization for rich text inputs.",
                "Implement Subresource Integrity (SRI) for external scripts.",
            ],
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                "https://cwe.mitre.org/data/definitions/79.html",
            ],
            compliance={"OWASP Top 10": "A03:2021", "PCI DSS": "6.5.7"},
            code_example='// BAD: element.innerHTML = userInput;\n// GOOD: element.textContent = userInput;',
        ),
    },
    FindingType.XSS_REFLECTED.value: {
        "high": RemediationAdvice(
            finding_type=FindingType.XSS_REFLECTED.value,
            severity="high",
            title="Reflected Cross-Site Scripting (XSS)",
            description="User input is reflected in the response without encoding, enabling reflected script execution.",
            impact="Session hijacking, phishing, credential theft, arbitrary actions on behalf of users.",
            remediation_steps=[
                "Apply context-aware output encoding on all reflected parameters.",
                "Implement Content Security Policy (CSP) headers.",
                "Use URL and input validation with strict whitelisting.",
                "Enable X-XSS-Protection and X-Content-Type-Options headers.",
                "Encode data in HTML, JavaScript, CSS, and URL contexts appropriately.",
            ],
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                "https://cwe.mitre.org/data/definitions/79.html",
            ],
            compliance={"OWASP Top 10": "A03:2021"},
            code_example='// Python: from markupsafe import escape; output = escape(user_input)',
        ),
    },
    "lfi": {
        "high": RemediationAdvice(
            finding_type="lfi",
            severity="high",
            title="Local File Inclusion (LFI)",
            description="User-controlled file paths allow reading of arbitrary files from the server filesystem.",
            impact="Reading /etc/passwd, application source code, configuration files with credentials, SSH keys.",
            remediation_steps=[
                "Never use user input directly in file operations.",
                "Implement a whitelist of allowed files/directories.",
                "Use chroot or containerization to limit filesystem access.",
                "Remove path traversal sequences (../) and validate canonical paths.",
                "Run the application with minimal filesystem permissions.",
                "Use chdir() before file operations to prevent traversal.",
                "Disable sensitive PHP functions if applicable (file_get_contents, include).",
            ],
            references=[
                "https://cwe.mitre.org/data/definitions/98.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/File_Inclusion_Prevention_Cheat_Sheet.html",
            ],
            compliance={"OWASP Top 10": "A03:2021", "CWE": "98"},
            code_example='# BAD: include($_GET[\'page\'])\n# GOOD: allowed = ["home", "about"]; if page in allowed: include(f"pages/{page}.html")',
        ),
    },
    "cmdi": {
        "critical": RemediationAdvice(
            finding_type="cmdi",
            severity="critical",
            title="OS Command Injection",
            description="User input is passed to system commands allowing arbitrary command execution on the server.",
            impact="Full server compromise, data exfiltration, lateral movement, ransomware deployment.",
            remediation_steps=[
                "NEVER pass user input to system commands.",
                "Use language-native APIs instead of shell commands.",
                "If shell commands are unavoidable, use parameterized execution (subprocess.run with args list).",
                "Apply strict input validation with whitelisting.",
                "Use chroot or containerization for command execution.",
                "Run the application with minimal OS privileges.",
                "Disable dangerous shell functions (exec, system, popen).",
                "Implement AppArmor or SELinux profiles.",
            ],
            references=[
                "https://cwe.mitre.org/data/definitions/78.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
            ],
            compliance={"OWASP Top 10": "A03:2021", "PCI DSS": "6.5.4"},
            code_example='# BAD: os.system("ping " + user_input)\n# GOOD: subprocess.run(["ping", "-c", "1", validated_input])',
        ),
    },
    "ssrf": {
        "high": RemediationAdvice(
            finding_type="ssrf",
            severity="high",
            title="Server-Side Request Forgery (SSRF)",
            description="Application fetches URLs based on user input, enabling access to internal services and cloud metadata.",
            impact="Cloud credential theft (169.254.169.254), internal network scanning, service exploitation.",
            remediation_steps=[
                "Implement URL allowlisting for server-side requests.",
                "Block requests to private IP ranges (RFC 1918, loopback, link-local).",
                "Use network segmentation to isolate sensitive services.",
                "Disable unnecessary URL schemes (file://, gopher://, dict://).",
                "Validate and normalize URLs before fetching.",
                "Use a dedicated proxy for external requests.",
                "Implement DNS resolution validation before HTTP requests.",
            ],
            references=[
                "https://cwe.mitre.org/data/definitions/918.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
            ],
            compliance={"OWASP Top 10": "A10:2021"},
            code_example='# BAD: requests.get(user_url)\n# GOOD: if urlparse(url).hostname not in ALLOWED_HOSTS: raise ValueError("Blocked")',
        ),
    },
    FindingType.OPEN_REDIRECT.value: {
        "medium": RemediationAdvice(
            finding_type=FindingType.OPEN_REDIRECT.value,
            severity="medium",
            title="Open Redirect",
            description="Application redirects users to attacker-controlled URLs via unvalidated redirect parameters.",
            impact="Phishing attacks, OAuth token theft, malware distribution via trusted domains.",
            remediation_steps=[
                "Implement an allowlist of permitted redirect destinations.",
                "Only redirect to relative paths within the application.",
                "Validate the redirect URL matches the current domain.",
                "Display a warning page before external redirects.",
                "Remove or validate the 'next' and 'return_to' parameters.",
            ],
            references=[
                "https://cwe.mitre.org/data/definitions/601.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
            ],
            compliance={"OWASP Top 10": "A01:2021"},
            code_example='# BAD: redirect(request.args.get("next"))\n# GOOD: if next_url.startswith("/"): redirect(next_url) else: redirect("/")',
        ),
    },
    "ssti": {
        "critical": RemediationAdvice(
            finding_type="ssti",
            severity="critical",
            title="Server-Side Template Injection (SSTI)",
            description="User input is embedded in server-side templates allowing template logic execution.",
            impact="Remote code execution, full server compromise, data exfiltration.",
            remediation_steps=[
                "NEVER embed raw user input in template rendering calls.",
                "Use template engines with sandboxed execution contexts.",
                "Implement context-aware template variable handling (pass as data, not template code).",
                "Use auto-escaping features of template engines.",
                "Avoid user-controlled template names or paths.",
                "Enable template engine sandboxing (Jinja2 SandboxedEnvironment).",
            ],
            references=[
                "https://portswigger.net/web-security/server-side-template-injection",
                "https://cwe.mitre.org/data/definitions/1336.html",
            ],
            compliance={"OWASP Top 10": "A03:2021"},
            code_example='# BAD: Template(user_input).render()\n# GOOD: Template("Hello {{ name }}").render(name=user_input)',
        ),
    },
    "xxe": {
        "high": RemediationAdvice(
            finding_type="xxe",
            severity="high",
            title="XML External Entity (XXE)",
            description="XML parser processes external entities, enabling file read, SSRF, and denial of service.",
            impact="Reading server files, SSRF to internal services, denial of service via billion laughs.",
            remediation_steps=[
                "Disable DTD processing and external entity resolution in XML parsers.",
                "Use JSON instead of XML where possible.",
                "If XML is required, use libxml2 with XML_PARSE_NOENT disabled.",
                "Validate and sanitize XML input before processing.",
                "Use schema validation to restrict XML structure.",
                "Deploy WAF rules to detect XXE payloads.",
            ],
            references=[
                "https://cwe.mitre.org/data/definitions/611.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
            ],
            compliance={"OWASP Top 10": "A05:2021", "PCI DSS": "6.5.9"},
            code_example='# Python lxml: parser = etree.XMLParser(resolve_entities=False, no_network=True)',
        ),
    },
    "jwt": {
        "high": RemediationAdvice(
            finding_type="jwt",
            severity="high",
            title="JWT Implementation Vulnerability",
            description="JSON Web Token implementation has weaknesses enabling forgery, algorithm confusion, or key extraction.",
            impact="Authentication bypass, privilege escalation, impersonation.",
            remediation_steps=[
                "Always validate JWT signatures with a strong algorithm (RS256/ES256, not HS256 with weak keys).",
                "Never accept the 'none' algorithm.",
                "Validate the 'alg' header matches the expected algorithm.",
                "Implement token expiration (exp claim) with reasonable TTLs.",
                "Use asymmetric algorithms (RS256) for public-facing APIs.",
                "Store JWT secrets in secure vaults, not source code.",
                "Implement token revocation and refresh token rotation.",
                "Validate 'iss', 'aud', and 'nbf' claims.",
            ],
            references=[
                "https://cwe.mitre.org/data/definitions/347.html",
                "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
            ],
            compliance={"OWASP Top 10": "A07:2021", "PCI DSS": "6.5.10"},
            code_example='# BAD: jwt.decode(token, options={"verify_signature": False})\n# GOOD: jwt.decode(token, key, algorithms=["RS256"], audience="expected_aud")',
        ),
    },
    "crlf": {
        "medium": RemediationAdvice(
            finding_type="crlf",
            severity="medium",
            title="CRLF Injection",
            description="User input injects carriage return/line feed characters into HTTP headers or responses.",
            impact="HTTP response splitting, XSS, cache poisoning, session fixation.",
            remediation_steps=[
                "Strip or encode CR (\\r) and LF (\\n) characters from user input.",
                "Validate header values against a strict character set.",
                "Use framework-provided header setting methods.",
                "Implement Content-Security-Policy headers.",
            ],
            references=[
                "https://cwe.mitre.org/data/definitions/113.html",
                "https://portswigger.net/web-security/request-smuggling",
            ],
            compliance={"OWASP Top 10": "A03:2021"},
            code_example='# BAD: response.headers["Location"] = user_input\n# GOOD: response.headers["Location"] = user_input.replace("\\r", "").replace("\\n", "")',
        ),
    },
    FindingType.CACHE_POISONING.value: {
        "medium": RemediationAdvice(
            finding_type=FindingType.CACHE_POISONING.value,
            severity="medium",
            title="Web Cache Poisoning",
            description="Unkeyed inputs manipulate cache behavior to serve poisoned responses to other users.",
            impact="XSS delivery, credential theft, defacement for all cached users.",
            remediation_steps=[
                "Identify and key all unkeyed inputs (X-Forwarded-Host, X-Original-URL).",
                "Cache only responses with safe status codes and content types.",
                "Implement cache-busting for sensitive operations.",
                "Use Vary headers appropriately.",
                "Deploy WAF rules to detect cache poisoning attempts.",
            ],
            references=[
                "https://portswigger.net/web-security/web-cache-poisoning",
                "https://cwe.mitre.org/data/definitions/524.html",
            ],
            compliance={"OWASP Top 10": "A04:2021"},
            code_example='# Cache Key should include: URL + Host + all Vary headers + relevant custom headers',
        ),
    },
    "http.smuggling": {
        "high": RemediationAdvice(
            finding_type="http.smuggling",
            severity="high",
            title="HTTP Request Smuggling",
            description="Discrepancies between front-end and back-end servers allow request tunneling and cache poisoning.",
            impact="Request hijacking, cache poisoning, XSS delivery, credential theft.",
            remediation_steps=[
                "Ensure consistent HTTP parsing across all servers and proxies.",
                "Disable HTTP/1.0 support where possible.",
                "Use HTTP/2 end-to-end to avoid parsing ambiguities.",
                "Normalize Transfer-Encoding headers.",
                "Set explicit Content-Length headers.",
                "Deploy WAF rules to detect smuggling payloads.",
            ],
            references=[
                "https://portswigger.net/web-security/request-smuggling",
                "https://cwe.mitre.org/data/definitions/444.html",
            ],
            compliance={"OWASP Top 10": "A05:2021"},
            code_example='# Ensure all proxies/servers agree on request boundaries. Use HTTP/2 when possible.',
        ),
    },
    "oauth": {
        "high": RemediationAdvice(
            finding_type="oauth",
            severity="high",
            title="OAuth Misconfiguration",
            description="OAuth implementation flaws allow token theft, open redirect, or authorization bypass.",
            impact="Account takeover, token theft, unauthorized access to protected resources.",
            remediation_steps=[
                "Validate the redirect_uri against a strict allowlist.",
                "Use PKCE (Proof Key for Code Exchange) for all OAuth flows.",
                "Validate state parameter to prevent CSRF.",
                "Use authorization_code grant (not implicit).",
                "Validate token audience and issuer claims.",
                "Implement token binding and DPoP.",
            ],
            references=[
                "https://cwe.mitre.org/data/definitions/601.html",
                "https://oauth.net/2/pkce/",
            ],
            compliance={"OWASP Top 10": "A07:2021"},
            code_example='# Always use PKCE: code_verifier = secrets.token_urlsafe(32); code_challenge = sha256(code_verifier)',
        ),
    },
    FindingType.NOSQL_INJECTION.value: {
        "high": RemediationAdvice(
            finding_type=FindingType.NOSQL_INJECTION.value,
            severity="high",
            title="NoSQL Injection",
            description="NoSQL query operators in user input allow data extraction or authentication bypass.",
            impact="Data exfiltration, authentication bypass, data manipulation.",
            remediation_steps=[
                "Use typed queries instead of string concatenation.",
                "Validate input types (expecting string, reject objects/arrays).",
                "Use ORM/ODM query builders with parameterized operations.",
                "Apply input validation with strict type checking.",
                "Use least-privilege database accounts.",
            ],
            references=[
                "https://cwe.mitre.org/data/definitions/943.html",
                "https://www.owasp.org/index.php/Testing_for_NoSQL_injection",
            ],
            compliance={"OWASP Top 10": "A03:2021"},
            code_example='# BAD: db.users.find({"username": request.json["username"], "password": request.json["password"]})\n# GOOD: validate type; db.users.find_one({"username": str(username), "password": str(password)})',
        ),
    },
    FindingType.LDAP_INJECTION.value: {
        "high": RemediationAdvice(
            finding_type=FindingType.LDAP_INJECTION.value,
            severity="high",
            title="LDAP Injection",
            description="User input is incorporated into LDAP queries without sanitization, enabling query manipulation.",
            impact="Authentication bypass, information disclosure, directory service manipulation.",
            remediation_steps=[
                "Use parameterized LDAP queries with proper escaping.",
                "Validate and encode special LDAP characters (\\, *, (, ), NUL).",
                "Use least-privilege LDAP service accounts.",
                "Implement input whitelisting for expected formats.",
                "Use frameworks with built-in LDAP safety features.",
            ],
            references=[
                "https://cwe.mitre.org/data/definitions/90.html",
                "https://www.owasp.org/index.php/LDAP_injection",
            ],
            compliance={"OWASP Top 10": "A03:2021"},
            code_example='# Escape: (, ), *, \\, NUL → \\28, \\29, \\2a, \\5c, \\00',
        ),
    },
    "auth.weak": {
        "high": RemediationAdvice(
            finding_type="auth.weak",
            severity="high",
            title="Weak Authentication Mechanism",
            description="Authentication system has flaws allowing brute force, credential stuffing, or session fixation.",
            impact="Account takeover, unauthorized access, data breach.",
            remediation_steps=[
                "Implement rate limiting on authentication endpoints (5 attempts/15 min).",
                "Deploy account lockout or progressive delays after failed attempts.",
                "Use multi-factor authentication (MFA).",
                "Enforce strong password policies (min 12 chars, complexity).",
                "Implement CAPTCHA after multiple failures.",
                "Use breached password databases (HIBP k-anonymity).",
                "Regenerate session IDs after authentication.",
                "Implement secure session management (HttpOnly, Secure, SameSite).",
            ],
            references=[
                "https://cwe.mitre.org/data/definitions/307.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            ],
            compliance={"OWASP Top 10": "A07:2021", "PCI DSS": "8.1"},
            code_example='# Rate limit: @limiter.limit("5 per minute")\ndef login(): ...',
        ),
    },
    "info.disclosure": {
        "medium": RemediationAdvice(
            finding_type="info.disclosure",
            severity="medium",
            title="Sensitive Data Exposure",
            description="Sensitive information (credentials, PII, tokens) is exposed in responses, headers, or source code.",
            impact="Credential theft, privacy violations, regulatory penalties.",
            remediation_steps=[
                "Remove sensitive data from HTTP responses and error messages.",
                "Do not include credentials in source code or version control.",
                "Use environment variables or secret management tools.",
                "Implement proper error handling (no stack traces in production).",
                "Encrypt sensitive data at rest and in transit.",
                "Use Content-Security-Policy to prevent data exfiltration.",
                "Implement DLP (Data Loss Prevention) controls.",
            ],
            references=[
                "https://cwe.mitre.org/data/definitions/200.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            ],
            compliance={"OWASP Top 10": "A02:2021", "PCI DSS": "3.4"},
            code_example='# Use vaults: os.environ.get("DB_PASSWORD") not hardcoded strings',
        ),
    },
    "idor": {
        "high": RemediationAdvice(
            finding_type="idor",
            severity="high",
            title="Broken Access Control",
            description="Authorization checks are missing or insufficient, allowing privilege escalation or IDOR.",
            impact="Unauthorized data access, privilege escalation, account takeover.",
            remediation_steps=[
                "Implement authorization checks on ALL endpoints (server-side).",
                "Deny by default; require explicit grants for each resource.",
                "Use role-based access control (RBAC) or attribute-based (ABAC).",
                "Validate resource ownership before granting access.",
                "Implement directory listing prevention.",
                "Log and monitor access control failures.",
                "Use indirect object references (maps) instead of exposing IDs.",
            ],
            references=[
                "https://cwe.mitre.org/data/definitions/284.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
            ],
            compliance={"OWASP Top 10": "A01:2021", "PCI DSS": "7.1"},
            code_example='# Check ownership: if resource.owner_id != current_user.id: abort(403)',
        ),
    },
    "host_header.injection": {
        "medium": RemediationAdvice(
            finding_type="host_header.injection",
            severity="medium",
            title="Host Header Injection",
            description="User-controlled Host header is used in responses, links, or email generation without validation.",
            impact="Password reset poisoning, cache poisoning, phishing.",
            remediation_steps=[
                "Validate the Host header against a whitelist of allowed values.",
                "Use SERVER_NAME in web server configuration.",
                "Do not use Host header in URL generation without validation.",
                "Implement DNS rebinding protection.",
            ],
            references=[
                "https://cwe.mitre.org/data/definitions/644.html",
                "https://portswigger.net/web-security/host-header-injection",
            ],
            compliance={"OWASP Top 10": "A03:2021"},
            code_example='# Django: ALLOWED_HOSTS = ["example.com"]\n# Nginx: server_name example.com;',
        ),
    },
    "api.abuse": {
        "medium": RemediationAdvice(
            finding_type="api.abuse",
            severity="medium",
            title="API Security Misconfiguration",
            description="API endpoints lack proper rate limiting, validation, or security controls.",
            impact="Data exposure, unauthorized actions, denial of service.",
            remediation_steps=[
                "Implement rate limiting on all API endpoints.",
                "Use API keys or OAuth for authentication.",
                "Validate Content-Type headers.",
                "Implement request/response schema validation.",
                "Use pagination and rate limits to prevent data overexposure.",
                "Deploy API gateway with security policies.",
                "Enable API logging and monitoring.",
            ],
            references=[
                "https://owasp.org/API-Security/",
                "https://cwe.mitre.org/data/definitions/770.html",
            ],
            compliance={"OWASP Top 10": "A04:2021"},
            code_example='# Rate limit: @app.route("/api/data") @limiter.limit("100/minute")',
        ),
    },
    "wordpress.vuln": {
        "high": RemediationAdvice(
            finding_type="wordpress.vuln",
            severity="high",
            title="WordPress Vulnerability",
            description="WordPress core, theme, or plugin has known vulnerabilities or misconfigurations.",
            impact="Site compromise, defacement, malware injection, data theft.",
            remediation_steps=[
                "Update WordPress core, themes, and plugins to latest versions.",
                "Remove unused plugins and themes.",
                "Implement Web Application Firewall (WAF).",
                "Disable XML-RPC if not needed.",
                "Restrict access to wp-admin and wp-login.php.",
                "Use strong, unique admin passwords.",
                "Implement two-factor authentication.",
                "Disable file editing in wp-admin (DISALLOW_FILE_EDIT).",
                "Set proper file permissions (644 files, 755 directories).",
            ],
            references=[
                "https://codex.wordpress.org/Hardening_WordPress",
                "https://cwe.mitre.org/data/definitions/693.html",
            ],
            compliance={"OWASP Top 10": "A06:2021"},
            code_example='define("DISALLOW_FILE_EDIT", true); // wp-config.php',
        ),
    },
    "reverse_shell": {
        "critical": RemediationAdvice(
            finding_type="reverse_shell",
            severity="critical",
            title="Reverse Shell / Remote Code Execution",
            description="Attacker has achieved code execution on the server via reverse shell or webshell.",
            impact="Full server compromise, data exfiltration, lateral movement, persistent access.",
            remediation_steps=[
                "IMMEDIATE: Isolate the compromised server from the network.",
                "IMMEDIATE: Kill unauthorized processes and connections.",
                "Analyze logs to determine initial attack vector.",
                "Patch the vulnerability that enabled code execution.",
                "Reset all credentials (database, application, system).",
                "Implement network segmentation.",
                "Deploy EDR/behavioral monitoring.",
                "Review and harden server configuration.",
                "Implement egress filtering to block reverse connections.",
            ],
            references=[
                "https://attack.mitre.org/techniques/T1059/",
                "https://cwe.mitre.org/data/definitions/78.html",
            ],
            compliance={"PCI DSS": "6.5.1", "NIST": "IR-4"},
            code_example='netstat -tulpn  # Find suspicious connections\nkill -9 <PID>  # Terminate malicious process',
        ),
    },
}


# Alias de categoria: cubren variantes granulares sin entrada propia
# (p. ej. xss.dom -> entrada de XSS reflejado, nosql.operator -> nosql.injection)
REMEDIATION_DB.setdefault("xss", REMEDIATION_DB[FindingType.XSS_REFLECTED.value])
REMEDIATION_DB.setdefault("open_redirect", REMEDIATION_DB[FindingType.OPEN_REDIRECT.value])
REMEDIATION_DB.setdefault("nosql", REMEDIATION_DB[FindingType.NOSQL_INJECTION.value])
REMEDIATION_DB.setdefault("ldap", REMEDIATION_DB[FindingType.LDAP_INJECTION.value])


def _lookup_entry(finding_type: str) -> Optional[Dict[str, "RemediationAdvice"]]:
    """Resolve a finding type (granular or category) to its DB entry.

    The DB is keyed either by an exact FindingType value (e.g. "xss.stored")
    or by a category prefix (e.g. "sqli" matches "sqli.error", "sqli.union").
    """
    if hasattr(finding_type, "value"):
        finding_type = finding_type.value
    ft = str(finding_type or "").strip().lower()
    if not ft:
        return None
    if ft in REMEDIATION_DB:
        return REMEDIATION_DB[ft]
    best_key = None
    for key in REMEDIATION_DB:
        if ft.startswith(key + "."):
            if best_key is None or len(key) > len(best_key):
                best_key = key
    if best_key is not None:
        return REMEDIATION_DB[best_key]
    return None


def get_remediation(finding_type: str, severity: str = "high") -> Optional[RemediationAdvice]:
    """Get remediation advice for a finding type."""
    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
    }
    normalized = severity_map.get(str(severity).lower(), "high")
    entry = _lookup_entry(finding_type)
    if entry:
        if normalized in entry:
            return entry[normalized]
        first_severity = next(iter(entry))
        return entry[first_severity]
    return None


def get_remediation_summary(findings: List[Finding]) -> Dict:
    """Generate a summary of remediation priorities from findings."""
    priority_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    type_counts: Dict[str, int] = {}
    remediation_plan: List[Dict] = []
    for f in findings:
        sev = f.severity.lower() if f.severity else "info"
        if sev in priority_counts:
            priority_counts[sev] += 1
        ft = f.type.value if hasattr(f.type, "value") else str(f.type)
        type_counts[ft] = type_counts.get(ft, 0) + 1
    for ft, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        advice = get_remediation(ft)
        if advice:
            remediation_plan.append({
                "finding_type": ft,
                "occurrences": count,
                "remediation_steps": advice.remediation_steps[:3],
                "priority": "IMMEDIATE" if ft == "reverse_shell" or ft.startswith(
                    ("sqli.", "cmdi.", "lfi.", "sti.", "xxe.", "file_upload.")
                ) else "HIGH",
            })
    return {
        "severity_counts": priority_counts,
        "type_counts": type_counts,
        "total_findings": len(findings),
        "top_remediations": remediation_plan,
    }


def export_remediation_report(findings: List[Finding], format: str = "json") -> str:
    """Export remediation guidance as JSON."""
    summary = get_remediation_summary(findings)
    detailed = []
    seen = set()
    for f in findings:
        ft = f.type.value if hasattr(f.type, "value") else str(f.type)
        if ft not in seen:
            seen.add(ft)
            advice = get_remediation(ft, f.severity)
            if advice:
                detailed.append(asdict(advice))
    report = {"summary": summary, "detailed_remediations": detailed}
    return json.dumps(report, indent=2, default=str)
