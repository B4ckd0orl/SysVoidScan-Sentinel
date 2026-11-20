import uuid
import time
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any


class FindingType(Enum):
    """Complete taxonomy of vulnerability types."""
    # SQL Injection
    SQLI_ERROR = "sqli.error"
    SQLI_BLIND_BOOLEAN = "sqli.blind.boolean"
    SQLI_BLIND_TIME = "sqli.blind.time"
    SQLI_UNION = "sqli.union"
    SQLI_OOB = "sqli.oob"
    SQLI_STACKED = "sqli.stacked"

    # XSS
    XSS_REFLECTED = "xss.reflected"
    XSS_STORED = "xss.stored"
    XSS_DOM = "xss.dom"
    XSS_BLIND = "xss.blind"
    XSS_HEIST = "xss.heist"

    # SSRF
    SSRF_SERVER = "ssrf.server"
    SSRF_BLIND = "ssrf.blind"
    SSRF_CLOUD = "ssrf.cloud"
    SSRF_PROTOCOL = "ssrf.protocol"

    # Command Injection
    CMDI_DIRECT = "cmdi.direct"
    CMDI_BLIND = "cmdi.blind"
    CMDI_TIMED = "cmdi.timed"

    # File Inclusion
    LFI_LOCAL = "lfi.local"
    LFI_RFI = "lfi.rfi"
    LFI_LOG_POISON = "lfi.log_poison"
    LFI_PHP_WRAPPER = "lfi.php_wrapper"

    # SSTI
    SSTI_RCE = "ssti.rce"
    SSTI_FILE_READ = "ssti.file_read"

    # XXE
    XXE_FILE_READ = "xxe.file_read"
    XXE_SSRF = "xxe.ssrf"
    XXE_RCE = "xxe.rce"
    XXE_BLIND = "xxe.blind"

    # File Upload
    FILE_UPLOAD_WEBSHELL = "file_upload.webshell"
    FILE_UPLOAD_POLYGLOT = "file_upload.polyglot"
    FILE_UPLOAD_BYPASS = "file_upload.bypass"

    # Authentication
    JWT_NONE_ALG = "jwt.none_alg"
    JWT_WEAK_SECRET = "jwt.weak_secret"
    JWT_CONFUSION = "jwt.confusion"
    JWT_KEY_TRAVERSAL = "jwt.kid_traversal"

    # Open Redirect
    OPEN_REDIRECT = "open_redirect.reflected"
    OPEN_REDIRECT_FRAMEWORK = "open_redirect.framework"

    # CRLF
    CRLF_HEADER_INJECTION = "crlf.header_injection"
    CRLF_COOKIE_INJECTION = "crlf.cookie_injection"

    # CSRF
    CSRF_TOKEN_ABSENT = "csrf.token_absent"
    CSRF_SAMESITE_NONE = "csrf.samesite_none"

    # IDOR
    IDOR_NUMERIC = "idor.numeric"
    IDOR_UUID = "idor.uuid"
    IDOR_PATH = "idor.path"

    # Mass Assignment
    MASS_ASSIGNMENT = "mass_assignment.privilege"

    # NoSQL
    NOSQL_INJECTION = "nosql.injection"
    NOSQL_OPERATOR = "nosql.operator"

    # LDAP
    LDAP_INJECTION = "ldap.injection"
    LDAP_AUTH_BYPASS = "ldap.auth_bypass"

    # Deserialization
    DESER_JAVA = "deser.java"
    DESER_PHP = "deser.php"
    DESER_PYTHON = "deser.python"
    DESER_DOTNET = "deser.dotnet"

    # WebSocket
    WS_HIJACK = "websocket.hijack"
    WS_INJECTION = "websocket.injection"

    # OAuth
    OAUTH_TOKEN_SUB = "oauth.token_substitution"
    OAUTH_REDIRECT = "oauth.redirect_manipulation"
    OAUTH_PKCE_DOWNGRADE = "oauth.pkce_downgrade"

    # GraphQL
    GQL_INTROSPECTION = "graphql.introspection"
    GQL_BATCHING = "graphql.batching"
    GQL_MUTATION_ABUSE = "graphql.mutation_abuse"

    # HTTP
    SMUGGLING_CLTE = "http.smuggling.clte"
    SMUGGLING_TECL = "http.smuggling.tecl"
    SMUGGLING_H2 = "http.smuggling.h2"
    CACHE_POISONING = "http.cache_poisoning"

    # Race Condition
    RACE_CONDITION = "race_condition"

    # Infrastructure
    HEADER_MISSING = "header.security_missing"
    COOKIE_INSECURE = "cookie.insecure"
    CORS_MISCONFIG = "cors.misconfiguration"
    TLS_WEAK = "tls.weak_protocol"

    # Cloud
    AWS_METADATA = "cloud.aws_metadata"
    GCP_METADATA = "cloud.gcp_metadata"
    AZURE_METADATA = "cloud.azure_metadata"
    DOCKER_EXPOSED = "cloud.docker_api"
    K8S_EXPOSED = "cloud.k8s_api"

    # Supply Chain
    DEPENDENCY_VULN = "supply_chain.dependency"
    SECRETS_EXPOSED = "supply_chain.secrets"

    # Info
    INFO_DISCLOSURE = "info.disclosure"
    TECH_DETECTED = "info.technology"
    PORT_OPEN = "info.port"
    SUBDOMAIN_FOUND = "info.subdomain"
    API_ENDPOINT = "info.api_endpoint"


@dataclass
class Evidence:
    """HTTP request/response evidence for a finding."""
    request_method: str = ""
    request_url: str = ""
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    response_status: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    response_time: float = 0.0
    screenshot_path: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "request": {
                "method": self.request_method,
                "url": self.request_url,
                "headers": self.request_headers,
                "body": self.request_body[:2000],
            },
            "response": {
                "status": self.response_status,
                "headers": self.response_headers,
                "body": self.response_body[:5000],
                "time": self.response_time,
            },
            "screenshot": self.screenshot_path,
            "timestamp": self.timestamp,
        }


@dataclass
class CVSSScore:
    """CVSS v3.1 score."""
    score: float = 0.0
    severity: str = "info"
    vector: str = ""

    def calculate_severity(self):
        if self.score >= 9.0:
            self.severity = "critical"
        elif self.score >= 7.0:
            self.severity = "high"
        elif self.score >= 4.0:
            self.severity = "medium"
        elif self.score >= 0.1:
            self.severity = "low"
        else:
            self.severity = "info"


@dataclass
class Remediation:
    """Remediation guidance for a finding."""
    summary: str = ""
    description: str = ""
    impact: str = ""
    steps: List[str] = field(default_factory=list)
    code_example: str = ""
    references: List[str] = field(default_factory=list)
    compliance: List[str] = field(default_factory=list)


@dataclass
class Finding:
    """Structured finding with full metadata."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    type: FindingType = FindingType.INFO_DISCLOSURE
    severity: str = "info"
    title: str = ""
    detail: str = ""
    url: str = ""
    parameter: str = ""
    method: str = "GET"
    evidence: Optional[Evidence] = None
    cvss: Optional[CVSSScore] = None
    remediation: Optional[Remediation] = None
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    # Exploitation state
    confirmed: bool = False
    exploited: bool = False
    exploit_result: Dict[str, Any] = field(default_factory=dict)
    chain_id: str = ""

    # Metadata
    module: str = ""
    tool: str = ""
    timestamp: float = field(default_factory=time.time)
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type.value if isinstance(self.type, FindingType) else self.type,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "evidence": self.evidence.to_dict() if self.evidence else None,
            "cvss": {
                "score": self.cvss.score,
                "severity": self.cvss.severity,
                "vector": self.cvss.vector,
            } if self.cvss else None,
            "remediation": self.remediation.summary if self.remediation else None,
            "references": self.references,
            "tags": self.tags,
            "confirmed": self.confirmed,
            "exploited": self.exploited,
            "exploit_result": self.exploit_result,
            "chain_id": self.chain_id,
            "module": self.module,
            "tool": self.tool,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_legacy(cls, finding_data) -> "Finding":
        """Convert legacy string/dict finding to structured Finding."""
        if isinstance(finding_data, str):
            import re
            m = re.match(r'^\[([^\]]+)\]\s*(.*)', finding_data)
            if m:
                cat, msg = m.group(1), m.group(2)
                ftype = cls._category_to_type(cat)
                return cls(type=ftype, title=msg, detail=msg)
            return cls(title=finding_data, detail=finding_data)

        if isinstance(finding_data, dict):
            ftype_str = finding_data.get("type", "info.disclosure")
            try:
                ftype = FindingType(ftype_str)
            except ValueError:
                ftype = FindingType.INFO_DISCLOSURE

            return cls(
                type=ftype,
                severity=finding_data.get("severity", "info"),
                title=finding_data.get("name", finding_data.get("title", "")),
                detail=finding_data.get("detail", finding_data.get("description", "")),
                url=finding_data.get("url", finding_data.get("matched-at", "")),
                parameter=finding_data.get("param", finding_data.get("parameter", "")),
                confirmed=finding_data.get("confirmed", False),
            )

        return cls(title=str(finding_data))

    @classmethod
    def _category_to_type(cls, category: str) -> FindingType:
        mapping = {
            "VULN": FindingType.INFO_DISCLOSURE,
            "PORT": FindingType.PORT_OPEN,
            "NUCLEI": FindingType.INFO_DISCLOSURE,
            "SQLI": FindingType.SQLI_ERROR,
            "XSS": FindingType.XSS_REFLECTED,
            "SSRF": FindingType.SSRF_SERVER,
            "CMDI": FindingType.CMDI_DIRECT,
            "LFI": FindingType.LFI_LOCAL,
            "SSTI": FindingType.SSTI_RCE,
            "XXE": FindingType.XXE_FILE_READ,
            "API": FindingType.API_ENDPOINT,
        }
        return mapping.get(category.upper(), FindingType.INFO_DISCLOSURE)


class FindingManager:
    """Manages findings collection with filtering and search."""

    def __init__(self):
        self._findings: List[Finding] = []

    def add(self, finding: Finding):
        self._findings.append(finding)

    def add_legacy(self, legacy_finding):
        """Add a legacy string/dict finding, converting to Finding."""
        self.add(Finding.from_legacy(legacy_finding))

    def get_all(self) -> List[Finding]:
        return self._findings.copy()

    def get_by_type(self, ftype: FindingType) -> List[Finding]:
        return [f for f in self._findings if f.type == ftype]

    def get_by_severity(self, severity: str) -> List[Finding]:
        return [f for f in self._findings if f.severity == severity]

    def get_confirmed(self) -> List[Finding]:
        return [f for f in self._findings if f.confirmed]

    def get_exploited(self) -> List[Finding]:
        return [f for f in self._findings if f.exploited]

    def count_by_severity(self) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self._findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def to_legacy_list(self) -> list:
        """Convert to legacy format for backward compatibility."""
        return [f.to_dict() for f in self._findings]

    def __len__(self):
        return len(self._findings)

    def __iter__(self):
        return iter(self._findings)
