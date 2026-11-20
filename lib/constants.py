import re


class Constants:
    VERSION = "2.0.0"

    BANNER = r"""
  █████████                     █████   █████           ███      █████
 ███▒▒▒▒▒███                   ▒▒███   ▒▒███           ▒▒▒      ▒▒███
▒███    ▒▒▒  █████ ████  █████  ▒███    ▒███   ██████  ████   ███████
▒▒█████████ ▒▒███ ▒███  ███▒▒   ▒███    ▒███  ███▒▒███▒▒███  ███▒▒███
 ▒▒▒▒▒▒▒▒███ ▒███ ▒███ ▒▒█████  ▒▒███   ███  ▒███ ▒███ ▒███ ▒███ ▒███
 ███    ▒███ ▒███ ▒███  ▒▒▒▒███  ▒▒▒█████▒   ▒███ ▒███ ▒███ ▒███ ▒███
▒▒█████████  ▒▒███████  ██████     ▒▒███     ▒▒██████  █████▒▒████████
 ▒▒▒▒▒▒▒▒▒    ▒▒▒▒▒███ ▒▒▒▒▒▒       ▒▒▒       ▒▒▒▒▒▒  ▒▒▒▒▒  ▒▒▒▒▒▒▒▒
              ███ ▒███
             ▒▒██████
              ▒▒▒▒▒▒
"""

    DESCRIPTION = "Web Security Testing SysVoid Scanner"
    DEVELOPER = "developed by @SysVoiid Telegram"

    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

    SEVERITY_COLORS = {
        "critical": "magenta",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "info": "white",
        "unknown": "white",
    }

    _FINDING_SEV_CAT = {
        "critical": "VULN",
        "high": "VULN",
        "medium": "VULN",
        "low": "API",
        "info": "INFO",
    }

    _SOURCE_PATTERNS = [
        ("critical", "Clave privada PEM",
         re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), False),
        ("critical", "Cadena de conexión BD con credenciales",
         re.compile(r"\b(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|amqps?|mssql|jdbc:[a-z]+)://[^\s\"'<>]*:[^\s\"'<>@]+@[^\s\"'<>]+", re.IGNORECASE), False),
        ("high", "AWS Access Key ID",
         re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), False),
        ("high", "AWS Secret Access Key",
         re.compile(r"(?i)aws[_\-]?(?:secret|sk)[_\-]?(?:access[_\-]?)?key[\"'\s:=]{1,8}[\"']?([A-Za-z0-9/+=]{40})"), True),
        ("high", "Google API Key",
         re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), False),
        ("high", "GitHub token",
         re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), False),
        ("high", "Slack token",
         re.compile(r"\bxox[abpros]-[A-Za-z0-9\-]{10,}\b"), False),
        ("high", "Stripe live secret key",
         re.compile(r"\bsk_live_[0-9a-zA-Z]{20,}\b"), False),
        ("high", "JWT token",
         re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}\b"), False),
        ("high", "Credencial hardcoded",
         re.compile(r"(?i)(?:password|passwd|pwd|secret|api[_\-]?key|access[_\-]?key|client[_\-]?secret|auth[_\-]?token|bearer)[\"'\s:=]{1,8}[\"']([^\"'\s]{4,80})[\"']"), True),
        ("medium", "Basic Auth en URL",
         re.compile(r"\bhttps?://[A-Za-z0-9._\-]+:[^\s\"'<>@/]+@[A-Za-z0-9._\-]+"), False),
        ("medium", "Comentario HTML sensible",
         re.compile(
             r"<!--\s*("
             r"(?:(?!-->)[\s\S]){0,400}"
             r"(?:password|passwd|pwd|secret|api[_\-]?key|access[_\-]?key|"
             r"private[_\-]?key|client[_\-]?secret|auth[_\-]?token|bearer|"
             r"credentials|hardcoded|backdoor|deprecated|do not commit|"
             r"todo[: ]|fixme[: ]|xxx[: ]|hack[: ]|"
             r"backup\s+(?:file|path|server|db)|"
             r"internal\s+(?:use|api|server|tool)|"
             r"debug\s+(?:enabled|mode|key|token))"
             r"(?:(?!-->)[\s\S]){0,400}"
             r")\s*-->",
             re.IGNORECASE), True),
        ("medium", "Source map expuesto",
         re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*([^\s\"']+)"), True),
        ("medium", "IP privada hardcoded",
         re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"), False),
        ("low", "Ruta sensible referenciada",
         re.compile(r"[\"'](/(?:admin|adminer|debug|console|h2-console|phpmyadmin|backup|backups|dump|wp-admin|actuator|internal|staging|.git|.env)[A-Za-z0-9_\-/.]*)[\"']"), True),
        ("low", "Email expuesto",
         re.compile(r"\b[A-Za-z0-9_.+\-]+@[A-Za-z0-9\-]+\.[A-Za-z0-9.\-]+\b"), False),
    ]

    _SOURCE_ASSET_EXT = ('.js', '.mjs', '.jsx', '.ts', '.tsx', '.json', '.map', '.css', '.txt', '.xml', '.yml', '.yaml', '.env')

    _SOURCE_TEXT_CT = ('text/', 'application/javascript', 'application/json', 'application/xml',
                       'application/x-yaml', 'application/yaml', 'application/octet-stream')

    _SRC_MAX_BYTES = 2 * 1024 * 1024
    _SRC_SNIPPET_CHARS = 140
    _SRC_MAX_FINDINGS_PER_FILE = 30

    _LOGIN_LOCATION_RE = re.compile(
        r'(?:[?&](?:next|return|returnurl|return_url|redirect|redirect_uri|continue|come_from|dest|destination)=)'
        r'|(?:/(?:account/)?(?:login|signin|sign[-_]?in|auth|sso|session/new)\b)',
        re.I,
    )

    _ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')
