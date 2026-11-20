import os
import re
import sys
import time
import json
import subprocess
import signal
import platform
import logging
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin, quote, unquote

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

    class _FakeFore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""
        LIGHTRED_EX = LIGHTGREEN_EX = LIGHTYELLOW_EX = ""
        LIGHTBLUE_EX = LIGHTMAGENTA_EX = LIGHTCYAN_EX = ""
        BLACK = LIGHTBLACK_EX = ""

    class _FakeStyle:
        BRIGHT = DIM = RESET_ALL = ""

    Fore = _FakeFore()
    Style = _FakeStyle()

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

_FINDINGS_SET = set()


def clear_screen():
    os.system("cls" if platform.system() == "Windows" else "clear")


def safe_execute(func: Callable, *args, **kwargs) -> Any:
    try:
        return func(*args, **kwargs)
    except KeyboardInterrupt:
        raise
    except Exception as e:
        logging.exception("safe_execute caught exception")
        return None


def normalize_url(url: str) -> str:
    if not url:
        return url
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    path = parsed.path.rstrip("/") if parsed.path != "/" else "/"
    normalized = f"{parsed.scheme}://{parsed.netloc}{path}"
    if parsed.query:
        normalized += f"?{parsed.query}"
    if parsed.fragment:
        normalized += f"#{parsed.fragment}"
    return normalized


def safe_filename_from_url(url: str) -> str:
    parsed = urlparse(url)
    name = parsed.netloc.replace(".", "_").replace(":", "_")
    if parsed.path and parsed.path != "/":
        path_part = parsed.path.strip("/").replace("/", "_")
        name = f"{name}_{path_part}"
    safe = re.sub(r'[<>:"/\\|?*]', "_", name)
    safe = re.sub(r"_+", "_", safe).strip("_")
    if len(safe) > 100:
        safe = safe[:100]
    return safe


def _append_finding_once(text: str):
    global _FINDINGS_SET
    normalized = text.strip().lower()
    if normalized not in _FINDINGS_SET:
        _FINDINGS_SET.add(normalized)
        return True
    return False


def _format_external_command(cmd: List[str]) -> str:
    sensitive_patterns = [
        r"password", r"token", r"secret", r"key", r"auth",
        r"cookie", r"session", r"credential",
    ]
    parts = []
    for part in cmd:
        is_sensitive = False
        for pattern in sensitive_patterns:
            if re.search(pattern, str(part), re.IGNORECASE):
                is_sensitive = True
                break
        if is_sensitive and len(str(part)) > 4:
            val = str(part)
            parts.append(f"{val[:2]}***{val[-2:]}")
        else:
            parts.append(str(part))
    return " ".join(parts)


def _strip_ansi(text: str) -> str:
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    return ansi_escape.sub("", text)


def print_info(msg: str):
    print(f"{Fore.CYAN}[*] {msg}{Style.RESET_ALL}")


def print_good(msg: str):
    print(f"{Fore.GREEN}[+] {msg}{Style.RESET_ALL}")


def print_warning(msg: str):
    print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")


def print_error(msg: str):
    print(f"{Fore.RED}[-] {msg}{Style.RESET_ALL}")


def print_vuln(msg: str):
    print(f"{Fore.LIGHTRED_EX}[VULN] {msg}{Style.RESET_ALL}")


def print_phase(title: str):
    width = 60
    print()
    print(f"{Fore.CYAN}{Style.BRIGHT}{'=' * width}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{Style.BRIGHT}  {title}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{Style.BRIGHT}{'=' * width}{Style.RESET_ALL}")
    print()


def print_table(
    headers: List[str],
    rows: List[List[str]],
    alignments: Optional[List[str]] = None,
    title: Optional[str] = None,
    border_color: str = "",
    footer: Optional[str] = None,
):
    if not rows:
        print_info("No data to display.")
        return

    if not alignments:
        alignments = ["<"] * len(headers)

    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], len(str(cell)))

    color = getattr(Fore, border_color.upper(), "") if border_color else ""

    def _format_row(cells, widths, aligns):
        parts = []
        for i, cell in enumerate(cells):
            w = widths[i] if i < len(widths) else len(str(cell))
            a = aligns[i] if i < len(aligns) else "<"
            s = str(cell)
            if a == ">":
                parts.append(s.rjust(w))
            elif a == "^":
                parts.append(s.center(w))
            else:
                parts.append(s.ljust(w))
        return " │ ".join(parts)

    def _border(widths, char="─"):
        segments = [char * (w + 2) for w in widths]
        return "┼".join(segments)

    if title:
        total_width = sum(col_widths) + 3 * (len(col_widths) - 1)
        print(f"\n{color}┌{'─' * (total_width + 2)}┐{Style.RESET_ALL}")
        print(f"{color}│{Style.RESET_ALL} {Style.BRIGHT}{title}{Style.RESET_ALL}{' ' * max(0, total_width - len(title))} {color}│{Style.RESET_ALL}")
        print(f"{color}├{'─' * (total_width + 2)}┤{Style.RESET_ALL}")

    header_line = _format_row(headers, col_widths, alignments)
    print(f"{color}│{Style.RESET_ALL} {Style.BRIGHT}{header_line}{Style.RESET_ALL}{' ' * max(0, sum(col_widths) + 3 * (len(col_widths) - 1) - len(header_line))} {color}│{Style.RESET_ALL}")
    print(f"{color}├{_border(col_widths)}┤{Style.RESET_ALL}")

    for row in rows:
        row_line = _format_row(row, col_widths, alignments)
        print(f"{color}│{Style.RESET_ALL} {row_line}{' ' * max(0, sum(col_widths) + 3 * (len(col_widths) - 1) - len(row_line))} {color}│{Style.RESET_ALL}")

    if title:
        total_width = sum(col_widths) + 3 * (len(col_widths) - 1)
        print(f"{color}└{'─' * (total_width + 2)}┘{Style.RESET_ALL}")

    if footer:
        print(f"{Style.DIM}{footer}{Style.RESET_ALL}")


def _throttle_hook(response, **kwargs):
    pass


def _build_retry(total: int = 2, backoff_factor: float = 0.3, status_forcelist: Optional[Tuple[int, ...]] = None):
    if not HAS_REQUESTS:
        return None
    if status_forcelist is None:
        status_forcelist = (500, 502, 503, 504, 429)
    return Retry(
        total=total,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE", "PATCH"],
    )


def get_session(user_agent: Optional[str] = None, verify_tls: bool = True, proxy: Optional[str] = None):
    if not HAS_REQUESTS:
        print_warning("requests library not available.")
        return None

    session = requests.Session()
    session.verify = verify_tls
    retry = _build_retry()
    adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    if user_agent:
        session.headers["User-Agent"] = user_agent
    else:
        session.headers["User-Agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )

    if proxy:
        session.proxies = {"http": proxy, "https": proxy}

    if not verify_tls:
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            logging.exception("Failed to disable urllib3 insecure request warnings")

    original_send = session.send

    def throttled_send(*args, **kwargs):
        _throttle_hook(None)
        kwargs.setdefault("timeout", 10)
        kwargs.setdefault("allow_redirects", True)
        return original_send(*args, **kwargs)

    session.send = throttled_send
    return session


def _session_header_value(session, name: str) -> Optional[str]:
    if session is None:
        return None
    headers = getattr(session, "headers", {})
    return headers.get(name)


def _apply_cookie_string_to_session(session, cookie_string: str):
    if not session or not cookie_string:
        return
    for part in cookie_string.split(";"):
        part = part.strip()
        if "=" in part:
            name, value = part.split("=", 1)
            session.cookies.set(name.strip(), value.strip())


def _external_http_headers_from_session(session) -> Dict[str, str]:
    if not session:
        return {}
    headers = {}
    for key, value in session.headers.items():
        if key.lower() not in ("user-agent", "connection", "keep-alive"):
            headers[key] = value
    return headers


def _load_json_file(filepath: str) -> Any:
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError, IOError):
        return None


def _load_ffuf_json_results(filepath: str) -> List[Dict[str, Any]]:
    data = _load_json_file(filepath)
    if not data:
        return []
    if isinstance(data, dict):
        return data.get("results", [])
    if isinstance(data, list):
        return data
    return []


def _stream_process_output(process: subprocess.Popen, callback: Optional[Callable] = None):
    if not process or not process.stdout:
        return
    for line in iter(process.stdout.readline, ""):
        line = line.rstrip("\n\r")
        if callback:
            callback(line)
        else:
            print(line)


def _stream_command_output(
    cmd: List[str],
    callback: Optional[Callable] = None,
    timeout: Optional[int] = None,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> Tuple[int, str, str]:
    cmd_str = _format_external_command(cmd)
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=cwd,
            env=env,
            creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0,
        )
        stdout_lines = []
        stderr_lines = []

        def stdout_cb(line):
            stdout_lines.append(line)
            if callback:
                callback(line)

        def stderr_cb(line):
            stderr_lines.append(line)

        stdout_thread = __import__("threading").Thread(target=_stream_process_output, args=(proc, stdout_cb))
        stderr_thread = __import__("threading").Thread(target=_stream_process_output, args=(proc, stderr_cb))
        stdout_thread.daemon = True
        stderr_thread.daemon = True
        stdout_thread.start()
        stderr_thread.start()

        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout_thread.join(timeout=5)
            stderr_thread.join(timeout=5)
            return -1, "\n".join(stdout_lines), "Timeout expired"

        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)
        return proc.returncode, "\n".join(stdout_lines), "\n".join(stderr_lines)

    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except PermissionError:
        return -1, "", f"Permission denied: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def _capture_command_output(
    cmd: List[str],
    timeout: Optional[int] = None,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> Tuple[int, str, str]:
    cmd_str = _format_external_command(cmd)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=env,
            creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Timeout expired"
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except PermissionError:
        return -1, "", f"Permission denied: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def _wait_for_interrupted_child(process: subprocess.Popen, timeout: int = 5):
    if not process:
        return
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)
    except KeyboardInterrupt:
        process.kill()
        process.wait(timeout=2)


def _find_tool(name: str) -> Optional[str]:
    try:
        result = subprocess.run(
            ["where" if platform.system() == "Windows" else "which", name],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().split("\n")[0]
    except Exception:
        logging.exception(f"_find_tool: error locating {name}")
    return None


def check_nmap() -> bool:
    return _find_tool("nmap") is not None


def check_ffuf() -> bool:
    return _find_tool("ffuf") is not None


def check_nuclei() -> bool:
    return _find_tool("nuclei") is not None


def check_subfinder() -> bool:
    return _find_tool("subfinder") is not None


def check_httpx() -> bool:
    return _find_tool("httpx") is not None


def check_amass() -> bool:
    return _find_tool("amass") is not None


def check_gobuster() -> bool:
    return _find_tool("gobuster") is not None


def check_dirsearch() -> bool:
    return _find_tool("dirsearch") is not None


def check_nikto() -> bool:
    return _find_tool("nikto") is not None


def check_sqlmap() -> bool:
    return _find_tool("sqlmap") is not None


def check_whatweb() -> bool:
    return _find_tool("whatweb") is not None


def check_wpscan() -> bool:
    return _find_tool("wpscan") is not None


def check_go() -> bool:
    return _find_tool("go") is not None


def check_python3() -> bool:
    return _find_tool("python3") is not None or _find_tool("python") is not None


def install_nmap() -> bool:
    print_info("Attempting to install nmap...")
    system = platform.system()
    if system == "Linux":
        code, _, err = _capture_command_output(["sudo", "apt-get", "install", "-y", "nmap"], timeout=120)
        if code != 0:
            code, _, err = _capture_command_output(["sudo", "yum", "install", "-y", "nmap"], timeout=120)
    elif system == "Darwin":
        code, _, err = _capture_command_output(["brew", "install", "nmap"], timeout=120)
    elif system == "Windows":
        print_warning("Please install nmap manually from https://nmap.org/download.html")
        return False
    else:
        print_error(f"Unsupported OS for nmap installation: {system}")
        return False

    if code == 0:
        print_good("nmap installed successfully.")
        return True
    else:
        print_error(f"Failed to install nmap: {err}")
        return False


def install_ffuf() -> bool:
    print_info("Attempting to install ffuf...")
    system = platform.system()
    if check_go():
        code, _, err = _capture_command_output(
            ["go", "install", "github.com/ffuf/ffuf/v2@latest"],
            timeout=180,
            env={**os.environ, "GOPATH": os.path.expanduser("~/go")},
        )
        if code == 0:
            print_good("ffuf installed successfully.")
            return True

    if system == "Linux":
        code, _, err = _capture_command_output(["sudo", "apt-get", "install", "-y", "ffuf"], timeout=120)
    elif system == "Darwin":
        code, _, err = _capture_command_output(["brew", "install", "ffuf"], timeout=120)
    elif system == "Windows":
        print_warning("Please install ffuf manually from https://github.com/ffuf/ffuf/releases")
        return False
    else:
        print_error(f"Unsupported OS for ffuf installation: {system}")
        return False

    if code == 0:
        print_good("ffuf installed successfully.")
        return True
    else:
        print_error(f"Failed to install ffuf: {err}")
        return False


def install_nuclei() -> bool:
    print_info("Attempting to install nuclei...")
    system = platform.system()
    if check_go():
        code, _, err = _capture_command_output(
            ["go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"],
            timeout=300,
            env={**os.environ, "GOPATH": os.path.expanduser("~/go")},
        )
        if code == 0:
            print_good("nuclei installed successfully.")
            return True

    if system == "Linux":
        code, _, err = _capture_command_output(
            ["bash", "-c", "curl -s https://raw.githubusercontent.com/projectdiscovery/nuclei/master/scripts/install-nuclei.sh | bash"],
            timeout=120,
        )
    elif system == "Darwin":
        code, _, err = _capture_command_output(["brew", "install", "nuclei"], timeout=120)
    elif system == "Windows":
        print_warning("Please install nuclei manually from https://github.com/projectdiscovery/nuclei/releases")
        return False
    else:
        print_error(f"Unsupported OS for nuclei installation: {system}")
        return False

    if code == 0:
        print_good("nuclei installed successfully.")
        return True
    else:
        print_error(f"Failed to install nuclei: {err}")
        return False


def install_subfinder() -> bool:
    print_info("Attempting to install subfinder...")
    system = platform.system()
    if check_go():
        code, _, err = _capture_command_output(
            ["go", "install", "-v", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"],
            timeout=180,
            env={**os.environ, "GOPATH": os.path.expanduser("~/go")},
        )
        if code == 0:
            print_good("subfinder installed successfully.")
            return True

    if system == "Linux":
        code, _, err = _capture_command_output(
            ["bash", "-c", "curl -s https://raw.githubusercontent.com/projectdiscovery/subfinder/main/scripts/install.sh | bash"],
            timeout=120,
        )
    elif system == "Darwin":
        code, _, err = _capture_command_output(["brew", "install", "subfinder"], timeout=120)
    elif system == "Windows":
        print_warning("Please install subfinder manually from https://github.com/projectdiscovery/subfinder/releases")
        return False
    else:
        print_error(f"Unsupported OS for subfinder installation: {system}")
        return False

    if code == 0:
        print_good("subfinder installed successfully.")
        return True
    else:
        print_error(f"Failed to install subfinder: {err}")
        return False


def install_httpx() -> bool:
    print_info("Attempting to install httpx...")
    system = platform.system()
    if check_go():
        code, _, err = _capture_command_output(
            ["go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest"],
            timeout=180,
            env={**os.environ, "GOPATH": os.path.expanduser("~/go")},
        )
        if code == 0:
            print_good("httpx installed successfully.")
            return True

    if system == "Linux":
        code, _, err = _capture_command_output(
            ["bash", "-c", "curl -s https://raw.githubusercontent.com/projectdiscovery/httpx/main/scripts/install.sh | bash"],
            timeout=120,
        )
    elif system == "Darwin":
        print_warning("Please install httpx manually from https://github.com/projectdiscovery/httpx/releases")
        return False
    elif system == "Windows":
        print_warning("Please install httpx manually from https://github.com/projectdiscovery/httpx/releases")
        return False
    else:
        print_error(f"Unsupported OS for httpx installation: {system}")
        return False

    if code == 0:
        print_good("httpx installed successfully.")
        return True
    else:
        print_error(f"Failed to install httpx: {err}")
        return False


def install_amass() -> bool:
    print_info("Attempting to install amass...")
    system = platform.system()
    if check_go():
        code, _, err = _capture_command_output(
            ["go", "install", "-v", "github.com/owasp-amass/amass/v4/...@master"],
            timeout=300,
            env={**os.environ, "GOPATH": os.path.expanduser("~/go")},
        )
        if code == 0:
            print_good("amass installed successfully.")
            return True

    if system == "Linux":
        code, _, err = _capture_command_output(
            ["bash", "-c", "curl -s https://raw.githubusercontent.com/owasp-amass/amass/master/install.sh | sudo bash"],
            timeout=120,
        )
    elif system == "Darwin":
        code, _, err = _capture_command_output(["brew", "install", "amass"], timeout=120)
    elif system == "Windows":
        print_warning("Please install amass manually from https://github.com/owasp-amass/amass/releases")
        return False
    else:
        print_error(f"Unsupported OS for amass installation: {system}")
        return False

    if code == 0:
        print_good("amass installed successfully.")
        return True
    else:
        print_error(f"Failed to install amass: {err}")
        return False


def install_gobuster() -> bool:
    print_info("Attempting to install gobuster...")
    system = platform.system()
    if check_go():
        code, _, err = _capture_command_output(
            ["go", "install", "github.com/OJ/gobuster/v3@latest"],
            timeout=180,
            env={**os.environ, "GOPATH": os.path.expanduser("~/go")},
        )
        if code == 0:
            print_good("gobuster installed successfully.")
            return True

    if system == "Linux":
        code, _, err = _capture_command_output(["sudo", "apt-get", "install", "-y", "gobuster"], timeout=120)
    elif system == "Darwin":
        code, _, err = _capture_command_output(["brew", "install", "gobuster"], timeout=120)
    elif system == "Windows":
        print_warning("Please install gobuster manually from https://github.com/OJ/gobuster/releases")
        return False
    else:
        print_error(f"Unsupported OS for gobuster installation: {system}")
        return False

    if code == 0:
        print_good("gobuster installed successfully.")
        return True
    else:
        print_error(f"Failed to install gobuster: {err}")
        return False


def install_dirsearch() -> bool:
    print_info("Attempting to install dirsearch...")
    if check_python3():
        python_cmd = "python3" if _find_tool("python3") else "python"
        code, _, err = _capture_command_output(
            [python_cmd, "-m", "pip", "install", "dirsearch"],
            timeout=120,
        )
        if code == 0:
            print_good("dirsearch installed successfully.")
            return True

    print_warning("Please install dirsearch manually from https://github.com/maurosoria/dirsearch")
    return False


def install_nikto() -> bool:
    print_info("Attempting to install nikto...")
    system = platform.system()
    if system == "Linux":
        code, _, err = _capture_command_output(["sudo", "apt-get", "install", "-y", "nikto"], timeout=120)
        if code != 0:
            code, _, err = _capture_command_output(["sudo", "yum", "install", "-y", "nikto"], timeout=120)
    elif system == "Darwin":
        code, _, err = _capture_command_output(["brew", "install", "nikto"], timeout=120)
    elif system == "Windows":
        print_warning("Please install nikto manually from https://github.com/sullo/nikto")
        return False
    else:
        print_error(f"Unsupported OS for nikto installation: {system}")
        return False

    if code == 0:
        print_good("nikto installed successfully.")
        return True
    else:
        print_error(f"Failed to install nikto: {err}")
        return False


def install_sqlmap() -> bool:
    print_info("Attempting to install sqlmap...")
    system = platform.system()
    if system == "Linux":
        code, _, err = _capture_command_output(["sudo", "apt-get", "install", "-y", "sqlmap"], timeout=120)
    elif system == "Darwin":
        code, _, err = _capture_command_output(["brew", "install", "sqlmap"], timeout=120)
    elif system == "Windows":
        print_warning("Please install sqlmap manually from https://github.com/sqlmapproject/sqlmap")
        return False
    else:
        print_error(f"Unsupported OS for sqlmap installation: {system}")
        return False

    if code == 0:
        print_good("sqlmap installed successfully.")
        return True
    else:
        print_error(f"Failed to install sqlmap: {err}")
        return False


def install_whatweb() -> bool:
    print_info("Attempting to install whatweb...")
    system = platform.system()
    if system == "Linux":
        code, _, err = _capture_command_output(["sudo", "apt-get", "install", "-y", "whatweb"], timeout=120)
    elif system == "Darwin":
        code, _, err = _capture_command_output(["brew", "install", "whatweb"], timeout=120)
    elif system == "Windows":
        print_warning("Please install whatweb manually from https://github.com/urbanadventurer/WhatWeb")
        return False
    else:
        print_error(f"Unsupported OS for whatweb installation: {system}")
        return False

    if code == 0:
        print_good("whatweb installed successfully.")
        return True
    else:
        print_error(f"Failed to install whatweb: {err}")
        return False


def install_wpscan() -> bool:
    print_info("Attempting to install wpscan...")
    system = platform.system()
    if system == "Linux" or system == "Darwin":
        code, _, err = _capture_command_output(
            ["gem", "install", "wpscan"],
            timeout=180,
        )
        if code == 0:
            print_good("wpscan installed successfully.")
            return True

    print_warning("Please install wpscan manually from https://github.com/wpscanteam/wpscan")
    return False


def _setup_signal_handlers():
    def signal_handler(sig, frame):
        print_warning("\nScan interrupted by user. Cleaning up...")
        sys.exit(0)

    try:
        signal.signal(signal.SIGINT, signal_handler)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, signal_handler)
    except (OSError, ValueError):
        pass
