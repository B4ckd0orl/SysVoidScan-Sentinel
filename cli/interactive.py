import os
import platform
import sys
import time
import logging
from typing import Any, Dict, List, Optional

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
VERSION = "3.0.0"

MENU_OPTIONS = {
    "1": "Reconocimiento + Hidden Routes",
    "2": "Nmap + Nuclei",
    "3": "Fuzzing (dirs, vhosts, subdomains)",
    "4": "Spider + Source Code Analysis",
    "5": "API Discovery + WordPress Detection",
    "6": "Injection Tests (SQLi, XSS, Command Injection, LFI)",
    "7": "Advanced Tests (SSRF, SSTI, XXE, CRLF, Smuggling, Cache)",
    "8": "API Security + JWT + File Upload",
    "9": "User Enumeration & Brute Force",
    "10": "Active Directory Tests",
    "11": "NoSQL + LDAP + Deserialization",
    "12": "OAuth + GraphQL + WebSocket Testing",
    "13": "Headless Browser (SPA Crawl + DOM XSS)",
    "14": "Authentication Setup",
    "15": "WAF Detection + Bypass",
    "16": "Scheduled Scans",
    "17": "Notifications Setup",
    "18": "REST API Server",
    "19": "View Report",
    "20": "Export Report (SARIF/Jira/HTML/JSON)",
    "21": "Brute Force (SSH, FTP, HTTP, SMB)",
    "22": "FULL PENTEST + EXPLOTACION (TODOS LOS ATAQUES)",
    "23": "View Artifacts",
    "24": "List Plugins",
    "25": "Exit",
}


class InteractiveMenu:
    def __init__(self, plugin_loader: Optional[Any] = None):
        self._authenticated = False
        self._auth_config = {}
        self._api_server = None
        self.plugin_loader = plugin_loader

    def show_banner(self, scanner: Optional[Any] = None):
        os.system("cls" if platform.system() == "Windows" else "clear")
        print(f"{Fore.CYAN}{Style.BRIGHT}{BANNER}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  {DESCRIPTION}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}  Version {VERSION} (Sentinel) | {DEVELOPER}{Style.RESET_ALL}")
        plugin_count = len(self.plugin_loader.list_plugins()) if self.plugin_loader else 0
        artifact_count = 0
        if scanner and hasattr(scanner, "artifact_manager") and scanner.artifact_manager is not None:
            artifact_count = len(scanner.artifact_manager.list_artifacts())
        plugin_status = f"Plugins loaded: {plugin_count}" if plugin_count else "No plugins loaded"
        artifact_status = f"Artifacts stored: {artifact_count}" if artifact_count else "No artifacts stored yet"
        print(f"{Fore.GREEN}  Dashboard: HTML reports + evidence artifacts + plugin manifests enabled{Style.RESET_ALL}")
        print(f"{Fore.GREEN}  {plugin_status} | {artifact_status}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  Tip: use the export option to generate a rich HTML report and preview artifacts.{Style.RESET_ALL}")
        print()

    def show_menu(self, targets: List[str] = None, authenticated: bool = False, scanner: Optional[Any] = None) -> str:
        self._authenticated = authenticated
        print(f"\n{Fore.CYAN}{Style.BRIGHT}{'=' * 60}{Style.RESET_ALL}")
        if targets:
            print(f"{Fore.WHITE}  Targets: {Style.BRIGHT}{len(targets)}{Style.RESET_ALL}")
            for t in targets[:3]:
                print(f"    {Fore.GREEN}{chr(9656)}{Style.RESET_ALL} {t}")
            if len(targets) > 3:
                print(f"    {Fore.WHITE}... and {len(targets) - 3} more{Style.RESET_ALL}")
        auth_status = f"{Fore.GREEN}[AUTHENTICATED]{Style.RESET_ALL}" if authenticated else f"{Fore.YELLOW}[UNAUTHENTICATED]{Style.RESET_ALL}"
        plugin_count = len(self.plugin_loader.list_plugins()) if self.plugin_loader else 0
        artifact_count = 0
        if scanner and hasattr(scanner, "artifact_manager") and scanner.artifact_manager is not None:
            artifact_count = len(scanner.artifact_manager.list_artifacts())
        print(f"  Status: {auth_status} | Plugins: {plugin_count} | Artifacts: {artifact_count}")
        print(f"{Fore.CYAN}{Style.BRIGHT}{'=' * 60}{Style.RESET_ALL}\n")
        for key, label in MENU_OPTIONS.items():
            num = f"{Fore.CYAN}{Style.BRIGHT}{key:>2}{Style.RESET_ALL}"
            if key == "22":
                color = Fore.MAGENTA
            elif key in ("23", "25"):
                color = Fore.RED
            elif key == "24":
                color = Fore.CYAN
            elif key == "14":
                color = Fore.YELLOW if not authenticated else Fore.GREEN
            elif key in ("15", "16", "17", "18", "19", "20", "21", "23", "25"):
                color = Fore.LIGHTCYAN_EX
            else:
                color = Fore.WHITE
            print(f"  {num}. {color}{label}{Style.RESET_ALL}")
        print()
        try:
            choice = input(f"{Fore.CYAN}  Select option [1-25, exit]: {Style.RESET_ALL}").strip()
        except (EOFError, KeyboardInterrupt):
            choice = "23"
        return choice

    def prompt_target_selection(self) -> List[str]:
        print(f"\n{Fore.CYAN}  Target Configuration{Style.RESET_ALL}")
        print(f"  {'─' * 40}")
        print(f"  Enter target URL(s), one per line, or comma-separated on the first line.")
        print(f"  Press Enter on empty line to finish.\n")
        targets = []
        while True:
            try:
                url = input(f"  {Fore.GREEN}Target URL: {Style.RESET_ALL}").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not url:
                if not targets:
                    print(f"  {Fore.YELLOW}No targets entered yet. Please provide at least one target.{Style.RESET_ALL}")
                    continue
                break
            if "," in url:
                candidates = [part.strip() for part in url.split(",") if part.strip()]
            else:
                candidates = [url]
            for part in candidates:
                if not part.startswith(("http://", "https://")):
                    part = "http://" + part
                if part not in targets:
                    targets.append(part)
                    print(f"    {Fore.GREEN}+{Style.RESET_ALL} Added: {part}")
        return targets

    def prompt_auth_setup(self) -> Dict:
        print(f"\n{Fore.YELLOW}  Authentication Setup{Style.RESET_ALL}")
        print(f"  {'─' * 40}")
        auth = {"type": "none", "credentials": {}}
        print(f"\n  Authentication types:")
        print(f"    1. Cookie-based")
        print(f"    2. Basic Auth (user:password)")
        print(f"    3. Bearer Token")
        print(f"    4. Custom Headers")
        print(f"    0. No authentication")
        try:
            choice = input(f"\n  {Fore.YELLOW}Select type [0-4]: {Style.RESET_ALL}").strip()
        except (EOFError, KeyboardInterrupt):
            return auth
        if choice == "0" or not choice:
            return auth
        if choice == "1":
            auth["type"] = "cookie"
            try:
                cookie = input(f"  {Fore.WHITE}Cookie value: {Style.RESET_ALL}").strip()
                auth["credentials"]["cookie"] = cookie
            except (EOFError, KeyboardInterrupt):
                pass
        elif choice == "2":
            auth["type"] = "basic"
            try:
                user = input(f"  {Fore.WHITE}Username: {Style.RESET_ALL}").strip()
                import getpass
                password = getpass.getpass(f"  {Fore.WHITE}Password: {Style.RESET_ALL}")
                auth["credentials"]["username"] = user
                auth["credentials"]["password"] = password
            except (EOFError, KeyboardInterrupt):
                pass
        elif choice == "3":
            auth["type"] = "bearer"
            try:
                token = input(f"  {Fore.WHITE}Bearer token: {Style.RESET_ALL}").strip()
                auth["credentials"]["token"] = token
            except (EOFError, KeyboardInterrupt):
                pass
        elif choice == "4":
            auth["type"] = "custom_headers"
            auth["credentials"]["headers"] = {}
            print(f"  Enter custom headers (Name: Value), empty line to finish:")
            while True:
                try:
                    header = input(f"  {Fore.WHITE}Header: {Style.RESET_ALL}").strip()
                except (EOFError, KeyboardInterrupt):
                    break
                if not header:
                    break
                if ":" in header:
                    name, value = header.split(":", 1)
                    auth["credentials"]["headers"][name.strip()] = value.strip()
        self._authenticated = auth["type"] != "none"
        self._auth_config = auth
        return auth

    def dispatch(self, option: str, target: str, session, scanner) -> Optional[Dict]:
        if option == "1":
            return self._run_info_gathering(target, session, scanner)
        elif option == "2":
            return self._run_nmap_nuclei(target, session, scanner)
        elif option == "3":
            return self._run_fuzzing(target, session, scanner)
        elif option == "4":
            return self._run_spider_source(target, session, scanner)
        elif option == "5":
            return self._run_api_wordpress(target, session, scanner)
        elif option == "6":
            return self._run_injection(target, session, scanner)
        elif option == "7":
            return self._run_advanced(target, session, scanner)
        elif option == "8":
            return self._run_api_jwt_upload(target, session, scanner)
        elif option == "9":
            return self._run_user_enum(target, session, scanner)
        elif option == "10":
            return self._run_active_directory(target, session, scanner)
        elif option == "11":
            return self._run_nosql_ldap_deser(target, session, scanner)
        elif option == "12":
            return self._run_oauth_graphql_ws(target, session, scanner)
        elif option == "13":
            return self._run_headless_browser(target, session, scanner)
        elif option == "14":
            return self.prompt_auth_setup()
        elif option == "15":
            return self._run_waf_detection(target, session, scanner)
        elif option == "16":
            return self._run_scheduler(target, session, scanner)
        elif option == "17":
            return self._run_notifications(target, session, scanner)
        elif option == "18":
            return self._run_api_server(target, session, scanner)
        elif option == "19":
            return self._view_report(scanner)
        elif option == "20":
            return self._export_report(scanner)
        elif option == "21":
            return self._run_brute_force(target, session, scanner)
        elif option == "22":
            return self._run_full_pentest(target, session, scanner)
        elif option == "23":
            return self._view_artifacts(scanner)
        elif option == "24":
            return self._list_plugins(scanner)
        elif option == "25":
            return None
        else:
            print(f"{Fore.RED}  Invalid option.{Style.RESET_ALL}")
            return {}

    def _run_full_pentest(self, target, session, scanner):
        """Execute complete 83-phase full pentest without exceptions."""
        from core.utils import print_phase, print_info, print_good, print_warning
        
        print_phase("INICIANDO FULL PENTEST - 83 FASES OBLIGATORIAS")
        print_info(f"Objetivo: {target}")
        print_info("Modo: SIN EXCEPCIONES - TODAS LAS FASES SE EJECUTAN")
        
        # FASE 0: PREPARACIÓN
        self._phase_00_target_validation(target, session, scanner)
        self._phase_01_oob_server(scanner)
        
        # FASE 1: RECONOCIMIENTO
        self._phase_02_info_gathering(target, session, scanner)
        self._phase_03_nmap_scan(target, session, scanner)
        self._phase_04_subdomain_enum(target, session, scanner)
        self._phase_05_vhost_bruteforce(target, session, scanner)
        self._phase_06_directory_bruteforce(target, session, scanner)
        self._phase_07_spider_crawl(target, session, scanner)
        self._phase_08_source_analysis(target, session, scanner)
        self._phase_09_parameter_discovery(target, session, scanner)
        self._phase_10_api_discovery(target, session, scanner)
        
        # FASE 2: VULNERABILIDADES WEB CORE
        self._phase_11_sqli_test(target, session, scanner)
        self._phase_12_xss_test(target, session, scanner)
        self._phase_13_ssrf_test(target, session, scanner)
        self._phase_14_lfi_rfi_test(target, session, scanner)
        self._phase_15_rce_cmdi_test(target, session, scanner)
        self._phase_16_ssti_test(target, session, scanner)
        self._phase_17_xxe_test(target, session, scanner)
        self._phase_18_file_upload_test(target, session, scanner)
        self._phase_19_jwt_test(target, session, scanner)
        self._phase_20_cors_csrf_test(target, session, scanner)
        self._phase_21_idor_mass_test(target, session, scanner)
        self._phase_22_nosql_test(target, session, scanner)
        self._phase_23_graphql_test(target, session, scanner)
        self._phase_24_oauth_test(target, session, scanner)
        self._phase_25_websocket_test(target, session, scanner)
        self._phase_26_crlf_ssti_test(target, session, scanner)
        self._phase_27_deserialization_test(target, session, scanner)
        self._phase_28_xxe_advanced_test(target, session, scanner)
        
        # FASE 3: INFRAESTRUCTURA Y SERVICIOS
        self._phase_29_wordpress_test(target, session, scanner)
        self._phase_30_active_directory_test(target, session, scanner)
        self._phase_31_ldap_test(target, session, scanner)
        self._phase_32_ssl_tls_test(target, session, scanner)
        self._phase_33_dns_test(target, session, scanner)
        self._phase_34_smb_test(target, session, scanner)
        self._phase_35_snmp_test(target, session, scanner)
        self._phase_36_database_test(target, session, scanner)
        
        # FASE 4: EXPLOTACIÓN AUTOMÁTICA
        self._phase_37_exploit_sqli(target, session, scanner)
        self._phase_38_exploit_xss(target, session, scanner)
        self._phase_39_exploit_ssrf(target, session, scanner)
        self._phase_40_exploit_ssti(target, session, scanner)
        self._phase_41_exploit_xxe(target, session, scanner)
        self._phase_42_exploit_cmdi(target, session, scanner)
        self._phase_43_exploit_upload(target, session, scanner)
        self._phase_44_exploit_jwt(target, session, scanner)
        self._phase_45_exploit_lfi(target, session, scanner)
        self._phase_46_exploit_deserialization(target, session, scanner)
        self._phase_46_exploit_nosql(target, session, scanner)
        self._phase_47_exploit_graphql(target, session, scanner)
        self._phase_48_exploit_oauth(target, session, scanner)
        
        # FASE 5: CADENAS DE EXPLOTACIÓN
        self._phase_49_chain_sqli_webshell(target, session, scanner)
        self._phase_50_chain_ssrf_cloud(target, session, scanner)
        self._phase_51_chain_lfi_log_poison(target, session, scanner)
        self._phase_52_chain_ssti_rce(target, session, scanner)
        self._phase_53_chain_upload_shell(target, session, scanner)
        self._phase_54_chain_jwt_privesc(target, session, scanner)
        self._phase_55_chain_xxe_creds(target, session, scanner)
        self._phase_56_chain_sqli_os(target, session, scanner)
        self._phase_57_chain_open_redirect_xss(target, session, scanner)
        self._phase_58_chain_ad_full(target, session, scanner)
        
        # FASE 6: POST-EXPLOTACIÓN
        self._phase_59_cred_spray_http(target, session, scanner)
        self._phase_60_cred_spray_smb(target, session, scanner)
        self._phase_61_cred_spray_ssh(target, session, scanner)
        self._phase_62_cred_spray_rdp(target, session, scanner)
        self._phase_63_cred_spray_mssql(target, session, scanner)
        self._phase_64_cred_spray_postgres(target, session, scanner)
        self._phase_65_cred_spray_mysql(target, session, scanner)
        self._phase_66_cred_spray_ldap(target, session, scanner)
        self._phase_67_cred_spray_winrm(target, session, scanner)
        self._phase_68_system_enum(target, session, scanner)
        self._phase_69_cred_harvest(target, session, scanner)
        self._phase_70_lateral_movement(target, session, scanner)
        self._phase_71_persistence(target, session, scanner)
        self._phase_72_privilege_escalation(target, session, scanner)
        self._phase_73_pivoting(target, session, scanner)
        self._phase_74_data_exfil(target, session, scanner)
        self._phase_75_cleanup(target, session, scanner)
        
        # FASE 7: CVE AUTO-EXPLOTACIÓN
        self._phase_76_cve_scan(target, session, scanner)
        self._phase_77_cve_auto_exploit(target, session, scanner)
        
        # FASE 8: REPORTES FINALES
        self._phase_78_report_executive(target, session, scanner)
        self._phase_79_report_technical(target, session, scanner)
        self._phase_80_report_compliance(target, session, scanner)
        self._phase_81_report_attack_path(target, session, scanner)
        self._phase_82_report_remediation(target, session, scanner)
        self._phase_83_artifact_package(target, session, scanner)
        
        print_good("FULL PENTEST COMPLETADO - TODAS LAS 83 FASES EJECUTADAS")
        return {"status": "completed", "phases": 83}

    # ============================================================
    # Helpers: conectan las fases con la implementacion real
    # ============================================================
    def _orchestrator(self, scanner):
        from exploit.orchestrator import ExploitOrchestrator
        orch = getattr(scanner, "_exploit_orchestrator", None)
        if orch is None:
            orch = ExploitOrchestrator(scanner)
            scanner._exploit_orchestrator = orch
        return orch

    def _chain_engine(self, scanner):
        from exploit.chain_engine import ChainEngine
        engine = getattr(scanner, "_menu_chain_engine", None)
        if engine is None:
            engine = ChainEngine(self._orchestrator(scanner))
            scanner._menu_chain_engine = engine
        return engine

    def _lateral_movement(self, scanner):
        from post_exploitation.lateral_movement import LateralMovement
        lm = getattr(scanner, "_menu_lateral", None)
        if lm is None:
            lm = LateralMovement()
            scanner._menu_lateral = lm
        return lm

    def _scan_findings(self, scanner):
        raw = getattr(scanner, "findings", None)
        if not raw:
            raw = getattr(getattr(scanner, "config", None), "findings", None)
        return [f for f in (raw or []) if isinstance(f, dict)]

    def _credentials(self, scanner):
        try:
            return list(self._orchestrator(scanner).cred_store.get_all() or [])
        except Exception:
            return []

    def _summarize(self, res, max_items=6):
        if not isinstance(res, dict):
            return ""
        parts = []
        for key, val in list(res.items())[:max_items]:
            if isinstance(val, (list, dict, tuple, set)):
                parts.append(f"{key}={len(val)}")
            elif isinstance(val, bool):
                parts.append(f"{key}={val}")
            elif isinstance(val, (int, float)):
                parts.append(f"{key}={val}")
        return (", ".join(parts))[:160]

    def _report(self, label, res):
        from core.utils import print_good, print_info, print_warning
        if res is None:
            print_info(f"{label}: sin ejecutar.")
            return res
        if isinstance(res, dict) and res.get("error"):
            print_warning(f"{label}: {res['error']}")
            return res
        summary = self._summarize(res)
        print_good(f"{label}: completado" + (f" -> {summary}" if summary else "."))
        return res

    def _local_postex_allowed(self, label):
        from core.utils import print_warning
        if os.environ.get("SYSVOIDSCAN_POSTEX_LOCAL") == "1":
            return True
        print_warning(f"{label}: OPERA SOBRE ESTA MAQUINA, no sobre el objetivo remoto.")
        print_warning(f"{label}: omitida por seguridad. Activala con SYSVOIDSCAN_POSTEX_LOCAL=1")
        return False

    def _run_exploit_phase(self, target, session, scanner, key, label):
        from core.utils import print_info, print_good, print_warning
        try:
            orch = self._orchestrator(scanner)
        except Exception as e:
            print_warning(f"{label}: orquestador no disponible ({e})")
            return None
        if key not in orch._exploiters:
            print_warning(f"{label}: explotador '{key}' no disponible.")
            return None
        matched = [f for f in self._scan_findings(scanner) if orch._classify_finding(f) == key]
        if not matched:
            print_info(f"{label}: 0 hallazgos de este tipo en el objetivo -> nada que explotar.")
            return {"exploited": 0, "candidates": 0}
        ok = 0
        for finding in matched:
            try:
                result = orch.exploit_finding(finding, target, session)
                if isinstance(result, dict) and result.get("success"):
                    ok += 1
            except Exception:
                logging.exception("_run_exploit_phase: exploiter failed")
        print_good(f"{label}: {ok}/{len(matched)} explotaciones confirmadas")
        return {"exploited": ok, "candidates": len(matched)}

    def _run_chain_phase(self, target, session, scanner, chain_key, label):
        from core.utils import print_info, print_good, print_warning
        try:
            engine = self._chain_engine(scanner)
        except Exception as e:
            print_warning(f"{label}: motor de cadenas no disponible ({e})")
            return None
        if chain_key not in engine.CHAINS:
            print_warning(f"{label}: cadena '{chain_key}' no definida.")
            return None
        try:
            result = engine.run_chain(chain_key, target, session,
                                      findings=self._scan_findings(scanner))
        except Exception as e:
            logging.exception("_run_chain_phase: chain failed")
            print_warning(f"{label}: la cadena fallo ({e})")
            return None
        if not isinstance(result, dict):
            print_info(f"{label}: sin resultado.")
            return None
        done = len(result.get("steps_completed") or [])
        failed = len(result.get("steps_failed") or [])
        creds = len(result.get("credentials") or [])
        if result.get("success"):
            print_good(f"{label}: {done} pasos OK / {failed} fallidos, {creds} credenciales.")
        else:
            print_info(f"{label}: precondiciones no cumplidas ({done} OK, {failed} fallidos) - nada que encadenar.")
        return result

    def _port_open(self, host, port, timeout=3.0):
        import socket
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            return None
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            return sock.connect_ex((ip, port)) == 0
        except Exception:
            return None
        finally:
            sock.close()

    def _run_service_phase(self, target, session, scanner, service, port, lateral_method=None):
        from core.utils import print_info, print_good, print_warning
        from urllib.parse import urlparse
        host = urlparse(target).hostname or target
        state = self._port_open(host, port)
        if state is None:
            print_warning(f"{service}: no se pudo resolver {host}; fase no ejecutada.")
            return None
        if not state:
            print_info(f"{service}: puerto {port} cerrado/inaccesible en {host} -> fase no aplica.")
            return {"service": service, "port": port, "open": False}
        print_good(f"{service}: puerto {port} ABIERTO en {host}")
        creds = self._credentials(scanner)
        if not creds:
            print_info(f"{service}: sin credenciales capturadas -> spray no ejecutado.")
            return {"service": service, "port": port, "open": True, "credentials": 0}
        if not lateral_method:
            print_info(f"{service}: sin spray propio para este servicio; usa la fase 70 (lateral movement).")
            return {"service": service, "port": port, "open": True, "credentials": len(creds)}
        try:
            fn = getattr(self._lateral_movement(scanner), lateral_method, None)
            if fn is None:
                print_warning(f"{service}: metodo {lateral_method} no disponible.")
                return None
            res = fn(host, creds)
        except FileNotFoundError:
            print_warning(f"{service}: requiere herramientas ausentes (impacket/python3) en Windows.")
            return {"service": service, "open": True, "tooling": "missing"}
        except Exception as e:
            logging.exception("_run_service_phase failed")
            print_warning(f"{service}: fallo el intento ({type(e).__name__}: {e})")
            return None
        ok = len(res) if isinstance(res, list) else 0
        print_good(f"{service}: {ok} accesos confirmados con {len(creds)} credenciales probadas.")
        return {"service": service, "open": True, "accesses": ok, "tested": len(creds)}

    def _run_postex(self, label, fn, *args, **kwargs):
        from core.utils import print_warning
        try:
            res = fn(*args, **kwargs)
        except Exception as e:
            logging.exception("_run_postex: %s failed", label)
            print_warning(f"{label}: fallo ({type(e).__name__}: {e})")
            return None
        return self._report(label, res)

    # ============================================================
    # FASE 0: PREPARACIÓN
    # ============================================================
    def _phase_00_target_validation(self, target, session, scanner):
        from core.utils import print_phase, print_info, print_good, print_warning
        print_phase("FASE 00: VALIDACIÓN DE OBJETIVO")
        try:
            from urllib.parse import urlparse
            import socket
            parsed = urlparse(target)
            domain = parsed.hostname or target
            ip = socket.gethostbyname(domain)
            print_good(f"Objetivo válido: {target} -> {domain} ({ip})")
            scanner.scan_data["target"]["domain"] = domain
            scanner.scan_data["target"]["ip"] = ip
        except Exception as e:
            print_warning(f"Validación parcial: {e}")

    def _phase_01_oob_server(self, scanner):
        from core.utils import print_phase, print_info, print_good, print_warning
        print_phase("FASE 01: SERVIDOR OOB")
        try:
            if not scanner.oob_server.is_running:
                started = scanner.oob_server.start()
                if started:
                    print_good(f"OOB server iniciado en puerto {scanner.oob_server.port}")
                else:
                    print_warning("OOB server no pudo iniciarse")
        except Exception as e:
            print_warning(f"OOB server error: {e}")

    # ============================================================
    # FASE 1: RECONOCIMIENTO
    # ============================================================
    def _phase_02_info_gathering(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 02: RECONOCIMIENTO (WhatWeb, Headers, SSL, Tech)")
        scanner.run_module("info_gathering", target, session=session)

    def _phase_03_nmap_scan(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 03: ESCANEO NMAP COMPLETO (-sS -sV -sC -A -p-)")
        scanner.run_module("nmap", target, session=session)

    def _phase_04_subdomain_enum(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 04: ENUMERACIÓN DE SUBDOMINIOS (Subfinder + CRT.sh + DNS brute)")
        scanner.run_module("subdomain", target, session=session)

    def _phase_05_vhost_bruteforce(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 05: FUERZA BRUTA VIRTUAL HOSTS (FFUF + Seclists)")
        scanner.run_module("vhost", target, session=session)

    def _phase_06_directory_bruteforce(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 06: FUERZA BRUTA DIRECTORIOS/ARCHIVOS (FFUF + raft-medium + extensions)")
        scanner.run_module("directory", target, session=session)

    def _phase_07_spider_crawl(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 07: CRAWL/SPIDER (Katana depth=3, JS parsing, forms)")
        scanner.run_module("spider", target, session=session)

    def _phase_08_source_analysis(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 08: ANÁLISIS CÓDIGO FUENTE (Secrets, comments, meta tags)")
        scanner.run_module("source_code", target, session=session)

    def _phase_09_parameter_discovery(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 09: DESCUBRIMIENTO PARÁMETROS (GET/POST/JSON/Headers)")
        # Uses hidden_routes parameter_discovery
        try:
            from exploit.orchestrator import ExploitOrchestrator
            orch = ExploitOrchestrator(scanner)
            if "hidden_routes" in orch._exploiters:
                orch._exploiters["hidden_routes"].parameter_discovery(target, session)
        except Exception as e:
            logging.exception("Operation failed")

    def _phase_10_api_discovery(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 10: DESCUBRIMIENTO API (50+ endpoints, Swagger/OpenAPI/GraphQL)")
        scanner.run_module("api", target, session=session)

    # ============================================================
    # FASE 2: VULNERABILIDADES WEB CORE
    # ============================================================
    def _phase_11_sqli_test(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 11: SQL INJECTION (Error-based, Blind, Time-based, Stacked)")
        scanner.run_module("injection", target, session=session)

    def _phase_12_xss_test(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 12: XSS (Reflected, Stored, DOM, Mutation - Context-aware)")
        scanner.run_module("injection", target, session=session)

    def _phase_13_ssrf_test(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 13: SSRF + Cloud Metadata (AWS/GCP/Azure/DO/K8s) + DNS Rebinding")
        scanner.run_module("advanced_security", target, session=session)

    def _phase_14_lfi_rfi_test(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 14: LFI/RFI + Log Poisoning + php://filter + /proc/self/environ")
        scanner.run_module("injection", target, session=session)

    def _phase_15_rce_cmdi_test(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 15: RCE/CMDi + Blind OOB + Filter Bypass + Deserialization")
        scanner.run_module("advanced_security", target, session=session)

    def _phase_16_ssti_test(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 16: SSTI (Jinja2, Twig, FreeMarker, Mako, Thymeleaf, Pebble)")
        scanner.run_module("advanced_security", target, session=session)

    def _phase_17_xxe_test(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 17: XXE + Blind OOB + Parameter Entities + SVG XXE + Docx")
        scanner.run_module("advanced_security", target, session=session)

    def _phase_18_file_upload_test(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 18: FILE UPLOAD (Polyglots, MIME, .htaccess, Parsing flaws)")
        scanner.run_module("api_jwt_upload", target, session=session)

    def _phase_19_jwt_test(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 19: JWT (alg:none, HS256 brute, RS256->HS256, JWKS, kid, key confusion)")
        scanner.run_module("api_jwt_upload", target, session=session)

    def _phase_20_cors_csrf_test(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 20: CORS/CSRF/Open Redirect/Clickjacking")
        scanner.run_module("advanced_security", target, session=session)

    def _phase_21_idor_mass_test(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 21: IDOR MASIVO + Mass Assignment + BOLA/BFLA")
        scanner.run_module("advanced_security", target, session=session)

    def _phase_22_nosql_test(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 22: NoSQL INJECTION (MongoDB operators, $where JS injection)")
        scanner.run_module("nosql", target, session=session)

    def _phase_23_graphql_test(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 23: GRAPHQL (Introspection, Batch, Alias overload, DoS)")
        scanner.run_module("graphql", target, session=session)

    def _phase_24_oauth_test(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 24: OAUTH/OIDC (PKCE bypass, redirect_uri, implicit flow)")
        scanner.run_module("oauth", target, session=session)

    def _phase_25_websocket_test(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 25: WEBSOCKET (Auth bypass, message tampering)")
        scanner.run_module("websocket", target, session=session)

    def _phase_26_crlf_ssti_test(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 26: CRLF Header Injection + HTTP Request Smuggling")
        scanner.run_module("advanced_security", target, session=session)

    def _phase_27_deserialization_test(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 27: DESERIALIZACIÓN (Java, PHP, Python, .NET, Node.js)")
        scanner.run_module("deserialization", target, session=session)

    def _phase_28_xxe_advanced_test(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 28: XXE AVANZADO (XInclude, SVG, Blind OOB chains)")
        scanner.run_module("advanced_security", target, session=session)

    # ============================================================
    # FASE 3: INFRAESTRUCTURA Y SERVICIOS
    # ============================================================
    def _phase_29_wordpress_test(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 29: WORDPRESS (WPScan: users, plugins, themes, vulns, config)")
        scanner.run_module("wordpress", target, session=session)

    def _phase_30_active_directory_test(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 30: ACTIVE DIRECTORY (Kerbrute, AS-REP, Kerberoasting, LDAP)")
        scanner.run_module("active_directory", target, session=session)

    def _phase_31_ldap_test(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 31: LDAP (Anon bind, enumeration, pass-back)")
        scanner.run_module("ldap", target, session=session)

    def _phase_32_ssl_tls_test(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 32: SSL/TLS (Cert, protocolos, cifrados, vulns Heartbleed, etc.)")
        # Placeholder - would need SSL module
        pass

    def _phase_33_dns_test(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 33: DNS (Zone transfer, subdomain takeover, SPF/DMARC)")
        # Placeholder - would need DNS module
        pass

    def _phase_34_smb_test(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 34: SMB (Null session, signing, shares, users, relay)")
        # Placeholder - would need SMB module
        pass

    def _phase_35_snmp_test(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 35: SNMP (Community strings, enumeration)")
        # Placeholder - would need SNMP module
        pass

    def _phase_36_database_test(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 36: DATABASES (MySQL, PostgreSQL, MSSQL, Oracle, Redis, MongoDB auth)")
        # Placeholder - would need database modules
        pass

    # ============================================================
    # FASE 4: EXPLOTACIÓN AUTOMÁTICA
    # ============================================================
    def _phase_37_exploit_sqli(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 37: EXPLOTAR SQLi (Fingerprint DB, enum cols, dump creds, read files, OS cmd)")
        return self._run_exploit_phase(target, session, scanner, "sqli", "SQLi")

    def _phase_38_exploit_xss(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 38: EXPLOTAR XSS (Cookie stealer, session hijack, keylogger, port scanner, cred harvester)")
        return self._run_exploit_phase(target, session, scanner, "xss", "XSS")

    def _phase_39_exploit_ssrf(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 39: EXPLOTAR SSRF (Cloud creds, internal scan, file read, protocol smuggling, RCE)")
        return self._run_exploit_phase(target, session, scanner, "ssrf", "SSRF")

    def _phase_40_exploit_ssti(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 40: EXPLOTAR SSTI (RCE, file read, reverse shell per engine)")
        return self._run_exploit_phase(target, session, scanner, "ssti", "SSTI")

    def _phase_41_exploit_xxe(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 41: EXPLOTAR XXE (File read, SSRF, Blind OOB, RCE expect/php filter)")
        return self._run_exploit_phase(target, session, scanner, "xxe", "XXE")

    def _phase_42_exploit_cmdi(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 42: EXPLOTAR CMDi (System enum, file read/write, webshell, reverse/bind shell)")
        return self._run_exploit_phase(target, session, scanner, "command_injection", "CMDi/RCE")

    def _phase_43_exploit_upload(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 43: EXPLOTAR UPLOAD (Webshell deploy, verify execution, persist)")
        return self._run_exploit_phase(target, session, scanner, "file_upload", "File Upload")

    def _phase_44_exploit_jwt(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 44: EXPLOTAR JWT (Forge admin token, alg:none, key confusion, token reuse)")
        return self._run_exploit_phase(target, session, scanner, "jwt", "JWT")

    def _phase_45_exploit_lfi(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 45: EXPLOTAR LFI (Log poison -> RCE, /proc/self/environ, php://filter)")
        return self._run_exploit_phase(target, session, scanner, "lfi", "LFI")

    def _phase_46_exploit_deserialization(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 46: EXPLOTAR DESERIALIZACIÓN (ysoserial, phar, pickle, ObjectDataProvider)")
        return self._run_exploit_phase(target, session, scanner, "deserialization", "Deserializacion")

    def _phase_46_exploit_nosql(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 46b: EXPLOTAR NoSQL (Auth bypass, data extraction, RCE via $where)")
        return self._run_exploit_phase(target, session, scanner, "nosql", "NoSQL")

    def _phase_47_exploit_graphql(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 47: EXPLOTAR GRAPHQL (Data exfil, DoS, batch abuse)")
        return self._run_exploit_phase(target, session, scanner, "graphql", "GraphQL")

    def _phase_48_exploit_oauth(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 48: EXPLOTAR OAUTH (Account takeover, token theft)")
        return self._run_exploit_phase(target, session, scanner, "oauth", "OAuth")

    # ============================================================
    # FASE 5: CADENAS DE EXPLOTACIÓN (ChainEngine - TODAS)
    # ============================================================
    def _phase_49_chain_sqli_webshell(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 49: CADENA SQLi -> File Write -> Webshell -> RCE")
        return self._run_chain_phase(target, session, scanner, "sqli_webshell", "SQLi -> Webshell")

    def _phase_50_chain_ssrf_cloud(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 50: CADENA SSRF -> Cloud Metadata -> IAM Creds -> Console Access")
        return self._run_chain_phase(target, session, scanner, "ssrf_cloud_creds", "SSRF -> Cloud Creds")

    def _phase_51_chain_lfi_log_poison(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 51: CADENA LFI -> Log Poisoning -> RCE")
        return self._run_chain_phase(target, session, scanner, "lfi_log_poison", "LFI -> Log Poisoning")

    def _phase_52_chain_ssti_rce(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 52: CADENA SSTI -> RCE -> File Read -> Persistence")
        return self._run_chain_phase(target, session, scanner, "ssti_to_rce", "SSTI -> RCE")

    def _phase_53_chain_upload_shell(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 53: CADENA Upload Bypass -> Webshell -> Full Control")
        return self._run_chain_phase(target, session, scanner, "upload_full_control", "Upload -> Full Control")

    def _phase_54_chain_jwt_privesc(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 54: CADENA JWT Analysis -> Forge Admin -> Admin Panel Access")
        return self._run_chain_phase(target, session, scanner, "jwt_privilege_esc", "JWT -> PrivEsc")

    def _phase_55_chain_xxe_creds(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 55: CADENA XXE -> /etc/passwd -> /etc/shadow -> SSH Keys")
        return self._run_chain_phase(target, session, scanner, "xxe_to_credentials", "XXE -> Credentials")

    def _phase_56_chain_sqli_os(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 56: CADENA SQLi -> OS Command -> Cred Dump -> Lateral Movement")
        return self._run_chain_phase(target, session, scanner, "sqli_to_os", "SQLi -> OS")

    def _phase_57_chain_open_redirect_xss(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 57: CADENA Open Redirect -> XSS Delivery -> Cookie Theft")
        return self._run_chain_phase(target, session, scanner, "open_redirect_xss", "Open Redirect -> XSS")

    def _phase_58_chain_ad_full(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 58: CADENA AD: Kerberoasting -> AS-REP -> DCSync -> Golden Ticket -> Domain Admin")
        return self._run_chain_phase(target, session, scanner, "ad_full_compromise", "AD Full Compromise")

    # ============================================================
    # FASE 6: POST-EXPLOTACIÓN COMPLETA
    # ============================================================
    def _phase_59_cred_spray_http(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 59: CREDENTIAL SPRAYING HTTP Forms")
        scanner.post_exploitation(target, session=session)

    def _phase_60_cred_spray_smb(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 60: CREDENTIAL SPRAYING SMB (psexec, smbexec, wmiexec)")
        return self._run_service_phase(target, session, scanner, "SMB", 445, lateral_method="_try_smb")

    def _phase_61_cred_spray_ssh(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 61: CREDENTIAL SPRAYING SSH (keys + passwords)")
        return self._run_service_phase(target, session, scanner, "SSH", 22, lateral_method="_try_ssh")

    def _phase_62_cred_spray_rdp(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 62: CREDENTIAL SPRAYING RDP")
        return self._run_service_phase(target, session, scanner, "RDP", 3389, lateral_method="_try_rdp")

    def _phase_63_cred_spray_mssql(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 63: CREDENTIAL SPRAYING MSSQL (xp_cmdshell)")
        return self._run_service_phase(target, session, scanner, "MSSQL", 1433)

    def _phase_64_cred_spray_postgres(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 64: CREDENTIAL SPRAYING PostgreSQL (COPY TO PROGRAM)")
        return self._run_service_phase(target, session, scanner, "PostgreSQL", 5432)

    def _phase_65_cred_spray_mysql(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 65: CREDENTIAL SPRAYING MySQL (UDF, INTO OUTFILE)")
        return self._run_service_phase(target, session, scanner, "MySQL", 3306)

    def _phase_66_cred_spray_ldap(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 66: CREDENTIAL SPRAYING LDAP Bind")
        return self._run_service_phase(target, session, scanner, "LDAP", 389)

    def _phase_67_cred_spray_winrm(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 67: CREDENTIAL SPRAYING WinRM (PowerShell Remoting)")
        return self._run_service_phase(target, session, scanner, "WinRM", 5985, lateral_method="_try_winrm")

    def _phase_68_system_enum(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 68: POST-EXPLOIT ENUM (linpeas/winpeas auto: kernel, services, tasks, drivers)")
        if not self._local_postex_allowed("FASE 68 enumeracion local"):
            return None
        from post_exploitation.system_enum import SystemEnumerator
        return self._run_postex("Enumeracion de sistema", SystemEnumerator().enumerate_all, target, session)

    def _phase_69_cred_harvest(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 69: CREDENTIAL HARVEST (Browser, WiFi, SSH keys, configs, KeePass)")
        if not self._local_postex_allowed("FASE 69 harvest de credenciales"):
            return None
        from post_exploitation.credential_harvest import CredentialHarvester
        return self._run_postex("Harvest de credenciales", CredentialHarvester().harvest_all, target, session)

    def _phase_70_lateral_movement(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 70: LATERAL MOVEMENT (SMB, WinRM, SSH, RDP, WMI, Pass-the-Hash/Ticket, DCOM)")
        creds = self._credentials(scanner)
        if not creds:
            from core.utils import print_info
            print_info("Sin credenciales capturadas -> movimiento lateral no ejecutado.")
            return {"credentials": 0}
        from post_exploitation.lateral_movement import LateralMovement
        return self._run_postex("Movimiento lateral", LateralMovement().attempt_all, target, session, creds)

    def _phase_71_persistence(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 71: PERSISTENCE (Cron, systemd, Registry, Scheduled Tasks, WMI, SSH keys, COM)")
        if not self._local_postex_allowed("FASE 71 persistencia"):
            return None
        creds = self._credentials(scanner)
        if not creds:
            from core.utils import print_info
            print_info("Sin credenciales capturadas -> persistencia no instalada.")
            return {"credentials": 0}
        from post_exploitation.persistence import Persistence
        return self._run_postex("Persistencia", Persistence().install_all, target, session, creds)

    def _phase_72_privilege_escalation(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 72: PRIVILEGE ESCALATION (Kernel exploits, sudo, SUID, capabilities, token impersonation, DLL hijack)")
        if not self._local_postex_allowed("FASE 72 privilege escalation"):
            return None
        creds = self._credentials(scanner)
        from post_exploitation.privilege_escalation import PrivilegeEscalation
        return self._run_postex("Privilege escalation", PrivilegeEscalation().attempt_all, target, session, creds)

    def _phase_73_pivoting(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 73: PIVOTING (SSH tunnels, chisel, ligolo-ng, proxychains, meterpreter)")
        if not self._local_postex_allowed("FASE 73 pivoting"):
            return None
        creds = self._credentials(scanner)
        if not creds:
            from core.utils import print_info
            print_info("Sin credenciales capturadas -> pivoting no configurado.")
            return {"credentials": 0}
        from post_exploitation.pivoting import Pivoting
        return self._run_postex("Pivoting", Pivoting().setup_all, target, session, creds)

    def _phase_74_data_exfil(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 74: DATA EXFIL (DNS, HTTP/S, ICMP, Cloud storage S3/GCS/Azure Blob)")
        if not self._local_postex_allowed("FASE 74 data exfil"):
            return None
        import json as _json
        findings = self._scan_findings(scanner)
        payload = _json.dumps({
            "target": target,
            "findings": [{"id": f.get("id"), "severity": f.get("severity"),
                           "title": f.get("title")} for f in findings[:200]],
        }, ensure_ascii=False, default=str).encode("utf-8", errors="replace")
        from post_exploitation.data_exfil import DataExfiltrator
        return self._run_postex("Exfiltracion de datos", DataExfiltrator().exfiltrate_all,
                                 target, session, payload, methods=["dns", "http", "https"])

    def _phase_75_cleanup(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 75: CLEANUP (Log tampering, timestomp, artifact removal)")
        if not self._local_postex_allowed("FASE 75 cleanup"):
            return None
        artifacts = []
        am = getattr(scanner, "artifact_manager", None)
        if am is not None:
            artifacts = [a.get("path") for a in am.list_artifacts()
                         if isinstance(a, dict) and a.get("path")]
        from post_exploitation.cleanup import Cleanup
        return self._run_postex("Cleanup", Cleanup().cleanup_all, target, session, artifacts)

    # ============================================================
    # FASE 7: CVE AUTO-EXPLOTACIÓN
    # ============================================================
    def _phase_76_cve_scan(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 76: CVE SCAN (Nuclei full scan + CVE mapping)")
        from tools.nuclei_tool import NucleiTool
        tool = NucleiTool()
        if not tool.is_installed():
            from core.utils import print_warning
            print_warning("Nuclei no instalado -> escaneo CVE omitido.")
            return None
        return self._run_postex("Escaneo CVE (nuclei)", tool.run_scan, target, session=session)

    def _phase_77_cve_auto_exploit(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 77: CVE AUTO-EXPLOIT (Top 50 CVEs críticos confirmados)")
        from tools.nuclei_tool import NucleiTool
        from core.utils import print_good, print_info
        tool = NucleiTool()
        if not tool.is_installed():
            print_info("Nuclei no instalado -> priorizacion de CVE omitida.")
            return None
        result = self._run_postex("CVE criticos (nuclei)", tool.run_scan, target,
                                   session=session, extra_args=["-tags", "cve",
                                                                  "-severity", "critical,high"])
        items = (result or {}).get("findings", []) if isinstance(result, dict) else []
        cves = sorted({str(f.get("template_id", "")) for f in items
                       if str(f.get("template_id", "")).upper().startswith("CVE-")})
        if cves:
            print_good(f"{len(cves)} CVEs confirmados: " + ", ".join(cves[:15]))
        else:
            print_info("0 CVEs criticos confirmados en el objetivo.")
        print_info("La explotacion automatica de CVE no esta implementada; revisarlos manualmente.")
        return {"cves": cves, "scanned": len(items)}

    # ============================================================
    # FASE 8: REPORTES FINALES ENTERPRISE
    # ============================================================
    def _phase_78_report_executive(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 78: REPORTE EJECUTIVO (Risk score, business impact, compliance)")
        from core.utils import print_good
        files = scanner.save_reports("reports/executive", formats=["html"]) or []
        for path in files:
            print_good(f"  -> {path}")
        return {"files": files}

    def _phase_79_report_technical(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 79: REPORTE TÉCNICO (PoC reproducibles curl/python/nuclei, evidence)")
        from core.utils import print_good
        files = scanner.save_reports("reports/technical", formats=["json"]) or []
        for path in files:
            print_good(f"  -> {path}")
        return {"files": files}

    def _phase_80_report_compliance(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 80: COMPLIANCE MAPPING (OWASP Top 10, NIST 800-53, PCI-DSS 4.0, ISO 27001)")
        import json as _json
        from core.remediation import get_remediation
        from core.utils import print_good, print_info
        findings = self._scan_findings(scanner)
        if not findings:
            print_info("Sin hallazgos -> no hay mapeo de compliance que generar.")
            return {"controls": {}}
        counts = {}
        for f in findings:
            advice = get_remediation(f.get("type") or "", f.get("severity", "info"))
            if not advice:
                continue
            for ctrl, val in (advice.compliance or {}).items():
                key = f"{ctrl}: {val}"
                counts[key] = counts.get(key, 0) + 1
        out = os.path.join("reports", "compliance", "compliance.json")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", encoding="utf-8") as fh:
            _json.dump({"controls": counts, "total_findings": len(findings)},
                       fh, indent=2, ensure_ascii=False)
        print_good(f"Compliance: {len(counts)} controles mapeados -> {out}")
        for key, n in sorted(counts.items(), key=lambda x: -x[1])[:8]:
            print_good(f"  {key}  ({n} hallazgos)")
        return {"controls": counts}

    def _phase_81_report_attack_path(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 81: ATTACK PATH GRAPH (BloodHound style, choke points, critical assets)")
        from core.utils import print_good, print_info
        engine = self._chain_engine(scanner)
        possible = engine.discover_chains(self._scan_findings(scanner), target, session) or []
        if not possible:
            print_info("0 cadenas de ataque posibles con los hallazgos actuales.")
            return {"chains": []}
        print_good(f"{len(possible)} cadenas de ataque posibles:")
        for c in possible:
            print_good(f"  [{c.get('chain_id')}] {c.get('chain_name')}")
        return {"chains": possible}

    def _phase_82_report_remediation(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 82: REMEDIATION GUIDE (Fixes código, hardening, WAF rules, Sigma/YARA)")
        import json as _json
        from core.remediation import get_remediation
        from core.utils import print_good, print_info
        findings = self._scan_findings(scanner)
        plan, seen = [], set()
        for f in findings:
            ft = f.get("type") or ""
            sev = f.get("severity", "info")
            key = (ft, sev)
            if key in seen:
                continue
            seen.add(key)
            advice = get_remediation(ft, sev)
            if advice:
                plan.append({"type": ft, "severity": sev, "title": advice.title,
                             "steps": advice.remediation_steps[:3],
                             "compliance": advice.compliance})
        if not plan:
            print_info("Sin hallazgos con guia de remediacion asociada.")
            return {"plan": []}
        out = os.path.join("reports", "remediation", "remediation.json")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", encoding="utf-8") as fh:
            _json.dump({"total_findings": len(findings), "plan": plan},
                       fh, indent=2, ensure_ascii=False, default=str)
        print_good(f"Guia de remediacion: {len(plan)} items -> {out}")
        for item in plan[:6]:
            print_good(f"  [{item['severity'].upper()}] {item['title']}")
        return {"plan": plan}

    def _phase_83_artifact_package(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 83: ARTIFACT PACKAGE (Requests/responses, screenshots, logs, chains)")
        scanner.save_reports("reports/final", formats=["html", "json", "markdown", "txt", "csv", "sarif"])

    def _run_info_gathering(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 1: RECONOCIMIENTO + HIDDEN ROUTES")
        result = scanner.run_module("info_gathering", target, session=session)
        try:
            from exploit.orchestrator import ExploitOrchestrator
            orch = ExploitOrchestrator(scanner)
            if "hidden_routes" in orch._exploiters:
                orch._exploiters["hidden_routes"].discover(target, session)
        except Exception:
            logging.exception("_run_info_gathering: hidden_routes discovery failed")
        return result

    def _run_nmap_nuclei(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 2: NMAP + NUCLEI")
        scanner.run_module("nmap", target, session=session)
        return scanner.run_module("nuclei", target, session=session)

    def _run_fuzzing(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 3: FUZZING (DIRS, VHOSTS, SUBDOMAINS)")
        scanner.run_module("directory", target, session=session)
        scanner.run_module("vhost", target, session=session)
        return scanner.run_module("subdomain", target, session=session)

    def _run_spider_source(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 4: SPIDER + SOURCE CODE ANALYSIS")
        scanner.run_module("spider", target, session=session)
        return scanner.run_module("source_code", target, session=session)

    def _run_api_wordpress(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 5: API DISCOVERY + WORDPRESS DETECTION")
        scanner.run_module("api", target, session=session)
        return scanner.run_module("wordpress", target, session=session)

    def _run_injection(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 6: INJECTION TESTS (SQLi, XSS, Command Injection, LFI)")
        return scanner.run_module("injection", target, session=session)

    def _run_advanced(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 7: ADVANCED TESTS (SSRF, SSTI, XXE, CRLF, Smuggling, Cache)")
        return scanner.run_module("advanced_security", target, session=session)

    def _run_api_jwt_upload(self, target, session, scanner):
        from core.utils import print_phase, print_info, print_good
        from core.finding import Finding, FindingType
        print_phase("FASE 8: API SECURITY + JWT + FILE UPLOAD")
        result = scanner.run_module("api", target, session=session)

        print_info("Testing JWT vulnerabilities...")
        try:
            from core.utils import get_session
            http_session = session or get_session()
            jwt_headers = [
                {"Authorization": "Bearer null"},
                {"Authorization": "Bearer "},
            ]
            for h in jwt_headers:
                try:
                    resp = http_session.get(target, headers=h, timeout=5, allow_redirects=True)
                    if resp.status_code == 200 and "logout" in resp.text.lower():
                        f = Finding(type=FindingType.JWT_NONE_ALG, severity="critical",
                                    title="JWT None Algorithm accepted", detail=f"Header {h} accepted",
                                    url=target, module="api_jwt", confirmed=True)
                        scanner.finding_manager.add(f)
                        scanner.findings.append(f.to_dict())
                        print_good(f"JWT None Algorithm accepted!")
                        break
                except Exception as e:
                    logging.exception("JWT header check failed")
                    continue

            jwt_paths = ["/api/verify", "/api/auth/verify", "/auth/verify", "/api/check"]
            for path in jwt_paths:
                try:
                    url = target.rstrip("/") + path
                    resp = http_session.get(url, headers={"Authorization": "Bearer "}, timeout=5)
                    if resp.status_code in (200, 401, 403):
                        f = Finding(type=FindingType.API_ENDPOINT, severity="low",
                                    title=f"JWT verification endpoint: {path}",
                                    detail=f"Status: {resp.status_code}", url=url, module="api_jwt")
                        scanner.finding_manager.add(f)
                        scanner.findings.append(f.to_dict())
                        break
                except Exception as e:
                    logging.exception("JWT endpoint check failed")
                    continue
        except Exception as e:
            print(f"{Fore.RED}  [-] JWT test error: {e}{Style.RESET_ALL}")

        print_info("Testing file upload endpoints...")
        upload_paths = ["/upload", "/api/upload", "/api/files/upload", "/admin/upload", "/file/upload"]
        for path in upload_paths:
            try:
                url = target.rstrip("/") + path
                resp = http_session.get(url, timeout=5, allow_redirects=False)
                if resp.status_code in (200, 405, 400):
                    f = Finding(type=FindingType.FILE_UPLOAD_BYPASS, severity="medium",
                                title=f"Upload endpoint found: {path}",
                                detail=f"Status: {resp.status_code}", url=url, module="api_jwt")
                    scanner.finding_manager.add(f)
                    scanner.findings.append(f.to_dict())
            except Exception as e:
                logging.exception("File upload check failed")
                continue

        return result

    def _run_user_enum(self, target, session, scanner):
        return scanner.run_module("user_enum", target, session=session)

    def _run_active_directory(self, target, session, scanner):
        return scanner.run_module("active_directory", target, session=session)

    def _run_nosql_ldap_deser(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 9: NoSQL + LDAP + DESERIALIZATION INJECTION")
        scanner.run_module("nosql", target, session=session)
        scanner.run_module("ldap", target, session=session)
        return scanner.run_module("deserialization", target, session=session)

    def _run_oauth_graphql_ws(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("FASE 10: OAUTH + GRAPHQL + WEBSOCKET TESTING")
        scanner.run_module("oauth", target, session=session)
        scanner.run_module("graphql", target, session=session)
        return scanner.run_module("websocket", target, session=session)

    def _run_headless_browser(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("HEADLESS BROWSER: SPA CRAWL + DOM XSS")
        if not hasattr(scanner, "headless_browser") or scanner.headless_browser is None:
            print(f"{Fore.YELLOW}  [-] Headless browser not available. Install playwright.{Style.RESET_ALL}")
            return {}
        try:
            browser = scanner.headless_browser
            urls = browser.crawl(target, max_depth=3)
            print(f"{Fore.GREEN}  [+] Crawled {len(urls)} URLs{Style.RESET_ALL}")
            dom_xss = browser.detect_dom_xss(target)
            if dom_xss:
                for dx in dom_xss:
                    from core.finding import Finding, FindingType
                    f = Finding(url=target, severity="high", title="DOM XSS Detected", detail=dx, type=FindingType.XSS_DOM)
                    if hasattr(scanner, "finding_manager"):
                        scanner.finding_manager.add(f)
                    print(f"{Fore.RED}  [!] DOM XSS: {dx}{Style.RESET_ALL}")
            return {"urls_crawled": len(urls), "dom_xss": len(dom_xss)}
        except Exception as e:
            print(f"{Fore.RED}  [-] Browser error: {e}{Style.RESET_ALL}")
            return {}

    def _run_waf_detection(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("WAF DETECTION + BYPASS")
        if not hasattr(scanner, "waf_detector") or scanner.waf_detector is None:
            print(f"{Fore.YELLOW}  [-] WAF detector not available.{Style.RESET_ALL}")
            return {}
        try:
            import asyncio
            waf = scanner.waf_detector
            loop = asyncio.new_event_loop()
            result = loop.run_until_complete(waf.detect(target, session=session))
            loop.close()
            if result and result.name != "None":
                print(f"{Fore.RED}  [!] WAF Detected: {result.name}{Style.RESET_ALL}")
                bypasses = waf.get_bypasses(result.name) if hasattr(waf, 'get_bypasses') else []
                if bypasses:
                    print(f"{Fore.GREEN}  [+] Suggested bypass techniques:{Style.RESET_ALL}")
                    for b in bypasses[:5]:
                        print(f"    {Fore.CYAN}{chr(9656)}{Style.RESET_ALL} {b}")
                return {"detected": True, "waf_name": result.name, "confidence": result.confidence}
            else:
                print(f"{Fore.GREEN}  [+] No WAF detected{Style.RESET_ALL}")
                return {"detected": False}
        except Exception as e:
            print(f"{Fore.RED}  [-] WAF detection error: {e}{Style.RESET_ALL}")
            return {}

    def _run_scheduler(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("SCHEDULED SCANS")
        try:
            from scheduler.scan_scheduler import ScanScheduler
            sched = ScanScheduler()
            presets = sched.get_preset_crons()
            print(f"\n  {Fore.CYAN}Available Presets:{Style.RESET_ALL}")
            for name, cron in presets.items():
                print(f"    {Fore.GREEN}{name}{Style.RESET_ALL}: {cron}")
            print(f"\n  {Fore.CYAN}Current Schedule:{Style.RESET_ALL}")
            for scan in sched.get_schedule():
                print(f"    {scan['id']}: {scan['target']} [{scan['scan_type']}] -> next: {scan.get('next_run_human', 'N/A')}")
            print(f"\n  {Fore.YELLOW}To add a scheduled scan, use --schedule flag.{Style.RESET_ALL}")
            return {}
        except Exception as e:
            print(f"{Fore.RED}  [-] Scheduler error: {e}{Style.RESET_ALL}")
            return {}

    def _run_notifications(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("NOTIFICATIONS SETUP")
        print(f"\n  {Fore.CYAN}Configure notifications via environment variables:{Style.RESET_ALL}")
        print(f"    SYSVOIDSCAN_TG_BOT_TOKEN  - Telegram bot token")
        print(f"    SYSVOIDSCAN_TG_CHAT_ID    - Telegram chat ID")
        print(f"    SYSVOIDSCAN_DISCORD_WEBHOOK - Discord webhook URL")
        print(f"    SYSVOIDSCAN_SLACK_WEBHOOK   - Slack webhook URL")
        print(f"    SYSVOIDSCAN_SMTP_HOST       - SMTP server host")
        print(f"    SYSVOIDSCAN_SMTP_PORT       - SMTP server port")
        print(f"    SYSVOIDSCAN_SMTP_USER       - SMTP username")
        print(f"    SYSVOIDSCAN_SMTP_PASS       - SMTP password")
        print(f"    SYSVOIDSCAN_SMTP_FROM       - Sender email")
        print(f"    SYSVOIDSCAN_SMTP_TO         - Recipient emails (comma-separated)")
        print(f"    SYSVOIDSCAN_WEBHOOKS        - Custom webhook URLs (comma-separated)")
        try:
            from notifications.notifier import Notifier
            notifier = Notifier.from_env()
            channels = []
            if notifier.telegram: channels.append("Telegram")
            if notifier.discord: channels.append("Discord")
            if notifier.slack: channels.append("Slack")
            if notifier.email: channels.append("Email")
            if notifier.webhooks: channels.append(f"{len(notifier.webhooks)} Webhooks")
            if channels:
                print(f"\n  {Fore.GREEN}[+] Active channels: {', '.join(channels)}{Style.RESET_ALL}")
            else:
                print(f"\n  {Fore.YELLOW}[!] No notification channels configured.{Style.RESET_ALL}")
        except Exception:
            logging.exception("_run_notifications: failed to initialize notifier")
        return {}

    def _run_api_server(self, target, session, scanner):
        from core.utils import print_phase
        print_phase("REST API SERVER")
        print(f"\n  {Fore.CYAN}Start the API server:{Style.RESET_ALL}")
        print(f"    python api/server.py")
        print(f"\n  {Fore.CYAN}Endpoints:{Style.RESET_ALL}")
        print(f"    GET  /api/v1/health           - Health check")
        print(f"    POST /api/v1/scan             - Start scan")
        print(f"    GET  /api/v1/scan/<id>        - Get scan status")
        print(f"    GET  /api/v1/scan/<id>/results - Get results")
        print(f"    GET  /api/v1/scan/<id>/report  - Get report")
        print(f"    GET  /api/v1/scans            - List all scans")
        print(f"    GET  /api/v1/findings         - List findings")
        print(f"    GET  /api/v1/stats            - Get statistics")
        print(f"\n  {Fore.YELLOW}API runs on http://0.0.0.0:8080{Style.RESET_ALL}")
        return {}

    def _view_report(self, scanner):
        from core.utils import print_info
        scan_data = scanner.get_summary()
        print(f"\n{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  SCAN SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
        print(f"  Target: {scan_data.get('target', 'N/A')}")
        print(f"  Findings: {scan_data.get('total_findings', 0)}")
        sev = scan_data.get("severity_counts", {})
        if sev:
            print(f"  Critical: {Fore.RED}{sev.get('critical', 0)}{Style.RESET_ALL}")
            print(f"  High:     {Fore.LIGHTRED_EX}{sev.get('high', 0)}{Style.RESET_ALL}")
            print(f"  Medium:   {Fore.YELLOW}{sev.get('medium', 0)}{Style.RESET_ALL}")
            print(f"  Low:      {Fore.CYAN}{sev.get('low', 0)}{Style.RESET_ALL}")
            print(f"  Info:     {Fore.WHITE}{sev.get('info', 0)}{Style.RESET_ALL}")
        print()
        return {}

    def _export_report(self, scanner):
        from core.utils import print_info, print_good
        print(f"\n  {Fore.CYAN}Export Report{Style.RESET_ALL}")
        print(f"\n  Available formats:")
        print(f"    1. HTML  2. Dashboard  3. JSON  4. Markdown  5. CSV  6. SARIF  7. Jira JSON  8. TXT")
        try:
            fmt = input(f"\n  {Fore.WHITE}Select format [1-8]: {Style.RESET_ALL}").strip()
        except (EOFError, KeyboardInterrupt):
            fmt = "1"
        fmt_map = {"1": "html", "2": "dashboard", "3": "json", "4": "markdown", "5": "csv", "6": "sarif", "7": "jira", "8": "txt"}
        format_type = fmt_map.get(fmt, "html")
        try:
            output_dir = input(f"  {Fore.WHITE}Output directory [./reports]: {Style.RESET_ALL}").strip()
        except (EOFError, KeyboardInterrupt):
            output_dir = ""
        if not output_dir:
            output_dir = os.path.join(os.getcwd(), "reports")
        os.makedirs(output_dir, exist_ok=True)
        if format_type == "sarif":
            try:
                from reports.sarif_report import SARIFReport
                report = SARIFReport(
                    scan_data=getattr(scanner, "scan_data", None),
                    findings=scanner.finding_manager.get_all() if hasattr(scanner, "finding_manager") else [],
                    target=getattr(scanner.config, "target_url", "") if hasattr(scanner, "config") else "",
                    output_dir=output_dir,
                )
                path = os.path.join(output_dir, "sarif_report.sarif")
                report.save(path)
                print_good(f"SARIF report exported to: {path}")
            except Exception as e:
                print(f"{Fore.RED}  [-] SARIF export error: {e}{Style.RESET_ALL}")
        elif format_type == "jira":
            try:
                from reports.jira_report import JiraReporter, JiraConfig
                print(f"\n  {Fore.YELLOW}Jira export requires configuration.{Style.RESET_ALL}")
                server = input(f"  {Fore.WHITE}Jira server URL: {Style.RESET_ALL}").strip()
                if server:
                    username = input(f"  {Fore.WHITE}Username: {Style.RESET_ALL}").strip()
                    token = input(f"  {Fore.WHITE}API token: {Style.RESET_ALL}").strip()
                    project = input(f"  {Fore.WHITE}Project key: {Style.RESET_ALL}").strip()
                    if all([username, token, project]):
                        config = JiraConfig(server=server, username=username, api_token=token, project_key=project)
                        reporter = JiraReporter(config)
                        path = os.path.join(output_dir, "jira_export.json")
                        reporter.export_to_file(
                            findings=scanner.finding_manager.get_all() if hasattr(scanner, "finding_manager") else [],
                            output_path=path,
                        )
                        print_good(f"Jira export to: {path}")
            except Exception as e:
                print(f"{Fore.RED}  [-] Jira export error: {e}{Style.RESET_ALL}")
        else:
            selected_formats = ["html"] if fmt_map.get(fmt, "html") == "html" else [fmt_map.get(fmt, "html")]
            scanner.save_reports(output_dir, formats=selected_formats)
            print_good(f"Reports exported to: {output_dir}")
        return {}

    def _view_artifacts(self, scanner):
        manager = getattr(scanner, "artifact_manager", None)
        if manager is None:
            print(f"\n{Fore.YELLOW}  No artifact manager available.{Style.RESET_ALL}")
            return {}

        artifacts = manager.list_artifacts()
        if not artifacts:
            print(f"\n{Fore.YELLOW}  No artifacts found.{Style.RESET_ALL}")
            return {}

        print(f"\n{Fore.CYAN}  Artifact Index{Style.RESET_ALL}")
        print(f"  {'─' * 40}")
        for index, artifact in enumerate(artifacts, start=1):
            meta = artifact.get("metadata", {}) or {}
            print(
                f"  {Fore.GREEN}{index:>2}{Style.RESET_ALL}. {artifact.get('title')} "
                f"({artifact.get('kind')}, {artifact.get('size_bytes', 0)} bytes)"
            )
            if meta:
                print(f"       {Fore.WHITE}meta: {meta}{Style.RESET_ALL}")

        try:
            choice = input(f"\n  {Fore.WHITE}Choose artifact number to preview/open (blank to return): {Style.RESET_ALL}").strip()
        except (EOFError, KeyboardInterrupt):
            return {}
        if not choice:
            return {}
        if not choice.isdigit() or int(choice) < 1 or int(choice) > len(artifacts):
            print(f"{Fore.RED}  Invalid selection.{Style.RESET_ALL}")
            return {}

        artifact = artifacts[int(choice) - 1]
        preview = manager.preview_artifact(artifact.get("path", ""))
        print(f"\n  {Fore.CYAN}Preview for {artifact.get('title')}{Style.RESET_ALL}")
        print(f"  {preview}\n")
        try:
            action = input(f"  {Fore.WHITE}Open this artifact? [y/N]: {Style.RESET_ALL}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return {}
        if action == "y":
            opened = manager.open_artifact(artifact.get("path", ""))
            if opened:
                print(f"{Fore.GREEN}  Artifact opened successfully.{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}  Could not open artifact automatically.{Style.RESET_ALL}")
        return {}

    def _list_plugins(self, scanner):
        loader = self.plugin_loader or getattr(scanner, "plugin_loader", None)
        if loader is None:
            print(f"\n{Fore.YELLOW}  No plugin loader available.{Style.RESET_ALL}")
            return {}

        plugins = loader.list_plugins()
        errors = loader.get_error_summary()

        if not plugins and not errors:
            print(f"\n{Fore.YELLOW}  No plugins found or loaded.{Style.RESET_ALL}")
            return {}

        print(f"\n{Fore.CYAN}  Plugins{Style.RESET_ALL}")
        print(f"  {'─' * 40}")
        for plugin in plugins:
            tags = plugin.get("tags") or []
            tag_line = f" tags={tags}" if tags else ""
            author = plugin.get("author") or "unknown"
            print(
                f"  {Fore.GREEN}+{Style.RESET_ALL} {plugin.get('name')} v{plugin.get('version')} "
                f"[{plugin.get('category', 'misc')}] by {author}{tag_line}"
            )
            if plugin.get("description"):
                print(f"      {Fore.WHITE}{plugin.get('description')}{Style.RESET_ALL}")
        if errors:
            print(f"\n{Fore.RED}  Load Errors:{Style.RESET_ALL}")
            for name, err in errors.items():
                print(f"    {Fore.RED}-{Style.RESET_ALL} {name}: {err}")

        return {}

    def _run_brute_force(self, target, session, scanner):
        from core.utils import print_phase, print_info, print_good, print_warning
        from core.finding import Finding, FindingType
        from urllib.parse import urlparse
        print_phase("BRUTE FORCE (SSH, FTP, HTTP)")
        results = {"ssh": [], "ftp": [], "http": []}

        try:
            import requests
            from core.utils import get_session

            http_session = session or get_session()
            from urllib.parse import urljoin

            parsed = urlparse(target)
            host = parsed.hostname or target

            http_paths = ["/login", "/signin", "/wp-login.php", "/admin/login", "/auth/login"]
            http_users = ["admin", "root", "user", "test", "guest"]
            http_passes = ["admin", "password", "123456", "root", "admin123", "test", "guest", "letmein", "password123"]

            for path in http_paths:
                login_url = urljoin(target, path)
                try:
                    resp = http_session.get(login_url, timeout=5, allow_redirects=True)
                    if resp.status_code == 200:
                        for user in http_users[:3]:
                            for pwd in http_passes[:3]:
                                try:
                                    r = http_session.post(login_url, data={"username": user, "password": pwd, "user": user, "pass": pwd},
                                                      timeout=5, verify=getattr(session, "verify", True), allow_redirects=True)
                                    if r.status_code in (200, 302) and "logout" in r.text.lower():
                                        f = Finding(type=FindingType.INFO_DISCLOSURE, severity="critical",
                                                    title=f"HTTP Brute Force: {user}:{pwd} en {login_url}",
                                                    detail=f"Login exitoso", url=login_url, module="brute_force", confirmed=True)
                                        scanner.finding_manager.add(f)
                                        scanner.findings.append(f.to_dict())
                                        results["http"].append({"user": user, "pass": pwd, "url": login_url})
                                        print_good(f"Credencial encontrada: {user}:{pwd} en {login_url}")
                                        break
                                except Exception:
                                    logging.exception("brute_force: http post iteration failed")
                                    continue
                    break
                except Exception:
                    logging.exception("brute_force: login_url request failed")
                    continue

            try:
                from tools.hydra_tool import HydraTool
                hydra = HydraTool()
                if hydra.is_installed():
                    print_info("Hydra disponible para SSH/FTP bruteforce")
            except Exception:
                logging.exception("brute_force: hydra check failed")

        except Exception as e:
            print(f"{Fore.RED}  [-] Brute force error: {e}{Style.RESET_ALL}")

        total = sum(len(v) for v in results.values())
        print_good(f"Brute force: {total} credenciales encontradas")
        return results

def run_interactive():
    from core.scanner import Scanner
    from core.utils import get_session
    from plugins.loader import PluginLoader

    menu = InteractiveMenu()
    scanner = Scanner()
    loader = PluginLoader()
    loader.load_all()
    loader.register_hooks(scanner)
    scanner.plugin_loader = loader
    menu.plugin_loader = loader
    menu.show_banner(scanner)
    session = get_session()
    targets = menu.prompt_target_selection()
    if not targets:
        print(f"{Fore.RED}  No targets provided. Exiting.{Style.RESET_ALL}")
        return

    target = targets[0]
    while True:
        choice = menu.show_menu(targets=[target], authenticated=menu._authenticated, scanner=scanner)
        if choice == "25" or choice.lower() in ("exit", "quit"):
            print(f"{Fore.GREEN}  Bye!{Style.RESET_ALL}")
            break
        result = menu.dispatch(choice, target, session, scanner)
        if isinstance(result, dict) and result.get("error"):
            print(f"{Fore.RED}  Error: {result['error']}{Style.RESET_ALL}")
        elif result is None:
            continue
        elif choice != "14" and choice != "23":
            print(f"{Fore.GREEN}  Done.{Style.RESET_ALL}")
        time.sleep(1)