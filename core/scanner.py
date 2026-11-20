import logging
import os
import time
from typing import Any, Dict, List, Optional

from core.config import Config
from core.database import Database
from core.finding import Finding, FindingType, FindingManager, CVSSScore, Evidence
from core.pipeline import ScanPipeline, ScanTask
from core.oob_server import OOBServer
from core.waf_detector import WAFDetector
from core.evidence_collector import EvidenceCollector
from core.artifact_manager import ArtifactManager
from tools.base import ToolManager
from tools.nmap_tool import NmapTool
from tools.nuclei_tool import NucleiTool
from tools.gobuster_tool import GobusterTool
from tools.ffuf_tool import FfufTool
from tools.httpx_tool import HttpxTool
from tools.katana_tool import KatanaTool
from tools.wpscan_tool import WpscanTool
from tools.subfinder_tool import SubfinderTool
from tools.sqlmap_tool import SqlmapTool
from tools.dalfox_tool import DalfoxTool
from tools.whatweb_tool import WhatwebTool
from tools.hydra_tool import HydraTool
from tools.kerbrute_tool import KerbruteTool
from exploit.orchestrator import ExploitOrchestrator
from exploit.chain_engine import ChainEngine
from exploit.credential_store import CredentialStore


class Scanner:
    """Main scanner orchestrator that manages tools, modules, and scan lifecycle."""

    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.scan_data = self.config.scan_data
        self.findings = self.config.findings
        self.db = Database()
        self.tool_manager = ToolManager()
        self.finding_manager = FindingManager()
        self.oob_server = OOBServer()
        self.artifact_manager = ArtifactManager(base_dir=os.path.join('reports', 'artifacts'))
        self.evidence_collector = EvidenceCollector(artifact_manager=self.artifact_manager)
        self.waf_detector = WAFDetector()
        self.pipeline = ScanPipeline(max_workers=5)
        self._register_tools()
        self._modules = {}
        self._register_modules()
        self._exploit_orchestrator = None
        self._chain_engine = None
        self._current_scan_id = None
        self._waf_info = None

    def _register_tools(self):
        tools = [
            NmapTool(),
            NucleiTool(),
            GobusterTool(),
            FfufTool(),
            HttpxTool(),
            KatanaTool(),
            WpscanTool(),
            SubfinderTool(),
            SqlmapTool(),
            DalfoxTool(),
            WhatwebTool(),
            HydraTool(),
            KerbruteTool(),
        ]
        for tool in tools:
            self.tool_manager.register(tool)

    def _register_modules(self):
        self._modules = {
            "info_gathering": _InfoGatheringModule(self),
            "nmap": _NmapModule(self),
            "nuclei": _NucleiModule(self),
            "vhost": _VHostModule(self),
            "directory": _DirectoryModule(self),
            "subdomain": _SubdomainModule(self),
            "spider": _SpiderModule(self),
            "source_code": _SourceCodeModule(self),
            "injection": _InjectionModule(self),
            "advanced_security": _AdvancedSecurityModule(self),
            "api": _APIModule(self),
            "user_enum": _UserEnumModule(self),
            "wordpress": _WordPressModule(self),
            "active_directory": _ActiveDirectoryModule(self),
            "nosql": _NoSQLModule(self),
            "ldap": _LDAPModule(self),
            "deserialization": _DeserializationModule(self),
            "oauth": _OAuthModule(self),
            "graphql": _GraphQLModule(self),
            "websocket": _WebSocketModule(self),
        }

    def run_module(self, module_name: str, target: str, session=None) -> Optional[Dict[str, Any]]:
        module = self._modules.get(module_name)
        if not module:
            return None
        try:
            result = module.run(target, session)
            if module_name not in self.scan_data.get("scan_info", {}).get("modules_run", []):
                self.scan_data.setdefault("scan_info", {}).setdefault("modules_run", []).append(module_name)
            return result
        except Exception as e:
            self.scan_data.setdefault("scan_info", {}).setdefault("errors", []).append(
                f"{module_name}: {str(e)}"
            )
            return {"error": str(e)}

    def run_exploitation(self, target: str, session=None) -> Dict[str, Any]:
        from core.utils import print_phase, print_info

        print_phase("FASE 4: EXPLOTACION AUTOMATICA")

        if not self._exploit_orchestrator:
            self._exploit_orchestrator = ExploitOrchestrator(self)

        if not self._chain_engine:
            self._chain_engine = ChainEngine(self)

        try:
            results = self._exploit_orchestrator.exploit_all_findings(target, session)

            chain_results = []
            confirmed_findings = self.finding_manager.get_confirmed()
            if confirmed_findings:
                confirmed_dicts = [f.to_dict() for f in confirmed_findings]
                possible_chains = self._chain_engine.discover_chains(
                    confirmed_dicts, target, session
                )
                for chain_info in possible_chains:
                    chain_result = self._chain_engine.run_chain(
                        chain_info['chain_id'], target, session,
                        findings=confirmed_dicts
                    )
                    if chain_result and chain_result.get('success'):
                        chain_results.append(chain_result)
                        for cred in chain_result.get('credentials', []):
                            self._exploit_orchestrator.cred_store.store(
                                source=f"chain:{chain_info['chain_id']}",
                                username=cred.get('username', ''),
                                password=cred.get('password', ''),
                                url=target,
                                service=cred.get('service', 'web'),
                            )

            return {
                "exploit_results": results,
                "chain_results": chain_results,
                "chain_stats": self._chain_engine.get_stats(),
                "credentials": self._exploit_orchestrator.cred_store.get_all(),
                "credential_count": self._exploit_orchestrator.cred_store.count(),
            }
        except Exception as e:
            self.scan_data.setdefault("scan_info", {}).setdefault("errors", []).append(
                f"exploitation: {str(e)}"
            )
            return {"error": str(e)}

    def post_exploitation(self, target: str, session=None) -> Dict[str, Any]:
        from core.utils import print_phase, print_info, print_good, print_warning

        print_phase("FASE 5: POST-EXPLOTACION")

        if not self._exploit_orchestrator:
            self._exploit_orchestrator = ExploitOrchestrator(self)

        cred_store = self._exploit_orchestrator.cred_store
        credentials = cred_store.get_all()

        if not credentials:
            print_info("No hay credenciales capturadas para reutilizar.")
            return {"reused": False, "reason": "No credentials available"}

        print_info(f"Credenciales disponibles para reutilizar: {len(credentials)}")

        results = {
            "reused": True,
            "credential_spray_results": [],
            "successful_logins": [],
        }

        from core.utils import get_session
        from urllib.parse import urljoin
        http_session = session or get_session()

        login_paths = ["/login", "/signin", "/wp-login.php", "/admin/login", "/auth/login"]

        for cred in credentials:
            username = cred.get("username", "")
            password = cred.get("password", "")
            if not username or not password:
                continue

            print_info(f"Probando credencial: {username}:{password[:4]}****")

            for path in login_paths:
                login_url = urljoin(target, path)
                try:
                    resp = http_session.post(
                        login_url,
                        data={"username": username, "password": password, "user": username, "pass": password},
                        timeout=self.scan_data.get("scan_info", {}).get("timeout", 10),
                        allow_redirects=True,
                    )
                    if resp.status_code in (200, 302) and "logout" in resp.text.lower():
                        print_good(f"Login exitoso con {username}:{password[:4]}**** en {login_url}")
                        results["successful_logins"].append({
                            "username": username,
                            "password": password,
                            "url": login_url,
                            "status": resp.status_code,
                        })
                        finding = Finding(
                            type=FindingType.INFO_DISCLOSURE,
                            severity="critical",
                            title=f"Credential reuse: {username} en {login_url}",
                            detail="Credencial capturada reutilizada exitosamente",
                            url=login_url,
                            module="post_exploitation",
                            confirmed=True,
                        )
                        self.finding_manager.add(finding)
                        self.findings.append(finding.to_dict())
                        break
                except Exception:
                    logging.exception("scanner.py: exception")
                    continue

        print_info(f"Reutilización de credenciales: {len(results['successful_logins'])} logins exitosos")
        return results

    def run_full_pentest(self, target: str, session=None, interactive_ad: bool = True) -> Dict[str, Any]:
        self.config.target_url = target
        self.scan_data["target"]["url"] = target
        start_time = time.time()

        self.scan_data["scan_info"]["start_time"] = time.strftime("%Y-%m-%d %H:%M:%S")

        if session is None:
            from core.utils import get_session
            session = get_session()
            if session is None:
                from core.utils import print_error
                print_error("No se pudo crear sesion HTTP.")
                return self.get_summary()

        self._start_oob_server()

        self._detect_waf(target, session)

        self._build_pipeline(target, session, interactive_ad)
        self.pipeline.execute(parallel=True)

        self.run_exploitation(target, session=session)
        self.post_exploitation(target, session=session)

        end_time = time.time()
        duration = time.strftime("%H:%M:%S", time.gmtime(end_time - start_time))
        self.scan_data["scan_info"]["end_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self.scan_data["scan_info"]["duration"] = duration

        self.scan_data["stats"] = {
            "total_findings": len(self.findings),
            "structured_findings": len(self.finding_manager),
            "duration": duration,
            "modules_run": self.scan_data["scan_info"].get("modules_run", []),
            "oob_interactions": self.oob_server.get_stats() if self.oob_server.is_running else {},
            "evidence_items": self.evidence_collector.get_stats(),
            "pipeline_status": self.pipeline.get_status(),
            "waf_detected": self._waf_info.name if self._waf_info else "None",
        }

        self._stop_oob_server()

        return self.get_summary()

    def _build_pipeline(self, target: str, session, interactive_ad: bool):
        self.pipeline.clear()

        self.pipeline.add_task_raw(
            name="info_gathering", phase=1,
            func=self.run_module, args=("info_gathering", target),
            kwargs={"session": session},
        )

        self.pipeline.add_task_raw(
            name="nmap", phase=1,
            func=self.run_module, args=("nmap", target),
            kwargs={"session": session},
        )

        self.pipeline.add_task_raw(
            name="nuclei", phase=2,
            func=self.run_module, args=("nuclei", target),
            kwargs={"session": session},
            depends_on=["info_gathering"],
        )

        self.pipeline.add_task_raw(
            name="vhost", phase=2,
            func=self.run_module, args=("vhost", target),
            kwargs={"session": session},
            depends_on=["info_gathering"],
        )

        self.pipeline.add_task_raw(
            name="directory", phase=2,
            func=self.run_module, args=("directory", target),
            kwargs={"session": session},
            depends_on=["info_gathering"],
        )

        self.pipeline.add_task_raw(
            name="spider", phase=2,
            func=self.run_module, args=("spider", target),
            kwargs={"session": session},
            depends_on=["info_gathering"],
        )

        self.pipeline.add_task_raw(
            name="source_code", phase=2,
            func=self.run_module, args=("source_code", target),
            kwargs={"session": session},
            depends_on=["info_gathering"],
        )

        self.pipeline.add_task_raw(
            name="injection", phase=3,
            func=self.run_module, args=("injection", target),
            kwargs={"session": session},
            depends_on=["spider"],
        )

        self.pipeline.add_task_raw(
            name="nosql", phase=3,
            func=self.run_module, args=("nosql", target),
            kwargs={"session": session},
            depends_on=["spider"],
        )

        self.pipeline.add_task_raw(
            name="ldap", phase=3,
            func=self.run_module, args=("ldap", target),
            kwargs={"session": session},
            depends_on=["info_gathering"],
        )

        self.pipeline.add_task_raw(
            name="active_directory", phase=3,
            func=self.run_module, args=("active_directory", target),
            kwargs={"session": session},
            depends_on=["info_gathering"],
        )

        self.pipeline.add_task_raw(
            name="advanced_security", phase=3,
            func=self.run_module, args=("advanced_security", target),
            kwargs={"session": session},
            depends_on=["spider"],
        )

        self.pipeline.add_task_raw(
            name="deserialization", phase=3,
            func=self.run_module, args=("deserialization", target),
            kwargs={"session": session},
            depends_on=["spider"],
        )

        self.pipeline.add_task_raw(
            name="graphql", phase=3,
            func=self.run_module, args=("graphql", target),
            kwargs={"session": session},
            depends_on=["spider"],
        )

        self.pipeline.add_task_raw(
            name="websocket", phase=3,
            func=self.run_module, args=("websocket", target),
            kwargs={"session": session},
            depends_on=["info_gathering"],
        )

        self.pipeline.add_task_raw(
            name="oauth", phase=3,
            func=self.run_module, args=("oauth", target),
            kwargs={"session": session},
            depends_on=["info_gathering"],
        )

        self.pipeline.add_task_raw(
            name="api", phase=3,
            func=self.run_module, args=("api", target),
            kwargs={"session": session},
            depends_on=["spider"],
        )

        self.pipeline.add_task_raw(
            name="user_enum", phase=3,
            func=self.run_module, args=("user_enum", target),
            kwargs={"session": session},
            depends_on=["spider"],
        )

        self.pipeline.add_task_raw(
            name="wordpress", phase=3,
            func=self.run_module, args=("wordpress", target),
            kwargs={"session": session},
            depends_on=["info_gathering"],
        )

        if not interactive_ad:
            self.pipeline.add_task_raw(
                name="active_directory", phase=3,
                func=self.run_module, args=("active_directory", target),
                kwargs={"session": session},
                depends_on=["info_gathering"],
            )

    def _start_oob_server(self):
        from core.utils import print_info
        if not self.oob_server.is_running:
            started = self.oob_server.start()
            if started:
                print_info(f"OOB server iniciado en puerto {self.oob_server.port}")

    def _stop_oob_server(self):
        if self.oob_server.is_running:
            self.oob_server.stop()

    def _detect_waf(self, target: str, session):
        from core.utils import print_info, print_good
        import asyncio

        print_info("Detectando WAF/CDN...")
        try:
            loop = asyncio.new_event_loop()
            self._waf_info = loop.run_until_complete(self.waf_detector.detect(target, session=session))
            loop.close()
            if self._waf_info and self._waf_info.name != "None":
                print_good(f"WAF detectado: {self._waf_info.name} (confianza: {self._waf_info.confidence:.0%})")
                self.scan_data["waf"] = {
                    "name": self._waf_info.name,
                    "confidence": self._waf_info.confidence,
                    "detected_by": self._waf_info.detected_by,
                    "bypass_techniques": self._waf_info.bypass_techniques,
                }
            else:
                print_info("No se detecto WAF/CDN.")
        except Exception as e:
            print_info(f"Error detectando WAF: {e}")

    def save_reports(self, output_dir: str, formats: Optional[List[str]] = None) -> List[str]:
        os.makedirs(output_dir, exist_ok=True)
        generated = []

        from reports.html_report import HTMLReport
        from reports.json_report import JSONReport
        from reports.markdown_report import MarkdownReport
        from reports.txt_report import TXTReport
        from reports.csv_report import CSVReport

        target = self.config.target_url
        # Enrich scan_data with runtime metadata for reports (plugins, artifacts)
        try:
            if hasattr(self, 'plugin_loader') and self.plugin_loader is not None:
                try:
                    self.scan_data['plugins'] = self.plugin_loader.list_plugins()
                except Exception:
                    self.scan_data['plugins'] = []
            else:
                self.scan_data['plugins'] = []
        except Exception:
            self.scan_data['plugins'] = []

        try:
            if hasattr(self, 'artifact_manager') and self.artifact_manager is not None:
                try:
                    self.scan_data['artifacts'] = self.artifact_manager.list_artifacts()
                except Exception:
                    self.scan_data['artifacts'] = []
            else:
                self.scan_data['artifacts'] = []
        except Exception:
            self.scan_data['artifacts'] = []

        selected_formats = formats or ['html', 'json', 'markdown', 'txt', 'csv']
        from reports.sarif_report import SARIFReport
        report_map = {
            'html': HTMLReport,
            'dashboard': HTMLReport,
            'json': JSONReport,
            'markdown': MarkdownReport,
            'txt': TXTReport,
            'csv': CSVReport,
            'sarif': SARIFReport,
        }
        for fmt in selected_formats:
            fmt_name = (fmt or '').strip().lower()
            if fmt_name not in report_map:
                continue
            try:
                report_cls = report_map[fmt_name]
                gen = report_cls(self.scan_data, self.findings, target, output_dir)
                path = gen.generate()
                generated.append(path)
                if self.artifact_manager is not None:
                    try:
                        self.artifact_manager.register_file_artifact(path, kind='reports', title=os.path.basename(path), metadata={'format': fmt_name, 'target': target})
                    except Exception:
                        logging.exception("scanner.py: exception")
                        pass
            except Exception:
                logging.exception("scanner.py: exception")
                pass

        try:
            evidence_path = self.evidence_collector.export_all_evidence()
            if evidence_path and self.artifact_manager is not None:
                self.artifact_manager.register_file_artifact(evidence_path, kind='evidence', title=os.path.basename(evidence_path), metadata={'target': target})
        except Exception:
            logging.exception("scanner.py: exception")
            pass

        return generated

    def get_summary(self) -> Dict[str, Any]:
        severity_counts = self.finding_manager.count_by_severity()

        total = sum(severity_counts.values())
        risk_score = min(100, (
            severity_counts["critical"] * 25 +
            severity_counts["high"] * 15 +
            severity_counts["medium"] * 8 +
            severity_counts["low"] * 3 +
            severity_counts["info"] * 1
        ))

        exploited = self.finding_manager.get_exploited()

        return {
            "target": self.config.target_url,
            "total_findings": total,
            "severity_counts": severity_counts,
            "risk_score": risk_score,
            "scan_data": self.scan_data,
            "findings": self.findings,
            "structured_findings": [f.to_dict() for f in self.finding_manager.get_all()],
            "exploited_count": len(exploited),
            "duration": self.scan_data.get("scan_info", {}).get("duration", ""),
            "modules_run": self.scan_data.get("scan_info", {}).get("modules_run", []),
            "waf": self.scan_data.get("waf", {}),
            "oob_stats": self.oob_server.get_stats() if self.oob_server.is_running else {},
            "evidence_stats": self.evidence_collector.get_stats(),
            "pipeline_status": self.pipeline.get_status(),
        }

    def reset(self):
        self.config.reset()
        self.scan_data = self.config.scan_data
        self.findings = self.config.findings
        self.finding_manager = FindingManager()
        self.pipeline.clear()
        self._current_scan_id = None
        self._waf_info = None

    def close(self):
        self._stop_oob_server()
        if self._exploit_orchestrator:
            self._exploit_orchestrator.close()
        self.db.close()


class _InfoGatheringModule:
    def __init__(self, scanner: Scanner):
        self.scanner = scanner

    def run(self, target: str, session=None) -> Dict[str, Any]:
        from core.utils import print_info, print_good, print_warning
        from urllib.parse import urlparse

        print_info(f"Information gathering on {target}...")
        parsed = urlparse(target)
        domain = parsed.hostname or target
        self.scanner.scan_data["target"]["domain"] = domain
        self.scanner.scan_data["target"]["url"] = target

        try:
            import socket
            ip = socket.gethostbyname(domain)
            self.scanner.scan_data["target"]["ip"] = ip
            print_good(f"IP: {ip}")
        except socket.gaierror:
            print_warning(f"Could not resolve {domain}")

        whatweb = self.scanner.tool_manager.get("whatweb")
        if whatweb and whatweb.is_installed():
            result = whatweb.run_scan(target, session=session)
            if result and "technologies" in result:
                techs = result["technologies"]
                self.scanner.scan_data["target"]["technologies"] = techs
                print_good(f"Technologies: {', '.join(t['name'] if isinstance(t, dict) else str(t) for t in techs[:10])}")

        try:
            import requests
            resp = requests.get(target, timeout=self.scanner.config.timeout, verify=self.scanner.config.verify_tls, allow_redirects=True)
            self.scanner.scan_data["target"]["status"] = f"{resp.status_code} {resp.reason}"
            self.scanner.scan_data["target"]["headers"] = dict(resp.headers)
            server = resp.headers.get("Server", "")
            self.scanner.scan_data["target"]["server"] = server
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "html.parser")
            title_tag = soup.find("title")
            if title_tag:
                self.scanner.scan_data["target"]["title"] = title_tag.get_text(strip=True)[:200]
        except Exception as e:
            self.scanner.scan_data.setdefault("scan_info", {}).setdefault("errors", []).append(
                f"info_gathering: {str(e)}"
            )

        return self.scanner.scan_data["target"]


class _NmapModule:
    def __init__(self, scanner: Scanner):
        self.scanner = scanner

    def run(self, target: str, session=None) -> Dict[str, Any]:
        from urllib.parse import urlparse
        nmap = self.scanner.tool_manager.get("nmap")
        if not nmap or not nmap.is_installed():
            from core.utils import print_warning
            print_warning("Nmap not available, skipping port scan.")
            return {}

        host = urlparse(target).hostname or target
        result = nmap.run_scan(host, session=session)
        if result and "ports" in result:
            self.scanner.scan_data["nmap"] = result
            for p in result.get("ports", []):
                if p.get("state") == "open":
                    sev = "info"
                    service = p.get("service", "")
                    if service in ("http", "https"):
                        sev = "low"
                    finding = Finding(
                        type=FindingType.PORT_OPEN,
                        severity=sev,
                        title=f"Open port {p['port']}/{p['protocol']}",
                        detail=f"{service} {p.get('product', '')} {p.get('version', '')}".strip(),
                        url=target,
                        module="nmap",
                    )
                    self.scanner.finding_manager.add(finding)
                    self.scanner.findings.append(finding.to_dict())
        return result


class _NucleiModule:
    def __init__(self, scanner: Scanner):
        self.scanner = scanner

    def run(self, target: str, session=None) -> Dict[str, Any]:
        nuclei = self.scanner.tool_manager.get("nuclei")
        if not nuclei or not nuclei.is_installed():
            from core.utils import print_warning
            print_warning("Nuclei not available, skipping vulnerability scan.")
            return {}

        result = nuclei.run_scan(target, session=session)
        if result and "findings" in result:
            self.scanner.scan_data["nuclei_findings"] = result["findings"]
            for f in result["findings"]:
                finding = Finding(
                    type=FindingType.INFO_DISCLOSURE,
                    severity=f.get("severity", "info"),
                    title=f.get("name", f.get("template_id", "Unknown")),
                    detail=f.get("description", ""),
                    url=f.get("matched_at", target),
                    module="nuclei",
                    tool="nuclei",
                )
                self.scanner.finding_manager.add(finding)
                self.scanner.findings.append(finding.to_dict())
        return result


class _VHostModule:
    def __init__(self, scanner: Scanner):
        self.scanner = scanner

    def run(self, target: str, session=None) -> Dict[str, Any]:
        from core.utils import print_info, print_warning
        from lib.wordlists import Wordlists

        ffuf = self.scanner.tool_manager.get("ffuf")
        if not ffuf or not ffuf.is_installed():
            print_warning("FFUF not available, skipping vhost bruteforce.")
            return {}

        wl = Wordlists()
        wordlist = wl.find_wordlist("seclists/Discovery/DNS/subdomains-top1k-5000.txt")
        if not wordlist:
            wordlist = wl.find_wordlist("subdomains-top1k-5000.txt")
        if not wordlist:
            wordlist = wl.find_wordlist("subdomains-top1million-5000.txt")
        if not wordlist:
            print_warning("No suitable wordlist found for vhost bruteforce.")
            return {}

        domain = target.replace("http://", "").replace("https://", "").split("/")[0]
        result = ffuf.run_fuzz(target, wordlist, mode="vhost", session=session, base_domain=domain)
        if result and "hits" in result:
            self.scanner.scan_data["vhosts"] = result["hits"]
            for h in result["hits"]:
                finding = Finding(
                    type=FindingType.SUBDOMAIN_FOUND,
                    severity="info",
                    title=f"Virtual host found: {h.get('input', {}).get('FUZZ', '?')}",
                    detail=f"Status: {h.get('status')}, Length: {h.get('length')}",
                    url=target,
                    module="vhost",
                )
                self.scanner.finding_manager.add(finding)
                self.scanner.findings.append(finding.to_dict())
        return result


class _DirectoryModule:
    def __init__(self, scanner: Scanner):
        self.scanner = scanner

    def run(self, target: str, session=None) -> Dict[str, Any]:
        from core.utils import print_warning
        from lib.wordlists import Wordlists

        ffuf = self.scanner.tool_manager.get("ffuf")
        if not ffuf or not ffuf.is_installed():
            print_warning("FFUF not available, skipping directory bruteforce.")
            return {}

        wl = Wordlists()
        wordlist = wl.find_wordlist("seclists/Discovery/Web-Content/raft-medium-directories.txt")
        if not wordlist:
            wordlist = wl.find_wordlist("raft-medium-directories.txt")
        if not wordlist:
            print_warning("No suitable wordlist found for directory bruteforce.")
            return {}

        result = ffuf.run_fuzz(target, wordlist, mode="dir", session=session, threads=self.scanner.config.threads)
        if result and "hits" in result:
            self.scanner.scan_data.setdefault("directory_bruteforce", {})["results"] = result["hits"]
            for h in result["hits"]:
                status = h.get("status", 0)
                sev = "info"
                if status in (200, 301, 302):
                    sev = "low"
                finding = Finding(
                    type=FindingType.INFO_DISCLOSURE,
                    severity=sev,
                    title=f"Directory found: {h.get('url', '?')}",
                    detail=f"Status: {status}, Length: {h.get('length', 0)}",
                    url=target,
                    module="directory",
                )
                self.scanner.finding_manager.add(finding)
                self.scanner.findings.append(finding.to_dict())
        return result


class _SubdomainModule:
    def __init__(self, scanner: Scanner):
        self.scanner = scanner

    def run(self, target: str, session=None) -> Dict[str, Any]:
        from core.utils import print_info, print_good, print_warning
        from urllib.parse import urlparse

        print_info(f"Enumerating subdomains for {target}...")
        domain = urlparse(target).hostname or target

        subfinder = self.scanner.tool_manager.get("subfinder")
        if subfinder and subfinder.is_installed():
            result = subfinder.run_enumeration(domain)
            if result and "subdomains" in result:
                subs = result["subdomains"]
                self.scanner.scan_data.setdefault("subdomain_enum", {})["subdomains"] = subs
                for sub in subs:
                    finding = Finding(
                        type=FindingType.SUBDOMAIN_FOUND,
                        severity="info",
                        title=f"Subdomain found: {sub}",
                        detail=f"Discovered subdomain for {domain}",
                        url=f"http://{sub}",
                        module="subdomain",
                    )
                    self.scanner.finding_manager.add(finding)
                    self.scanner.findings.append(finding.to_dict())
                print_good(f"Subdomains: {len(subs)} found")
                return result

        print_warning("Subfinder not available, skipping subdomain enumeration.")
        return {}


class _SpiderModule:
    def __init__(self, scanner: Scanner):
        self.scanner = scanner

    def run(self, target: str, session=None) -> Dict[str, Any]:
        from core.utils import print_warning

        katana = self.scanner.tool_manager.get("katana")
        if not katana or not katana.is_installed():
            print_warning("Katana not available, skipping spider.")
            return {}

        result = katana.run_crawl(target, depth=3, session=session)
        if result and "urls" in result:
            self.scanner.scan_data.setdefault("crawl", {})["urls"] = result["urls"]
            finding = Finding(
                type=FindingType.INFO_DISCLOSURE,
                severity="info",
                title=f"Spider completed: {len(result['urls'])} URLs discovered",
                detail=f"Crawled target and found {len(result['urls'])} unique URLs",
                url=target,
                module="spider",
            )
            self.scanner.finding_manager.add(finding)
            self.scanner.findings.append(finding.to_dict())
        return result


class _SourceCodeModule:
    def __init__(self, scanner: Scanner):
        self.scanner = scanner

    def run(self, target: str, session=None) -> Dict[str, Any]:
        from core.utils import print_info, print_good
        import re

        print_info(f"Analyzing source code of {target}...")
        findings = []
        scripts_found = []
        try:
            import requests
            resp = requests.get(
                target,
                timeout=self.scanner.config.timeout,
                verify=self.scanner.config.verify_tls,
                allow_redirects=True,
            )
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "html.parser")

            scripts = soup.find_all("script", src=True)
            for script in scripts[:10]:
                src = script["src"]
                if not src.startswith(("http://", "https://", "//")):
                    from urllib.parse import urljoin
                    src = urljoin(target, src)
                scripts_found.append(src)

            comments = soup.find_all(string=lambda text: isinstance(text, type(soup.new_string(""))) and text.parent and text.parent.name in ("html", "body", "script", "style", "div"))
            sensitive_patterns = [
                (r"(?i)password\s*[=:]\s*[\"'][^\"']+[\"']", "hardcoded password"),
                (r"(?i)api[_\-]?key\s*[=:]\s*[\"'][^\"']+[\"']", "API key"),
                (r"(?i)secret\s*[=:]\s*[\"'][^\"']+[\"']", "secret value"),
                (r"(?i)token\s*[=:]\s*[\"'][^\"']+[\"']", "token"),
            ]

            for comment in comments[:20]:
                text = str(comment)
                for pattern, title in sensitive_patterns:
                    if re.search(pattern, text):
                        finding = Finding(
                            type=FindingType.SECRETS_EXPOSED,
                            severity="medium",
                            title=f"Sensitive data in source: {title}",
                            detail=text[:200],
                            url=target,
                            module="source_code",
                        )
                        self.scanner.finding_manager.add(finding)
                        findings.append(finding.to_dict())
                        break

            meta_tags = soup.find_all("meta")
            for meta in meta_tags:
                name = meta.get("name", "").lower()
                content = meta.get("content", "")
                if name in ("author", "generator") and content:
                    self.scanner.scan_data.setdefault("source_code_analysis", {}).setdefault("meta", []).append(
                        {"name": name, "content": content}
                    )

        except Exception as e:
            finding = Finding(
                type=FindingType.INFO_DISCLOSURE,
                severity="info",
                title="Source code analysis error",
                detail=str(e),
                url=target,
                module="source_code",
            )
            findings.append(finding.to_dict())

        self.scanner.scan_data.setdefault("source_code_analysis", {})["findings"] = findings
        self.scanner.findings.extend(findings)
        print_good(f"Source code analysis: {len(findings)} findings")
        return {"findings": findings}


class _InjectionModule:
    def __init__(self, scanner: Scanner):
        self.scanner = scanner

    def run(self, target: str, session=None) -> Dict[str, Any]:
        from core.utils import print_info, print_good
        from lib.payloads import Payloads

        print_info(f"Running injection tests on {target}...")
        results = {"sqli": [], "xss": [], "rce": [], "lfi": [], "open_redirect": []}

        try:
            import requests
            from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

            resp = requests.get(
                target,
                timeout=self.scanner.config.timeout,
                verify=self.scanner.config.verify_tls,
                allow_redirects=True,
            )

            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "html.parser")
            forms = soup.find_all("form")

            payloads = Payloads()

            for form in forms[:5]:
                action = form.get("action", "")
                method = form.get("method", "GET").upper()
                if not action:
                    action = target
                else:
                    action = urljoin(target, action)

                inputs = form.find_all(["input", "textarea"])
                params = {}
                for inp in inputs:
                    name = inp.get("name")
                    if name:
                        params[name] = "test"

                if params:
                    for payload in payloads.SQL_PAYLOADS[:3]:
                        test_params = {k: payload for k in params}
                        try:
                            if method == "POST":
                                r = requests.post(action, data=test_params, timeout=5, verify=self.scanner.config.verify_tls, allow_redirects=False)
                            else:
                                r = requests.get(action, params=test_params, timeout=5, verify=self.scanner.config.verify_tls, allow_redirects=False)

                            sql_errors = [
                                "sql syntax", "mysql_fetch", "sqlite3", "postgresql",
                                "ORA-", "SQL syntax", "unclosed quotation",
                            ]
                            body = r.text.lower()
                            for err in sql_errors:
                                if err.lower() in body:
                                    finding = Finding(
                                        type=FindingType.SQLI_ERROR,
                                        severity="critical",
                                        title=f"SQL Injection in form: {action}",
                                        detail=f"Parameter triggered SQL error with payload: {payload}",
                                        url=action,
                                        module="injection",
                                        confirmed=True,
                                    )
                                    self.scanner.finding_manager.add(finding)
                                    evidence = self.scanner.evidence_collector.capture_from_response(r, method, str(test_params))
                                    self.scanner.evidence_collector.add_finding_evidence(
                                        finding.id, "http_pair", evidence.to_dict()
                                    )
                                    results["sqli"].append(finding.to_dict())
                                    self.scanner.findings.append(finding.to_dict())
                                    break
                        except Exception:
                            logging.exception("scanner.py: exception")
                            continue

                    for payload in payloads.XSS_PAYLOADS[:3]:
                        test_params = {k: payload for k in params}
                        try:
                            if method == "POST":
                                r = requests.post(action, data=test_params, timeout=5, verify=self.scanner.config.verify_tls, allow_redirects=False)
                            else:
                                r = requests.get(action, params=test_params, timeout=5, verify=self.scanner.config.verify_tls, allow_redirects=False)

                            if payload in r.text:
                                finding = Finding(
                                    type=FindingType.XSS_REFLECTED,
                                    severity="high",
                                    title=f"Reflected XSS in form: {action}",
                                    detail=f"Payload reflected in response: {payload[:60]}",
                                    url=action,
                                    module="injection",
                                    confirmed=True,
                                )
                                self.scanner.finding_manager.add(finding)
                                evidence = self.scanner.evidence_collector.capture_from_response(r, method, str(test_params))
                                self.scanner.evidence_collector.add_finding_evidence(
                                    finding.id, "http_pair", evidence.to_dict()
                                )
                                results["xss"].append(finding.to_dict())
                                self.scanner.findings.append(finding.to_dict())
                                break
                        except Exception:
                            logging.exception("scanner.py: exception")
                            continue

            parsed = urlparse(target)
            params = parse_qs(parsed.query)
            if params:
                for param_name in params:
                    for payload in payloads.SQL_PAYLOADS[:2]:
                        test_params = {k: v[0] if v else "" for k, v in params.items()}
                        test_params[param_name] = payload
                        new_query = urlencode(test_params)
                        test_url = urlunparse(parsed._replace(query=new_query))
                        try:
                            r = requests.get(test_url, timeout=5, verify=self.scanner.config.verify_tls, allow_redirects=False)
                            sql_errors = ["sql syntax", "mysql_fetch", "sqlite3", "ORA-"]
                            body = r.text.lower()
                            for err in sql_errors:
                                if err.lower() in body:
                                    finding = Finding(
                                        type=FindingType.SQLI_ERROR,
                                        severity="critical",
                                        title=f"SQL Injection in parameter: {param_name}",
                                        detail=f"Parameter '{param_name}' triggered SQL error",
                                        url=test_url,
                                        module="injection",
                                        confirmed=True,
                                    )
                                    self.scanner.finding_manager.add(finding)
                                    evidence = self.scanner.evidence_collector.capture_from_response(r, "GET")
                                    self.scanner.evidence_collector.add_finding_evidence(
                                        finding.id, "http_pair", evidence.to_dict()
                                    )
                                    results["sqli"].append(finding.to_dict())
                                    self.scanner.findings.append(finding.to_dict())
                                    break
                        except Exception:
                            logging.exception("scanner.py: exception")
                            continue

        except Exception as e:
            results["error"] = str(e)

        total = sum(len(v) for v in results.values() if isinstance(v, list))
        print_good(f"Injection tests: {total} findings")
        return results


class _AdvancedSecurityModule:
    def __init__(self, scanner: Scanner):
        self.scanner = scanner

    def run(self, target: str, session=None) -> Dict[str, Any]:
        from core.utils import print_info, print_good

        print_info(f"Running advanced security tests on {target}...")
        results = {"ssti": [], "xxe": [], "crlf": [], "ssrf": []}

        try:
            import requests
            from urllib.parse import urljoin

            payloads = [
                ("{{1337*1337}}", "1787569", "SSTI"),
                ("${1337*1337}", "1787569", "SSTI"),
                ("<%= 1337*1337 %>", "1787569", "SSTI"),
            ]

            for payload, expected, test_type in payloads:
                try:
                    resp = requests.get(
                        target,
                        params={"q": payload, "input": payload, "name": payload, "search": payload},
                        timeout=5,
                        verify=self.scanner.config.verify_tls,
                        allow_redirects=False,
                    )
                    if expected in resp.text:
                        finding = Finding(
                            type=FindingType.SSTI_RCE,
                            severity="critical",
                            title=f"Potential {test_type} vulnerability",
                            detail=f"Payload {payload} resulted in evaluation: {expected}",
                            url=target,
                            module="advanced_security",
                            confirmed=True,
                        )
                        self.scanner.finding_manager.add(finding)
                        evidence = self.scanner.evidence_collector.capture_from_response(resp, "GET")
                        self.scanner.evidence_collector.add_finding_evidence(
                            finding.id, "http_pair", evidence.to_dict()
                        )
                        results["ssti"].append(finding.to_dict())
                        self.scanner.findings.append(finding.to_dict())
                except Exception:
                    logging.exception("scanner.py: exception")
                    continue

            crlf_payloads = ["%0d%0aSet-Cookie:crlf_test=injected", "%0aX-CRLF-Test:injected"]
            for payload in crlf_payloads:
                try:
                    resp = requests.get(
                        urljoin(target, f"/?header={payload}"),
                        timeout=5,
                        verify=self.scanner.config.verify_tls,
                        allow_redirects=False,
                    )
                    if "crlf_test" in resp.headers.get("Set-Cookie", "") or "X-CRLF-Test" in resp.headers:
                        finding = Finding(
                            type=FindingType.CRLF_HEADER_INJECTION,
                            severity="high",
                            title="CRLF Injection vulnerability",
                            detail="CRLF characters were injected into HTTP headers",
                            url=target,
                            module="advanced_security",
                            confirmed=True,
                        )
                        self.scanner.finding_manager.add(finding)
                        evidence = self.scanner.evidence_collector.capture_from_response(resp, "GET")
                        self.scanner.evidence_collector.add_finding_evidence(
                            finding.id, "http_pair", evidence.to_dict()
                        )
                        results["crlf"].append(finding.to_dict())
                        self.scanner.findings.append(finding.to_dict())
                        break
                except Exception:
                    logging.exception("scanner.py: exception")
                    continue

        except Exception as e:
            results["error"] = str(e)

        total = sum(len(v) for v in results.values() if isinstance(v, list))
        print_good(f"Advanced security tests: {total} findings")
        return results


class _APIModule:
    def __init__(self, scanner: Scanner):
        self.scanner = scanner

    def run(self, target: str, session=None) -> Dict[str, Any]:
        from core.utils import print_info, print_good
        from lib.wordlists import Wordlists

        print_info(f"Testing API endpoints on {target}...")
        wl = Wordlists()
        endpoints = []
        found = []

        try:
            import requests
            from urllib.parse import urljoin

            for ep in wl.API_ENDPOINTS[:50]:
                url = urljoin(target.rstrip("/") + "/", ep.lstrip("/"))
                try:
                    resp = requests.get(
                        url,
                        timeout=self.scanner.config.timeout,
                        verify=self.scanner.config.verify_tls,
                        allow_redirects=False,
                    )
                    endpoints.append({
                        "url": url,
                        "method": "GET",
                        "status": resp.status_code,
                    })
                    if resp.status_code not in (404, 403, 405, 500, 502, 503):
                        found.append({"url": url, "status": resp.status_code})
                        finding = Finding(
                            type=FindingType.API_ENDPOINT,
                            severity="low" if resp.status_code == 200 else "info",
                            title=f"API endpoint accessible: {ep}",
                            detail=f"Status: {resp.status_code}, Content-Type: {resp.headers.get('Content-Type', 'N/A')}",
                            url=url,
                            module="api",
                        )
                        self.scanner.finding_manager.add(finding)
                        self.scanner.findings.append(finding.to_dict())
                except Exception:
                    logging.exception("scanner.py: exception")
                    continue

        except Exception as e:
            self.scanner.scan_data.setdefault("scan_info", {}).setdefault("errors", []).append(
                f"api: {str(e)}"
            )

        self.scanner.scan_data.setdefault("api", {})["endpoints"] = endpoints
        print_good(f"API tests: {len(found)} accessible endpoints found")
        return {"endpoints": endpoints, "accessible": found}


class _UserEnumModule:
    def __init__(self, scanner: Scanner):
        self.scanner = scanner

    def run(self, target: str, session=None) -> Dict[str, Any]:
        from core.utils import print_info, print_good

        print_info(f"Testing user enumeration on {target}...")
        results = {"users": [], "login_pages": []}

        try:
            import requests

            login_paths = ["/login", "/signin", "/wp-login.php", "/admin/login", "/auth/login"]
            for path in login_paths:
                url = target.rstrip("/") + path
                try:
                    resp = requests.get(url, timeout=5, verify=self.scanner.config.verify_tls, allow_redirects=True)
                    if resp.status_code == 200:
                        results["login_pages"].append(url)
                        finding = Finding(
                            type=FindingType.INFO_DISCLOSURE,
                            severity="info",
                            title=f"Login page found: {path}",
                            detail=f"Status: {resp.status_code}",
                            url=url,
                            module="user_enum",
                        )
                        self.scanner.finding_manager.add(finding)
                        self.scanner.findings.append(finding.to_dict())
                        break
                except Exception:
                    logging.exception("scanner.py: exception")
                    continue

        except Exception as e:
            self.scanner.scan_data.setdefault("scan_info", {}).setdefault("errors", []).append(
                f"user_enum: {str(e)}"
            )

        print_good(f"User enumeration: {len(results['login_pages'])} login pages found")
        return results


class _WordPressModule:
    def __init__(self, scanner: Scanner):
        self.scanner = scanner

    def run(self, target: str, session=None) -> Dict[str, Any]:
        from core.utils import print_info, print_good, print_warning

        wpscan = self.scanner.tool_manager.get("wpscan")
        if not wpscan or not wpscan.is_installed():
            print_warning("WPScan not available, skipping WordPress tests.")
            return {}

        result = wpscan.run_scan(target, session=session)
        if result:
            self.scanner.scan_data["wordpress"] = result
            for user in result.get("users", []):
                finding = Finding(
                    type=FindingType.INFO_DISCLOSURE,
                    severity="info",
                    title=f"WordPress user found: {user.get('username', '?')}",
                    detail=f"User ID: {user.get('id', '?')}",
                    url=target,
                    module="wordpress",
                )
                self.scanner.finding_manager.add(finding)
                self.scanner.findings.append(finding.to_dict())
            for plugin in result.get("plugins", []):
                vulns = plugin.get("vulnerabilities", [])
                if vulns:
                    finding = Finding(
                        type=FindingType.DEPENDENCY_VULN,
                        severity="high",
                        title=f"Vulnerable WordPress plugin: {plugin.get('name', '?')}",
                        detail=f"{len(vulns)} known vulnerabilities",
                        url=target,
                        module="wordpress",
                        confirmed=True,
                    )
                    self.scanner.finding_manager.add(finding)
                    self.scanner.findings.append(finding.to_dict())
        return result


class _ActiveDirectoryModule:
    def __init__(self, scanner: Scanner):
        self.scanner = scanner

    def run(self, target: str, session=None) -> Dict[str, Any]:
        from core.utils import print_info, print_warning

        print_info(f"Active Directory tests on {target}...")
        print_warning("AD tests require domain controller information.")
        print_warning("Use the Authentication Setup (option 15) to configure AD parameters.")

        results = {
            "domain": "",
            "dc": "",
            "users_found": [],
            "kerberos_results": [],
        }

        kerbrute = self.scanner.tool_manager.get("kerbrute")
        if kerbrute and kerbrute.is_installed():
            print_info("Kerbrute is available for Kerberos attacks.")

        self.scanner.scan_data["active_directory"] = results
        return results


class _NoSQLModule:
    def __init__(self, scanner: Scanner):
        self.scanner = scanner

    def run(self, target: str, session=None) -> Dict[str, Any]:
        from core.utils import print_info, print_good

        print_info(f"Running NoSQL injection tests on {target}...")
        results = {"nosql": []}

        nosql_payloads = [
            '{"$gt": ""}',
            '{"$ne": ""}',
            '{"$regex": ".*"}',
            '{"$where": "1==1"}',
            '$gt',
            '$ne',
            'true, $where: "1==1"',
        ]

        try:
            import requests
            from urllib.parse import urljoin

            test_params = ["?id=", "?user=", "?search=", "?q=", "?name=", "?filter="]
            for param in test_params:
                for payload in nosql_payloads:
                    try:
                        test_url = f"{target.rstrip('/')}{param}{payload}"
                        resp = requests.get(test_url, timeout=5, verify=self.scanner.config.verify_tls, allow_redirects=False)
                        if resp.status_code == 200 and len(resp.content) > 100:
                            body_lower = resp.text.lower()
                            if any(x in body_lower for x in ["password", "email", "user", "admin", "token"]):
                                finding = Finding(
                                    type=FindingType.NOSQL_INJECTION,
                                    severity="critical",
                                    title=f"NoSQL Injection in parameter: {param.strip('?=&')}",
                                    detail=f"Payload {payload} returned sensitive data",
                                    url=test_url,
                                    module="nosql",
                                    confirmed=True,
                                )
                                self.scanner.finding_manager.add(finding)
                                evidence = self.scanner.evidence_collector.capture_from_response(resp, "GET")
                                self.scanner.evidence_collector.add_finding_evidence(
                                    finding.id, "http_pair", evidence.to_dict()
                                )
                                results["nosql"].append(finding.to_dict())
                                self.scanner.findings.append(finding.to_dict())
                                break
                    except Exception:
                        logging.exception("scanner.py: exception")
                        continue

        except Exception as e:
            results["error"] = str(e)

        total = len(results["nosql"])
        print_good(f"NoSQL injection tests: {total} findings")
        return results


class _LDAPModule:
    def __init__(self, scanner: Scanner):
        self.scanner = scanner

    def run(self, target: str, session=None) -> Dict[str, Any]:
        from core.utils import print_info, print_good

        print_info(f"Running LDAP injection tests on {target}...")
        results = {"ldap": []}

        ldap_payloads = [
            "*)(objectClass=*",
            "*()|&'",
            "admin)(&)",
            "*)(cn=*)",
            "*)(&",
            "(&(objectClass=*)",
            "admin))%00",
        ]

        try:
            import requests
            from urllib.parse import urljoin

            test_params = ["?user=", "?username=", "?uid=", "?login=", "?search="]
            for param in test_params:
                for payload in ldap_payloads:
                    try:
                        test_url = f"{target.rstrip('/')}{param}{payload}"
                        resp = requests.get(test_url, timeout=5, verify=self.scanner.config.verify_tls, allow_redirects=False)
                        body_lower = resp.text.lower()
                        if resp.status_code == 200 and (
                            "ldap" in body_lower or "bind" in body_lower or "objectclass" in body_lower
                        ) and "404" not in body_lower[:200]:
                            finding = Finding(
                                type=FindingType.LDAP_INJECTION,
                                severity="high",
                                title=f"LDAP Injection in parameter: {param.strip('?=&')}",
                                detail=f"Payload triggered LDAP-related response",
                                url=test_url,
                                module="ldap",
                                confirmed=True,
                            )
                            self.scanner.finding_manager.add(finding)
                            evidence = self.scanner.evidence_collector.capture_from_response(resp, "GET")
                            self.scanner.evidence_collector.add_finding_evidence(
                                finding.id, "http_pair", evidence.to_dict()
                            )
                            results["ldap"].append(finding.to_dict())
                            self.scanner.findings.append(finding.to_dict())
                            break
                    except Exception:
                        logging.exception("scanner.py: exception")
                        continue

        except Exception as e:
            results["error"] = str(e)

        total = len(results["ldap"])
        print_good(f"LDAP injection tests: {total} findings")
        return results


class _DeserializationModule:
    def __init__(self, scanner: Scanner):
        self.scanner = scanner

    def run(self, target: str, session=None) -> Dict[str, Any]:
        from core.utils import print_info, print_good

        print_info(f"Running deserialization tests on {target}...")
        results = {"deserialization": []}

        try:
            import requests
            import base64

            java_payloads = [
                base64.b64encode(b"\xac\xed\x00\x05").decode(),
                base64.b64encode(b"\xac\xed\x00\x05r\x00").decode(),
            ]

            php_payloads = [
                'O:8:"stdClass":0:{}',
                'a:1:{s:4:"test";s:4:"test";}',
            ]

            python_payloads = [
                base64.b64encode(b"cos\nsystem\n(S'id'\ntR.").decode(),
                base64.b64encode(b"\x80\x03}q\x00.").decode(),
            ]

            for payload in java_payloads + php_payloads + python_payloads:
                try:
                    resp = requests.get(
                        target,
                        params={"data": payload, "object": payload, "input": payload},
                        timeout=5,
                        verify=self.scanner.config.verify_tls,
                        allow_redirects=False,
                    )
                    body_lower = resp.text.lower()
                    if any(x in body_lower for x in [
                        "deserializ", "objectinputstream", "readobject",
                        "serialize", "unserialize", "__wakeup",
                        "pickle", "marshal",
                    ]):
                        finding = Finding(
                            type=FindingType.DESER_JAVA,
                            severity="critical",
                            title="Potential insecure deserialization",
                            detail=f"Payload triggered serialization-related response",
                            url=target,
                            module="deserialization",
                            confirmed=True,
                        )
                        self.scanner.finding_manager.add(finding)
                        evidence = self.scanner.evidence_collector.capture_from_response(resp, "GET")
                        self.scanner.evidence_collector.add_finding_evidence(
                            finding.id, "http_pair", evidence.to_dict()
                        )
                        results["deserialization"].append(finding.to_dict())
                        self.scanner.findings.append(finding.to_dict())
                        break
                except Exception:
                    logging.exception("scanner.py: exception")
                    continue

        except Exception as e:
            results["error"] = str(e)

        total = len(results["deserialization"])
        print_good(f"Deserialization tests: {total} findings")
        return results


class _OAuthModule:
    def __init__(self, scanner: Scanner):
        self.scanner = scanner

    def run(self, target: str, session=None) -> Dict[str, Any]:
        from core.utils import print_info, print_good

        print_info(f"Running OAuth testing on {target}...")
        results = {"oauth": []}

        try:
            import requests
            from urllib.parse import urljoin, urlparse, parse_qs

            oauth_paths = [
                "/oauth/authorize", "/oauth2/authorize", "/auth/authorize",
                "/oauth/token", "/oauth2/token", "/auth/token",
                "/.well-known/openid-configuration", "/openid-configuration",
            ]

            for path in oauth_paths:
                try:
                    url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
                    resp = requests.get(url, timeout=5, verify=self.scanner.config.verify_tls, allow_redirects=False)
                    if resp.status_code == 200:
                        body_lower = resp.text.lower()
                        if any(x in body_lower for x in ["access_token", "code", "redirect_uri", "client_id"]):
                            finding = Finding(
                                type=FindingType.OAUTH_REDIRECT,
                                severity="medium",
                                title=f"OAuth endpoint found: {path}",
                                detail=f"OAuth endpoint accessible at {url}",
                                url=url,
                                module="oauth",
                            )
                            self.scanner.finding_manager.add(finding)
                            results["oauth"].append(finding.to_dict())
                            self.scanner.findings.append(finding.to_dict())
                            break
                except Exception:
                    logging.exception("scanner.py: exception")
                    continue

            redirect_params = ["?redirect_uri=http://evil.com", "?callback=http://evil.com"]
            for rparam in redirect_params:
                try:
                    resp = requests.get(
                        f"{target.rstrip('/')}/oauth/authorize{rparam}",
                        timeout=5,
                        verify=self.scanner.config.verify_tls,
                        allow_redirects=False,
                    )
                    if resp.status_code in (301, 302, 303):
                        location = resp.headers.get("Location", "")
                        if "evil.com" in location:
                            finding = Finding(
                                type=FindingType.OAUTH_REDIRECT,
                                severity="high",
                                title="OAuth redirect URI manipulation",
                                detail=f"OAuth redirect can be manipulated to external domain",
                                url=target,
                                module="oauth",
                                confirmed=True,
                            )
                            self.scanner.finding_manager.add(finding)
                            results["oauth"].append(finding.to_dict())
                            self.scanner.findings.append(finding.to_dict())
                            break
                except Exception:
                    logging.exception("scanner.py: exception")
                    continue

        except Exception as e:
            results["error"] = str(e)

        total = len(results["oauth"])
        print_good(f"OAuth tests: {total} findings")
        return results


class _GraphQLModule:
    def __init__(self, scanner: Scanner):
        self.scanner = scanner

    def run(self, target: str, session=None) -> Dict[str, Any]:
        from core.utils import print_info, print_good

        print_info(f"Running GraphQL tests on {target}...")
        results = {"graphql": []}

        graphql_paths = ["/graphql", "/gql", "/api/graphql", "/query", "/graphiql", "/playground"]

        try:
            import requests

            for path in graphql_paths:
                try:
                    url = target.rstrip("/") + path
                    introspection_query = '{"query":"{ __schema { types { name } } }"}'
                    resp = requests.post(
                        url,
                        data=introspection_query,
                        headers={"Content-Type": "application/json"},
                        timeout=5,
                        verify=self.scanner.config.verify_tls,
                    )
                    if resp.status_code == 200:
                        body_lower = resp.text.lower()
                        if "__schema" in body_lower or "types" in body_lower:
                            finding = Finding(
                                type=FindingType.GQL_INTROSPECTION,
                                severity="medium",
                                title=f"GraphQL introspection enabled: {path}",
                                detail="GraphQL schema is accessible via introspection query",
                                url=url,
                                module="graphql",
                                confirmed=True,
                            )
                            self.scanner.finding_manager.add(finding)
                            evidence = self.scanner.evidence_collector.capture_from_response(
                                resp, "POST", introspection_query
                            )
                            self.scanner.evidence_collector.add_finding_evidence(
                                finding.id, "http_pair", evidence.to_dict()
                            )
                            results["graphql"].append(finding.to_dict())
                            self.scanner.findings.append(finding.to_dict())
                            break
                except Exception:
                    logging.exception("scanner.py: exception")
                    continue

            batch_payloads = [
                '[{"query":"{ __typename }"},{"query":"{ __typename }"}]',
                '[{"query":"query{__typename}"}]',
            ]
            for payload in batch_payloads:
                try:
                    resp = requests.post(
                        f"{target.rstrip('/')}/graphql",
                        data=payload,
                        headers={"Content-Type": "application/json"},
                        timeout=5,
                        verify=self.scanner.config.verify_tls,
                    )
                    if resp.status_code == 200 and "typename" in resp.text.lower():
                        finding = Finding(
                            type=FindingType.GQL_BATCHING,
                            severity="low",
                            title="GraphQL query batching supported",
                            detail="GraphQL endpoint accepts batched queries",
                            url=target,
                            module="graphql",
                        )
                        self.scanner.finding_manager.add(finding)
                        results["graphql"].append(finding.to_dict())
                        self.scanner.findings.append(finding.to_dict())
                        break
                except Exception:
                    logging.exception("scanner.py: exception")
                    continue

        except Exception as e:
            results["error"] = str(e)

        total = len(results["graphql"])
        print_good(f"GraphQL tests: {total} findings")
        return results


class _WebSocketModule:
    def __init__(self, scanner: Scanner):
        self.scanner = scanner

    def run(self, target: str, session=None) -> Dict[str, Any]:
        from core.utils import print_info, print_good

        print_info(f"Running WebSocket tests on {target}...")
        results = {"websocket": []}

        try:
            import requests
            from urllib.parse import urlparse

            parsed = urlparse(target)
            ws_scheme = "wss" if parsed.scheme == "https" else "ws"
            ws_urls = [
                f"{ws_scheme}://{parsed.netloc}/ws",
                f"{ws_scheme}://{parsed.netloc}/websocket",
                f"{ws_scheme}://{parsed.netloc}/socket",
                f"{ws_scheme}://{parsed.netloc}/api/ws",
                f"{ws_scheme}://{parsed.netloc}/socket.io/?EIO=3&transport=websocket",
            ]

            ws_paths = ["/ws", "/websocket", "/socket", "/api/ws"]
            for path in ws_paths:
                try:
                    resp = requests.get(
                        target.rstrip("/") + path,
                        headers={"Upgrade": "websocket", "Connection": "Upgrade"},
                        timeout=5,
                        verify=self.scanner.config.verify_tls,
                        allow_redirects=False,
                    )
                    if resp.status_code == 101 or "websocket" in resp.headers.get("Upgrade", "").lower():
                        finding = Finding(
                            type=FindingType.WS_INJECTION,
                            severity="info",
                            title=f"WebSocket endpoint found: {path}",
                            detail=f"WebSocket upgrade available at {path}",
                            url=target.rstrip("/") + path,
                            module="websocket",
                        )
                        self.scanner.finding_manager.add(finding)
                        results["websocket"].append(finding.to_dict())
                        self.scanner.findings.append(finding.to_dict())
                except Exception:
                    logging.exception("scanner.py: exception")
                    continue

            try:
                resp = requests.get(
                    f"{target.rstrip('/')}/socket.io/?EIO=3&transport=polling",
                    timeout=5,
                    verify=self.scanner.config.verify_tls,
                )
                if resp.status_code == 200 and "sid" in resp.text:
                    finding = Finding(
                        type=FindingType.WS_HIJACK,
                        severity="medium",
                        title="Socket.IO endpoint detected",
                        detail="Socket.IO polling endpoint accessible",
                        url=target,
                        module="websocket",
                    )
                    self.scanner.finding_manager.add(finding)
                    results["websocket"].append(finding.to_dict())
                    self.scanner.findings.append(finding.to_dict())
            except Exception:
                logging.exception("scanner.py: exception")
                pass

        except Exception as e:
            results["error"] = str(e)

        total = len(results["websocket"])
        print_good(f"WebSocket tests: {total} findings")
        return results

