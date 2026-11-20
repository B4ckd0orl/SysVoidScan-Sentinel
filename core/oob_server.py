import hashlib
import json
import socket
import struct
import threading
import time
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Optional, List, Dict, Any
import logging

logger = logging.getLogger(__name__)

try:
    from dnslib import DNSRecord, QTYPE, RCODE, RR, A, TXT, NS
    HAS_DNSLIB = True
except ImportError:
    HAS_DNSLIB = False


class OOBInteraction:
    """Represents a single OOB interaction."""

    def __init__(self, protocol, host, port, data, source_ip=None, timestamp=None):
        self.id = str(uuid.uuid4())[:8]
        self.protocol = protocol
        self.host = host
        self.port = port
        self.data = data
        self.source_ip = source_ip
        self.timestamp = timestamp or time.time()

    def to_dict(self):
        return {
            "id": self.id,
            "protocol": self.protocol,
            "host": self.host,
            "port": self.port,
            "data": self.data,
            "source_ip": self.source_ip,
            "timestamp": self.timestamp,
        }


class _OOBRequestHandler(BaseHTTPRequestHandler):
    """HTTP handler for OOB callbacks."""

    def do_GET(self):
        self.server.interactions.append(OOBInteraction(
            protocol="http",
            host=self.headers.get("Host", ""),
            port=80,
            data={"path": self.path, "query": parse_qs(urlparse(self.path).query)},
            source_ip=self.client_address[0],
        ))
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>OOB Callback Received</h1></body></html>")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace")
        self.server.interactions.append(OOBInteraction(
            protocol="http",
            host=self.headers.get("Host", ""),
            port=80,
            data={"path": self.path, "body": body[:5000]},
            source_ip=self.client_address[0],
        ))
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress default logging


class _OOB_DNSServer:
    """DNS server for OOB DNS exfiltration."""

    def __init__(self, oob_server, port=53, host="0.0.0.0"):
        self.oob_server = oob_server
        self.port = port
        self.host = host
        self.socket = None
        self._thread = None
        self._running = False

    def start(self):
        if not HAS_DNSLIB:
            logger.warning("dnslib not installed, DNS OOB server disabled")
            return False
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self._running = True
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
            return True
        except Exception as e:
            logger.error(f"Failed to start DNS OOB server: {e}")
            return False

    def stop(self):
        self._running = False
        if self.socket:
            self.socket.close()

    def _run(self):
        while self._running:
            try:
                data, addr = self.socket.recvfrom(1024)
            except OSError:
                # Socket cerrado por stop(): no es un error, terminar el hilo.
                break
            except Exception:
                logging.exception("Operation failed")
                break
            try:
                self._handle_query(data, addr)
            except Exception:
                logging.exception("Operation failed")

    def _handle_query(self, data, addr):
        try:
            request = DNSRecord.parse(data)
            qname = str(request.q.qname)
            qtype = QTYPE[request.q.qtype]

            # Extract token from subdomain
            token = qname.split('.')[0] if '.' in qname else qname.rstrip('.')

            interaction = OOBInteraction(
                protocol="dns",
                host=qname,
                port=self.port,
                data={"query": qname, "type": qtype, "token": token},
                source_ip=addr[0],
            )
            self.oob_server.interactions.append(interaction)

            # Respond with A record pointing to 127.0.0.1
            reply = request.reply()
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A("127.0.0.1"), ttl=60))
            self.socket.sendto(reply.pack(), addr)
        except Exception as e:
            logger.debug(f"DNS query handling error: {e}")


class OOBServer:
    """Built-in Out-of-Band interaction server (HTTP + DNS)."""

    def __init__(self, port=8888, host="0.0.0.0", dns_port=53):
        self.port = port
        self.host = host
        self.dns_port = dns_port
        self.interactions: List[OOBInteraction] = []
        self._http_server: Optional[HTTPServer] = None
        self._dns_server: Optional[_OOB_DNSServer] = None
        self._http_thread: Optional[threading.Thread] = None
        self._running = False
        self._callbacks: Dict[str, dict] = {}
        self._token_counter = 0

    def start(self) -> bool:
        """Start the OOB HTTP and DNS servers."""
        success = True
        try:
            self._http_server = HTTPServer((self.host, self.port), _OOBRequestHandler)
            self._http_server.interactions = self.interactions
            self._http_thread = threading.Thread(
                target=self._http_server.serve_forever, daemon=True
            )
            self._http_thread.start()
        except Exception as e:
            logger.error(f"[OOB] Failed to start HTTP server: {e}")
            success = False

        if HAS_DNSLIB:
            try:
                self._dns_server = _OOB_DNSServer(self, self.dns_port, self.host)
                if not self._dns_server.start():
                    success = False
            except Exception as e:
                logger.error(f"[OOB] Failed to start DNS server: {e}")
                success = False
        else:
            logger.warning("dnslib not available, DNS OOB disabled. Install with: pip install dnslib")

        self._running = success
        return success

    def stop(self):
        """Stop the OOB servers."""
        if self._http_server:
            self._http_server.shutdown()
        if self._dns_server:
            self._dns_server.stop()
        self._running = False

    def get_callback_url(self, label="") -> str:
        """Generate a unique callback URL."""
        self._token_counter += 1
        token = hashlib.md5(
            f"{time.time()}-{self._token_counter}-{label}".encode()
        ).hexdigest()[:12]
        callback_url = f"http://{self.host}:{self.port}/oob/{token}"
        self._callbacks[token] = {
            "url": callback_url,
            "label": label,
            "created": time.time(),
        }
        return callback_url

    def wait_for_interaction(self, token=None, timeout=30) -> Optional[OOBInteraction]:
        """Wait for an OOB interaction."""
        start = time.time()
        while time.time() - start < timeout:
            for interaction in reversed(self.interactions):
                if token is None or token in interaction.data.get("path", ""):
                    return interaction
            time.sleep(0.1)
        return None

    def get_interactions(self, token=None) -> List[dict]:
        """Get all interactions, optionally filtered by token."""
        results = []
        for interaction in self.interactions:
            if token is None or token in str(interaction.data):
                results.append(interaction.to_dict())
        return results

    def get_stats(self) -> dict:
        """Get OOB server statistics."""
        return {
            "running": self._running,
            "port": self.port,
            "total_interactions": len(self.interactions),
            "callbacks_created": len(self._callbacks),
            "protocols": {
                "http": sum(
                    1 for i in self.interactions if i.protocol == "http"
                ),
                "dns": sum(
                    1 for i in self.interactions if i.protocol == "dns"
                ),
            },
        }

    @property
    def is_running(self):
        return self._running
