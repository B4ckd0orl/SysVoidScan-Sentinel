import os
import json
import time
import base64
import hashlib
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from core.artifact_manager import ArtifactManager
import logging

@dataclass
class HTTPEvidence:
    """HTTP request/response evidence pair."""
    request_method: str = ""
    request_url: str = ""
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    response_status: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    response_time: float = 0.0
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> dict:
        return {
            "request": {
                "method": self.request_method,
                "url": self.request_url,
                "headers": self.request_headers,
                "body": self.request_body[:5000],
            },
            "response": {
                "status": self.response_status,
                "headers": self.response_headers,
                "body": self.response_body[:10000],
                "time_ms": round(self.response_time * 1000, 2),
            },
            "timestamp": self.timestamp,
        }

class EvidenceCollector:
    """Collect and store evidence for all findings."""
    
    def __init__(self, output_dir="./evidence", artifact_manager: Optional[ArtifactManager] = None):
        self.output_dir = output_dir
        self._evidence: Dict[str, List[dict]] = {}
        self._screenshots: Dict[str, str] = {}
        self.artifact_manager = artifact_manager
        os.makedirs(output_dir, exist_ok=True)
    
    def capture_http_pair(self, request_method, request_url, request_headers=None,
                          request_body="", response_status=0, response_headers=None,
                          response_body="", response_time=0.0) -> HTTPEvidence:
        """Store HTTP request/response pair."""
        evidence = HTTPEvidence(
            request_method=request_method,
            request_url=request_url,
            request_headers=request_headers or {},
            request_body=request_body,
            response_status=response_status,
            response_headers=response_headers or {},
            response_body=response_body,
            response_time=response_time,
        )
        
        evidence_id = hashlib.md5(f"{request_url}{time.time()}".encode()).hexdigest()[:12]
        
        if evidence_id not in self._evidence:
            self._evidence[evidence_id] = []
        self._evidence[evidence_id].append(evidence.to_dict())
        
        self._save_evidence(evidence_id, evidence)
        if self.artifact_manager is not None:
            try:
                self.artifact_manager.register_file_artifact(
                    source_path=os.path.join(self.output_dir, f"{evidence_id}_http_{int(evidence.timestamp)}.json"),
                    kind="evidence",
                    title=f"{evidence_id}_http_evidence.json",
                    metadata={"request_url": request_url, "request_method": request_method},
                )
            except Exception:
                logging.exception("capture_http_pair: failed to register file artifact")
        
        return evidence
    
    def capture_from_response(self, resp, request_method="GET", request_body=""):
        """Capture evidence from a requests.Response object."""
        return self.capture_http_pair(
            request_method=request_method,
            request_url=str(resp.url),
            request_headers=dict(resp.request.headers) if hasattr(resp, 'request') else {},
            request_body=request_body,
            response_status=resp.status_code,
            response_headers=dict(resp.headers),
            response_body=resp.text,
            response_time=resp.elapsed.total_seconds() if hasattr(resp, 'elapsed') else 0,
        )
    
    def capture_screenshot(self, finding_id: str, screenshot_data: bytes, url: str = "") -> str:
        """Store screenshot evidence."""
        filename = f"{finding_id}_{int(time.time())}.png"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, "wb") as f:
            f.write(screenshot_data)
        
        self._screenshots[finding_id] = filepath
        if self.artifact_manager is not None:
            try:
                self.artifact_manager.register_file_artifact(
                    filepath,
                    kind="screenshots",
                    title=os.path.basename(filepath),
                    metadata={"finding_id": finding_id, "url": url},
                )
            except Exception:
                logging.exception("capture_screenshot: failed to register screenshot artifact")
        return filepath
    
    def capture_text(self, finding_id: str, text: str, label: str = "output") -> str:
        """Store text evidence."""
        filename = f"{finding_id}_{label}_{int(time.time())}.txt"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(text)
        
        if self.artifact_manager is not None:
            try:
                self.artifact_manager.register_file_artifact(
                    filepath,
                    kind="text",
                    title=os.path.basename(filepath),
                    metadata={"finding_id": finding_id, "label": label},
                )
            except Exception:
                logging.exception("capture_text: failed to register text artifact")
        return filepath
    
    def add_finding_evidence(self, finding_id: str, evidence_type: str, data: dict):
        """Add structured evidence for a finding."""
        if finding_id not in self._evidence:
            self._evidence[finding_id] = []
        
        self._evidence[finding_id].append({
            "type": evidence_type,
            "data": data,
            "timestamp": time.time(),
        })
    
    def get_evidence(self, finding_id: str) -> List[dict]:
        """Get all evidence for a finding."""
        return self._evidence.get(finding_id, [])
    
    def get_screenshot(self, finding_id: str) -> Optional[str]:
        """Get screenshot path for a finding."""
        return self._screenshots.get(finding_id)
    
    def export_finding_evidence(self, finding_id: str, format: str = "json") -> str:
        """Export all evidence for a finding."""
        evidence = self.get_evidence(finding_id)
        screenshots = self.get_screenshot(finding_id)
        
        export_data = {
            "finding_id": finding_id,
            "evidence_count": len(evidence),
            "screenshots": [screenshots] if screenshots else [],
            "evidence": evidence,
            "exported_at": time.time(),
        }
        
        if format == "json":
            filepath = os.path.join(self.output_dir, f"{finding_id}_evidence.json")
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, default=str)
            return filepath
        
        return ""
    
    def export_all_evidence(self, format: str = "json") -> str:
        """Export all collected evidence."""
        export_data = {
            "total_findings": len(self._evidence),
            "total_screenshots": len(self._screenshots),
            "findings": {},
            "exported_at": time.time(),
        }
        
        for finding_id, evidence in self._evidence.items():
            export_data["findings"][finding_id] = {
                "evidence_count": len(evidence),
                "screenshot": self._screenshots.get(finding_id),
                "evidence": evidence,
            }
        
        filepath = os.path.join(self.output_dir, f"all_evidence.json")
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, default=str)
        return filepath
    
    def _save_evidence(self, evidence_id: str, evidence: HTTPEvidence):
        """Save evidence to file."""
        filename = f"{evidence_id}_http_{int(evidence.timestamp)}.json"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(evidence.to_dict(), f, indent=2, default=str)
    
    def get_stats(self) -> dict:
        """Get evidence collection statistics."""
        return {
            "total_findings_with_evidence": len(self._evidence),
            "total_evidence_items": sum(len(v) for v in self._evidence.values()),
            "total_screenshots": len(self._screenshots),
            "output_dir": self.output_dir,
        }
