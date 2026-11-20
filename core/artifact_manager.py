import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import logging
from typing import Any, Dict, List, Optional


class ArtifactManager:
    """Manage generated artifacts and evidence for scans."""

    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = os.path.abspath(base_dir or os.path.join("reports", "artifacts"))
        os.makedirs(self.base_dir, exist_ok=True)
        self._records: List[Dict[str, Any]] = []
        self._load_index()

    def _load_index(self) -> None:
        index_path = os.path.join(self.base_dir, "index.json")
        if os.path.isfile(index_path):
            try:
                with open(index_path, "r", encoding="utf-8") as handle:
                    data = json.load(handle)
                self._records = data.get("artifacts", [])
            except Exception:
                logging.exception("Failed to load artifact index")
                self._records = []

    def _write_index(self) -> None:
        index_path = os.path.join(self.base_dir, "index.json")
        with open(index_path, "w", encoding="utf-8") as handle:
            json.dump({"artifacts": self._records, "generated_at": time.time()}, handle, indent=2)

    def _safe_name(self, name: str) -> str:
        safe = os.path.basename(name).strip().replace(" ", "_")
        safe = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in safe)
        safe = safe.strip("._") or "artifact"
        if len(safe) > 120:
            safe = safe[:120]
        return safe

    def _artifact_path(self, kind: str, name: str) -> str:
        kind_dir = os.path.join(self.base_dir, kind)
        os.makedirs(kind_dir, exist_ok=True)
        return os.path.join(kind_dir, self._safe_name(name))

    def register_file_artifact(
        self,
        source_path: str,
        kind: str = "files",
        title: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not source_path or not os.path.isfile(source_path):
            raise FileNotFoundError(source_path)
        artifact_name = title or os.path.basename(source_path)
        destination = self._artifact_path(kind, artifact_name)
        if os.path.abspath(source_path) != os.path.abspath(destination):
            shutil.copy2(source_path, destination)
        size = os.path.getsize(destination)
        sha256 = hashlib.sha256(open(destination, "rb").read()).hexdigest()
        record = {
            "id": f"{kind}-{int(time.time() * 1000)}",
            "kind": kind,
            "title": artifact_name,
            "path": destination,
            "source": source_path,
            "size_bytes": size,
            "sha256": sha256,
            "created_at": time.time(),
            "metadata": metadata or {},
        }
        self._records.append(record)
        self._write_index()
        return record

    def register_text_artifact(
        self,
        title: str,
        content: str,
        kind: str = "text",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        destination = self._artifact_path(kind, title)
        with open(destination, "w", encoding="utf-8") as handle:
            handle.write(content)
        size = os.path.getsize(destination)
        sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
        record = {
            "id": f"{kind}-{int(time.time() * 1000)}",
            "kind": kind,
            "title": title,
            "path": destination,
            "size_bytes": size,
            "sha256": sha256,
            "created_at": time.time(),
            "metadata": metadata or {},
        }
        self._records.append(record)
        self._write_index()
        return record

    def list_artifacts(self) -> List[Dict[str, Any]]:
        return list(self._records)

    def preview_artifact(self, artifact_path: str, limit: int = 400) -> str:
        if not artifact_path:
            return ""
        resolved = artifact_path if os.path.isabs(artifact_path) else os.path.join(self.base_dir, artifact_path)
        if not os.path.isfile(resolved):
            return ""
        ext = os.path.splitext(resolved)[1].lower()
        if ext in {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}:
            return f"[image] {os.path.basename(resolved)}"
        with open(resolved, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)

    def open_artifact(self, artifact_path: str) -> bool:
        if not artifact_path:
            return False
        resolved = artifact_path if os.path.isabs(artifact_path) else os.path.join(self.base_dir, artifact_path)
        if not os.path.isfile(resolved):
            return False
        if sys.platform.startswith("win"):
            os.startfile(resolved)  # type: ignore[attr-defined]
        else:
            opener = "xdg-open"
            if os.system(f"which {opener} >/dev/null 2>&1") == 0:
                subprocess.Popen([opener, resolved])
            else:
                return False
        return True

    def write_index(self) -> str:
        self._write_index()
        return os.path.join(self.base_dir, "index.json")
