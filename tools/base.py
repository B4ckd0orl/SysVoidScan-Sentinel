import shutil
import subprocess
import os
import json
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class ToolWrapper(ABC):
    """Base class for all external tool wrappers."""

    name: str = ""
    binary: str = ""
    install_cmd: list = []

    def __init__(self):
        self._path: Optional[str] = None

    @property
    def path(self) -> Optional[str]:
        if self._path is None:
            self._path = shutil.which(self.binary)
        return self._path

    def is_installed(self) -> bool:
        return self.path is not None

    def install(self) -> bool:
        if self.is_installed():
            return True
        if not self.install_cmd:
            return False
        try:
            subprocess.run(self.install_cmd, check=True, capture_output=True, timeout=120)
            self._path = shutil.which(self.binary)
            return self._path is not None
        except Exception:
            return False

    def ensure_installed(self) -> bool:
        if self.is_installed():
            return True
        from core.utils import print_warning, print_info
        print_warning(f"{self.name} no esta instalado.")
        if os.name != 'nt' and self.install_cmd:
            print_info(f"Instalando {self.name}...")
            return self.install()
        return False

    def run(self, cmd_args: List[str], timeout: int = 600, capture_output: bool = True) -> subprocess.CompletedProcess:
        cmd = [self.path] + cmd_args
        return subprocess.run(cmd, capture_output=capture_output, text=True, timeout=timeout)

    def run_streaming(self, cmd_args: List[str], timeout: int = 600):
        cmd = [self.path] + cmd_args
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        lines = []
        for line in process.stdout:
            print(line, end='')
            lines.append(line)
        process.wait()
        return process.returncode, ''.join(lines)

    @abstractmethod
    def parse_results(self, raw_output: str) -> Any:
        pass


class ToolManager:
    """Manages all external tool wrappers."""

    def __init__(self):
        self._tools: Dict[str, ToolWrapper] = {}

    def register(self, tool: ToolWrapper):
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[ToolWrapper]:
        return self._tools.get(name)

    def check_all(self) -> Dict[str, bool]:
        return {name: tool.is_installed() for name, tool in self._tools.items()}

    def ensure_all(self) -> Dict[str, bool]:
        results = {}
        for name, tool in self._tools.items():
            results[name] = tool.ensure_installed()
        return results
