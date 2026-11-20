import importlib
import importlib.util
import os
import sys
import logging
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional


class Plugin(ABC):
    """Base class for all SysVoidScan plugins."""

    name: str = "unnamed"
    version: str = "0.0.1"
    description: str = ""
    category: str = "misc"
    author: str = ""
    tags: List[str] = []

    @abstractmethod
    def register(self, scanner) -> None:
        """Register plugin hooks with the scanner."""
        pass

    @abstractmethod
    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute the plugin's main functionality."""
        pass

    def manifest(self) -> Dict[str, Any]:
        """Expose plugin metadata for UI and loader integration."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "category": self.category,
            "author": self.author,
            "tags": list(self.tags or []),
        }

    def report(self, results: Dict[str, Any]) -> str:
        """Return a summary string of the plugin results."""
        return f"Plugin {self.name}: {len(results)} results"


class PluginLoader:
    """Discovers, loads, and manages plugins."""

    def __init__(self, plugins_dir: Optional[str] = None):
        self.plugins_dir = plugins_dir or os.path.join(os.path.dirname(__file__))
        self._plugins: Dict[str, Plugin] = {}
        self._hooks: Dict[str, List[Dict[str, Any]]] = {}
        self._load_errors: Dict[str, str] = {}

    def scan_plugins_dir(self, path: Optional[str] = None) -> List[str]:
        """Discover plugin files in the given directory."""
        target_dir = path or self.plugins_dir
        if not os.path.isdir(target_dir):
            return []

        discovered = []
        for filename in sorted(os.listdir(target_dir)):
            if (
                filename.endswith(".py")
                and not filename.startswith("_")
                and filename != "loader.py"
            ):
                discovered.append(os.path.join(target_dir, filename))
        return discovered

    def _normalize_manifest(self, manifest: Optional[Dict[str, Any]], plugin_instance: Plugin, module: Any) -> Dict[str, Any]:
        if isinstance(manifest, dict):
            normalized = {
                "name": manifest.get("name") or getattr(plugin_instance, "name", "unnamed"),
                "version": manifest.get("version") or getattr(plugin_instance, "version", "0.0.1"),
                "description": manifest.get("description") or getattr(plugin_instance, "description", ""),
                "category": manifest.get("category") or getattr(plugin_instance, "category", "misc"),
                "author": manifest.get("author") or getattr(plugin_instance, "author", ""),
                "tags": list(manifest.get("tags") or getattr(plugin_instance, "tags", []) or []),
            }
            return normalized

        return {
            "name": getattr(plugin_instance, "name", "unnamed"),
            "version": getattr(plugin_instance, "version", "0.0.1"),
            "description": getattr(plugin_instance, "description", ""),
            "category": getattr(plugin_instance, "category", "misc"),
            "author": getattr(plugin_instance, "author", ""),
            "tags": list(getattr(plugin_instance, "tags", []) or []),
        }

    def _resolve_manifest(self, plugin_instance: Plugin, module: Any) -> Dict[str, Any]:
        manifest = getattr(module, "PLUGIN_MANIFEST", None)
        if isinstance(manifest, dict):
            return self._normalize_manifest(manifest, plugin_instance, module)

        for attr_name in ("manifest", "get_manifest"):
            if hasattr(plugin_instance, attr_name):
                attr = getattr(plugin_instance, attr_name)
                if callable(attr):
                    try:
                        value = attr()
                    except Exception:
                        logging.exception("_resolve_manifest: plugin manifest callable failed")
                        value = None
                    if isinstance(value, dict):
                        return self._normalize_manifest(value, plugin_instance, module)
                elif isinstance(attr, dict):
                    return self._normalize_manifest(attr, plugin_instance, module)

        return self._normalize_manifest(None, plugin_instance, module)

    def _register_plugin(self, plugin_instance: Plugin, module: Any, module_name: str) -> Optional[Plugin]:
        manifest = self._resolve_manifest(plugin_instance, module)
        plugin_instance._manifest = manifest
        plugin_instance.manifest_data = manifest
        plugin_key = manifest.get("name") or getattr(plugin_instance, "name", module_name)
        self._plugins[plugin_key] = plugin_instance
        self._load_errors.pop(module_name, None)
        return plugin_instance

    def load_plugin(self, module_path: str) -> Optional[Plugin]:
        """Dynamically import a plugin module and return its Plugin instance."""
        if not os.path.isfile(module_path):
            return None

        module_name = os.path.splitext(os.path.basename(module_path))[0]
        full_module_name = f"plugins.{module_name}"

        try:
            spec = importlib.util.spec_from_file_location(full_module_name, module_path)
            if spec is None or spec.loader is None:
                return None
            module = importlib.util.module_from_spec(spec)
            sys.modules[full_module_name] = module
            spec.loader.exec_module(module)

            plugin_obj = getattr(module, "PLUGIN_INSTANCE", None)
            if plugin_obj is None:
                plugin_obj = getattr(module, "plugin", None)
            if isinstance(plugin_obj, Plugin):
                return self._register_plugin(plugin_obj, module, module_name)

            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if isinstance(attr, type) and issubclass(attr, Plugin) and attr is not Plugin:
                    if getattr(attr, "__abstractmethods__", None):
                        continue
                    try:
                        instance = attr()
                        return self._register_plugin(instance, module, module_name)
                    except Exception as exc:
                        logging.exception("load_plugin: plugin class instantiation failed")
                        self._load_errors[module_name] = str(exc)
                        continue

        except Exception as exc:
            logging.exception("load_plugin: failed to import/exec module")
            self._load_errors[module_name] = str(exc)

        return None

    def register_hooks(self, scanner) -> None:
        """Register all loaded plugin hooks with the scanner."""
        for name, plugin in self._plugins.items():
            try:
                plugin.register(scanner)
                self._hooks[name] = getattr(scanner, "_plugin_hooks", {}).get(name, [])
            except Exception as exc:
                logging.exception("register_hooks: plugin.register failed")
                self._load_errors[name] = str(exc)

    def list_plugins(self) -> List[Dict[str, Any]]:
        """Return a list of available plugins with their metadata."""
        plugins = []
        for plugin in self._plugins.values():
            manifest = getattr(plugin, "_manifest", {}) or {}
            plugins.append({
                "name": manifest.get("name", getattr(plugin, "name", "unnamed")),
                "version": manifest.get("version", getattr(plugin, "version", "0.0.1")),
                "description": manifest.get("description", getattr(plugin, "description", "")),
                "category": manifest.get("category", getattr(plugin, "category", "misc")),
                "author": manifest.get("author", ""),
                "tags": manifest.get("tags", []),
                "status": "loaded",
            })
        return plugins

    def get_error_summary(self) -> Dict[str, str]:
        return dict(self._load_errors)

    def get_plugin(self, name: str) -> Optional[Plugin]:
        """Get a specific plugin by name."""
        return self._plugins.get(name)

    def load_all(self) -> int:
        """Load all discovered plugins. Returns the count of loaded plugins."""
        discovered = self.scan_plugins_dir()
        loaded = 0
        for path in discovered:
            plugin = self.load_plugin(path)
            if plugin:
                loaded += 1
        return loaded
