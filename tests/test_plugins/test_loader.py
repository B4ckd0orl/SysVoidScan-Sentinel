import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from plugins.loader import PluginLoader


class DummyScanner:
    pass


class TestPluginLoader:
    def test_loads_plugin_from_manifest(self, tmp_path):
        plugin_file = tmp_path / "manifest_plugin.py"
        plugin_file.write_text(
            """
from plugins.loader import Plugin

PLUGIN_MANIFEST = {
    \"name\": \"fixture-plugin\",
    \"version\": \"1.2.3\",
    \"description\": \"Fixture plugin\",
    \"category\": \"testing\",
    \"author\": \"Copilot\",
    \"tags\": [\"fixture\", \"test\"],
}

class FixturePlugin(Plugin):
    name = \"fixture-plugin\"
    version = \"1.2.3\"
    description = \"Fixture plugin\"
    category = \"testing\"
    author = \"Copilot\"
    tags = [\"fixture\", \"test\"]

    def register(self, scanner):
        self.scanner = scanner

    def run(self, target, options=None):
        return {\"target\": target}
""",
            encoding="utf-8",
        )

        loader = PluginLoader(str(tmp_path))
        plugin = loader.load_plugin(str(plugin_file))

        assert plugin is not None
        assert plugin.name == "fixture-plugin"
        assert loader.get_error_summary() == {}
        metadata = loader.list_plugins()[0]
        assert metadata["name"] == "fixture-plugin"
        assert metadata["category"] == "testing"
        assert metadata["author"] == "Copilot"
        assert metadata["tags"] == ["fixture", "test"]

    def test_records_load_errors(self, tmp_path):
        broken_plugin = tmp_path / "broken_plugin.py"
        broken_plugin.write_text(
            """
from plugins.loader import Plugin

class BrokenPlugin(Plugin):
    name = \"broken-plugin\"
    description = \"Broken plugin\"

    def register(self, scanner):
        raise RuntimeError(\"registration failed\")

    def run(self, target, options=None):
        return {}
""",
            encoding="utf-8",
        )

        loader = PluginLoader(str(tmp_path))
        plugin = loader.load_plugin(str(broken_plugin))

        assert plugin is not None
        loader.register_hooks(DummyScanner())
        assert "broken-plugin" in loader.get_error_summary()
