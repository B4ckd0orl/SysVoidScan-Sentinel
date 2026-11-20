import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from tools.base import ToolWrapper, ToolManager


class DummyTool(ToolWrapper):
    name = "dummy"
    binary = "nonexistent_binary_xyz_12345"
    install_cmd = []

    def parse_results(self, raw_output):
        return {"output": raw_output}


class DummyToolWithInstall(ToolWrapper):
    name = "dummy_install"
    binary = "nonexistent_binary_xyz_12345"
    install_cmd = ["echo", "installing"]

    def parse_results(self, raw_output):
        return {"output": raw_output}


class TestToolNotFound:
    def test_path_is_none_when_not_installed(self):
        tool = DummyTool()
        assert tool.path is None

    def test_is_installed_returns_false(self):
        tool = DummyTool()
        assert tool.is_installed() is False

    def test_run_raises_when_not_installed(self):
        tool = DummyTool()
        import pytest
        with pytest.raises(TypeError):
            tool.run(["--help"])

    def test_parse_results_works(self):
        tool = DummyTool()
        result = tool.parse_results("test output")
        assert result == {"output": "test output"}


class TestToolManagerRegister:
    def test_register_and_get(self):
        manager = ToolManager()
        tool = DummyTool()
        manager.register(tool)
        assert manager.get("dummy") is tool

    def test_get_nonexistent_returns_none(self):
        manager = ToolManager()
        assert manager.get("nonexistent") is None

    def test_check_all(self):
        manager = ToolManager()
        tool = DummyTool()
        manager.register(tool)
        results = manager.check_all()
        assert "dummy" in results
        assert results["dummy"] is False

    def test_multiple_register(self):
        manager = ToolManager()
        tool1 = DummyTool()
        tool2 = DummyToolWithInstall()
        manager.register(tool1)
        manager.register(tool2)
        assert manager.get("dummy") is tool1
        assert manager.get("dummy_install") is tool2

    def test_register_overwrites_same_name(self):
        manager = ToolManager()
        tool1 = DummyTool()
        tool2 = DummyTool()
        manager.register(tool1)
        manager.register(tool2)
        assert manager.get("dummy") is tool2

    def test_ensure_all(self):
        manager = ToolManager()
        tool = DummyTool()
        manager.register(tool)
        results = manager.ensure_all()
        assert "dummy" in results
