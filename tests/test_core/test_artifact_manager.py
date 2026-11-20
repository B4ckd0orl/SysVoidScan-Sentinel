import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from core.artifact_manager import ArtifactManager


def test_register_and_preview_text_artifact(tmp_path):
    manager = ArtifactManager(base_dir=str(tmp_path))
    record = manager.register_text_artifact(
        title="sample.txt",
        content="Hello SysVoidScan!",
        kind="notes",
        metadata={"source": "test"},
    )

    assert os.path.isfile(record["path"])
    assert record["title"] == "sample.txt"
    assert record["kind"] == "notes"
    assert record["metadata"]["source"] == "test"
    assert len(manager.list_artifacts()) == 1

    preview = manager.preview_artifact(record["path"])
    assert "Hello SysVoidScan" in preview


def test_register_file_artifact_and_index(tmp_path):
    source_file = tmp_path / "payload.bin"
    source_file.write_text("binary-data-sample", encoding="utf-8")

    manager = ArtifactManager(base_dir=str(tmp_path / "artifacts"))
    record = manager.register_file_artifact(
        source_path=str(source_file),
        kind="payloads",
        title="payload.bin",
        metadata={"type": "test"},
    )

    assert os.path.isfile(record["path"])
    assert record["kind"] == "payloads"
    assert record["metadata"]["type"] == "test"
    assert len(manager.list_artifacts()) == 1
    assert record["sha256"]
