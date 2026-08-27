from __future__ import annotations

import hashlib
import json
import warnings
import zipfile
from pathlib import Path

import pytest

from arenyxa.application.project_format import PROJECT_FORMAT, ProjectManifest, ArenyxaProjectService
from arenyxa.application.versioning import DatasetVersionService
from arenyxa.application.workflows import WorkflowEngine
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import DatasetRevision, Workflow, WorkflowNode
from arenyxa.infrastructure.observability import Redactor
from arenyxa.infrastructure.plugins import PluginManifest, PluginSandbox


def test_version_compare_and_rollback() -> None:
    before = DatasetRevision("data", ["run1"], {"a": {"x": 1}, "b": {"x": 2}}, schema={"x": "integer"})
    after = DatasetRevision(
        "data",
        ["run2"],
        {"a": {"x": 3}, "c": {"x": 4, "name": "n"}},
        schema={"x": "number", "name": "string"},
    )
    diff = DatasetVersionService.compare(before, after)
    assert set(diff.added) == {"c"}
    assert set(diff.removed) == {"b"}
    assert diff.modified["a"][0].after == 3
    rolled = DatasetVersionService.rollback(after, before)
    assert rolled.parent_revision == after.id
    assert rolled.records == before.records


def test_project_pack_validate_unpack_and_traversal_defense(tmp_path) -> None:
    source = tmp_path / "source"
    (source / "workflows").mkdir(parents=True)
    (source / "workflows" / "main.json").write_text('{"ok":true}', encoding="utf-8")
    (source / "private.key").write_text("secret", encoding="utf-8")
    package = tmp_path / "project.arenyxa"
    service = ArenyxaProjectService()
    service.pack(source, package, ProjectManifest("Project"))
    manifest = service.validate(package)
    assert "workflows/main.json" in manifest.files
    assert "private.key" not in manifest.files
    output = tmp_path / "unpacked"
    service.unpack(package, output)
    assert (output / "workflows" / "main.json").exists()

    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "keep.txt").write_text("keep", encoding="utf-8")
    with pytest.raises(ArenyxaError) as occupied_error:
        service.unpack(package, occupied)
    assert occupied_error.value.code == "PROJECT_DESTINATION_NOT_EMPTY"
    assert (occupied / "keep.txt").read_text(encoding="utf-8") == "keep"

    malicious = tmp_path / "malicious.arenyxa"
    with zipfile.ZipFile(malicious, "w") as archive:
        archive.writestr("../escape.txt", "bad")
    with pytest.raises(ArenyxaError) as error:
        service.validate(malicious)
    assert error.value.code == "PROJECT_PATH_TRAVERSAL"


def test_project_repack_excludes_existing_destination_from_source(tmp_path: Path) -> None:
    source = tmp_path / "source"
    (source / "workflows").mkdir(parents=True)
    (source / "workflows" / "main.json").write_text("{}", encoding="utf-8")
    destination = source / "workflows" / "export.arenyxa"
    destination.write_bytes(b"old package must not be embedded")
    service = ArenyxaProjectService()
    service.pack(source, destination, ProjectManifest(name="demo"))
    manifest = service.validate(destination)
    assert "workflows/main.json" in manifest.files
    assert "workflows/export.arenyxa" not in manifest.files


def test_workflow_success_and_failure_route() -> None:
    workflow = Workflow(
        "quality",
        [
            WorkflowNode("source", {}, id="source", next_ids=["validate"]),
            WorkflowNode(
                "validate", {"required": ["title"]}, id="validate", next_ids=["sink"], failure_ids=["errors"]
            ),
            WorkflowNode("sink", {}, id="sink"),
            WorkflowNode("sink", {}, id="errors"),
        ],
    )
    result = WorkflowEngine().execute(workflow, [{"title": "ok"}, {"title": ""}])
    assert any(item.get("title") == "ok" for item in result.outputs)
    assert any("_error" in item for item in result.outputs)
    assert result.errors


def test_redaction_and_plugin_permission_guard(tmp_path) -> None:
    redacted = Redactor().redact(
        {"Authorization": "Bearer top-secret", "nested": {"password": "p"}, "message": "api_key=123"}
    )
    serialized = json.dumps(redacted)
    assert "top-secret" not in serialized and '"p"' not in serialized and "123" not in serialized

    plugin = tmp_path / "plugin"
    plugin.mkdir()
    (plugin / "plugin.json").write_text(
        json.dumps(
            {
                "id": "test.plugin",
                "name": "Test",
                "version": "1.0.0",
                "entry": "main.py",
                "permissions": {"network": {}},
            }
        ),
        encoding="utf-8",
    )
    (plugin / "main.py").write_text("def handle(request):\n    return request\n", encoding="utf-8")
    assert PluginManifest.load(plugin / "plugin.json").id == "test.plugin"
    with pytest.raises(ArenyxaError) as error:
        PluginSandbox().invoke(plugin, {"hello": "world"}, {})
    assert error.value.code == "PLUGIN_PERMISSION_DENIED"


def test_application_png_matches_current_approved_arenyxa_app_icon() -> None:
    icon = (
        Path(__file__).parents[1]
        / "src"
        / "arenyxa"
        / "resources"
        / "icons"
        / "arenyxa.png"
    )
    assert (
        hashlib.sha256(icon.read_bytes()).hexdigest().upper()
        == "EE03DFC7C4160A31B7B0730376E65E22932A501E25A4593D0DDE06E209D51FB8"
    )


def test_project_rejects_undeclared_archive_member(tmp_path: Path) -> None:
    source = tmp_path / "source"
    (source / "workflows").mkdir(parents=True)
    (source / "workflows" / "main.json").write_text("{}", encoding="utf-8")
    package = tmp_path / "project.arenyxa"
    service = ArenyxaProjectService()
    service.pack(source, package, ProjectManifest(name="demo"))
    with zipfile.ZipFile(package, "a") as archive:
        archive.writestr("scripts/injected.py", "print('unexpected')")
    try:
        service.validate(package)
    except ArenyxaError as exc:
        assert exc.code == "PROJECT_UNDECLARED_FILE"
    else:
        raise AssertionError("undeclared archive member must be rejected")


def test_project_rejects_duplicate_zip_entries(tmp_path: Path) -> None:
    package = tmp_path / "duplicate.arenyxa"
                                                                                            
                                                                                            
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="Duplicate name:.*", category=UserWarning)
        with zipfile.ZipFile(package, "w") as archive:
            archive.writestr("manifest.json", '{"name":"demo","files":{}}')
            archive.writestr("manifest.json", '{"name":"other","files":{}}')
    try:
        ArenyxaProjectService().validate(package)
    except ArenyxaError as exc:
        assert exc.code == "PROJECT_DUPLICATE_ENTRY"
    else:
        raise AssertionError("duplicate ZIP entries must be rejected")


def test_project_rejects_non_object_manifest(tmp_path: Path) -> None:
    package = tmp_path / "bad-root.arenyxa"
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("manifest.json", "[]")
    with pytest.raises(ArenyxaError) as exc:
        ArenyxaProjectService().validate(package)
    assert exc.value.code == "PROJECT_MANIFEST_INVALID"


def test_project_rejects_unknown_manifest_fields(tmp_path: Path) -> None:
    package = tmp_path / "bad-field.arenyxa"
    manifest = {"name": "x", "format": PROJECT_FORMAT, "files": {}, "unknown": True}
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
    with pytest.raises(ArenyxaError) as exc:
        ArenyxaProjectService().validate(package)
    assert exc.value.code == "PROJECT_MANIFEST_INVALID"
