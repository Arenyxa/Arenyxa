from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RELEASE_RECORDS = [
    "RUNTIME_STABILIZATION_REPORT.md", "RELEASE_TEST_REPORT.md", "P99_FINAL_VALIDATION_REPORT.md",
    "REAL_GUI_ACCEPTANCE_REPORT.md", "BUILD_RELEASE_REPORT.md", "CLEAN_INSTALL_VALIDATION_REPORT.md",
    "FINAL_RELEASE_REPORT.md", "GITHUB_RELEASE_PREPARATION_REPORT.md", "PUBLIC_SOURCE_SANITIZATION_REPORT.md",
    "GUI_AUTOMATION_LIMITATION_REPORT.md", "VERSION_MIGRATION_REPORT.md", "DOCUMENTATION_RELEASE_REPORT.md",
]


def _script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("relative", [
    ".release/data/postgres/base/123", "p99_pg16/pgsql/bin/postgres.exe",
    "p99_artifacts_local/run.json", "p99_pre_lease_param_fix_backup_20260913/distributed_queue.py",
    "audit_out_v82_final/scan.json", "evidence/p99_local_pre_abg/distributed_queue.py.pre_abg",
    "src/arenyxa/enterprise/runtime_storage.py.before_pool_perf_fix",
    "RELEASE_BASELINE_AUDIT.md", "PHASE0_BASELINE_RECORD.md",
    "ARENXYA_V0.1_RELEASE_EXECUTION_PLAN.md", "RELEASE_EXECUTION_CHECKLIST.md",
    "RELEASE_FIX_PLAN.md", "V0.1_SOURCE_BASELINE.md", "PHASE6_SOURCE_INTEGRITY.txt", "gui-smoke.png",
    *RELEASE_RECORDS,
])
def test_manifest_excludes_preserved_local_artifacts(relative):
    assert _script("build_source_manifest").is_generated_or_ephemeral(Path(relative))


@pytest.mark.parametrize("relative", ["tests/fixtures/compatibility/migration-v01/arenyxa.db",
                                     "src/arenyxa/resources/icon.png", "docs/architecture.md",
                                     "docs/FINAL_RELEASE_REPORT.md"])
def test_manifest_keeps_source_and_immutable_fixtures(relative):
    assert not _script("build_source_manifest").is_generated_or_ephemeral(Path(relative))


def test_repair_candidates_exclude_preserved_package_backup(tmp_path):
    package = tmp_path / "arenyxa"
    package.mkdir()
    (package / "runtime.py").write_text("current")
    (package / "runtime.py.before_pool_perf_fix").write_text("old")
    assert [p.name for p in _script("build_source_repair_seed")._package_candidates(package)] == ["runtime.py"]


def test_git_ignore_matches_preserved_release_artifacts(tmp_path):
    git = shutil.which("git")
    assert git is not None
    subprocess.run([git, "init", str(tmp_path)], check=True, capture_output=True)
    shutil.copyfile(ROOT / ".gitignore", tmp_path / ".gitignore")
    names = [".release/report.json", "p99_pg16/postgres.exe", "audit_out_v82/scan.json",
             "evidence/local/trace.txt", "RELEASE_BASELINE_AUDIT.md", "PHASE0_BASELINE_RECORD.md",
             "ARENXYA_V0.1_RELEASE_EXECUTION_PLAN.md", "RELEASE_EXECUTION_CHECKLIST.md",
             "RELEASE_FIX_PLAN.md", "V0.1_SOURCE_BASELINE.md", "PHASE6_SOURCE_INTEGRITY.txt", "gui-smoke.png",
             *RELEASE_RECORDS]
    result = subprocess.run([git, "-C", str(tmp_path), "check-ignore", "--stdin"],
                            input=("\n".join(names) + "\n").encode("utf-8"), capture_output=True)
    assert result.returncode == 0
    assert set(result.stdout.decode("utf-8").splitlines()) == set(names)


def test_publication_local_inventory_excludes_preserved_evidence(tmp_path, monkeypatch, capsys):
    gate = _script("github_publication_gate")
    for name in gate.REQUIRED_FILES:
        (tmp_path / name).write_text("* text=auto eol=lf" if name == ".gitattributes" else "public source")
    local = tmp_path / ".release" / "private.key"
    local.parent.mkdir()
    local.write_text("preserved local evidence")
    monkeypatch.setattr(sys, "argv", ["gate", "--root", str(tmp_path), "--allow-local-artifacts"])
    assert gate.main() == 0
    assert "private/transient" not in capsys.readouterr().out
    monkeypatch.setattr(sys, "argv", ["gate", "--root", str(tmp_path)])
    assert gate.main() == 1


@pytest.mark.parametrize("separator", [chr(92), chr(92) * 2, "/"])
@pytest.mark.parametrize("segments", [("Users", "Jerry", "workspace"), ("Project", "Arenyxa_v0.1", "src")])
def test_publication_detects_personal_paths_in_all_common_encodings(separator, segments):
    gate = _script("github_publication_gate")
    value = "D:" + separator + separator.join(segments)
    assert any(pattern.search(value) for _, pattern in gate.PERSONAL_OR_PRIVATE_PATTERNS)


@pytest.mark.skipif(sys.platform != "win32", reason="PowerShell Windows build provenance contract")
def test_windows_build_refuses_non_git_provenance_before_build_tools(tmp_path):
    script = tmp_path / "scripts" / "reproducible_windows_build.ps1"
    script.parent.mkdir()
    shutil.copyfile(ROOT / "scripts" / script.name, script)
    report = tmp_path / "report.json"
    shell = shutil.which("pwsh") or shutil.which("powershell")
    assert shell is not None
    result = subprocess.run([shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), "-ReportPath", str(report)],
                            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20)
    assert result.returncode != 0
    assert report.is_file()
    data = json.loads(report.read_text(encoding="utf-8-sig"))
    assert data["passed"] is False
    assert data["stage"] == "source-provenance"
    assert "git" in data["error"].lower()


def test_postgres_results_gate_rejects_skips_and_missing_cases(tmp_path):
    path = ROOT / "scripts" / "verify_postgresql_test_results.py"
    assert path.is_file()
    gate = _script("verify_postgresql_test_results")
    xml = tmp_path / "results.xml"
    cases = "".join(f'<testcase name="{name}" />' for name in gate.REQUIRED_TESTS)
    xml.write_text("<testsuite>" + cases + "</testsuite>")
    assert gate.validate(xml) == []
    xml.write_text("<testsuite>" + cases.replace(" />", "><skipped /></testcase>", 1) + "</testsuite>")
    assert gate.validate(xml)
    xml.write_text("<testsuite />")
    assert gate.validate(xml)
