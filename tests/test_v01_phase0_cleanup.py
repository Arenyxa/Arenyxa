from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write(root, name, data=b'preserved original'):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def test_cleanup_removes_gate_bytecode_but_preserves_source_and_coverage_config(tmp_path):
    bytecode = [_write(tmp_path, name) for name in (
        'src/arenyxa/__pycache__/app.cpython-313.pyc',
        'scripts/__pycache__/gate.cpython-313.pyc',
        'tests/nested/module.pyo',
    )]
    preserved = [_write(tmp_path, name) for name in (
        'src/arenyxa/app.py', 'scripts/gate.py', 'tests/nested/test_module.py',
        'tests/.coveragerc', 'scripts/.coverage-policy.md',
    )]
    _script('phase0_gate').cleanup_ephemeral(tmp_path)
    assert not any(path.exists() for path in bytecode)
    assert all(path.read_bytes() == b'preserved original' for path in preserved)


def test_cleanup_preserves_dependencies_backups_and_unrelated_runtime_trees(tmp_path):
    protected = [
        '.release/rollback/package.egg-info/PKG-INFO',
        '.release/rollback/__pycache__/original.pyc',
        '.venv/Lib/site-packages/dependency.egg-info/PKG-INFO',
        '.venv/Lib/site-packages/__pycache__/dependency.pyc',
        '.env/Lib/__pycache__/dependency.pyc',
        'build/lib/__pycache__/app.pyc', 'dist/app.egg-info/PKG-INFO',
        'p99_pg16/python/__pycache__/tool.pyc', 'audit_out_local/.coverage.data',
        'tools/runtime/__pycache__/tool.pyc', 'docs/__pycache__/example.pyc',
        'src/app.egg-info/PKG-INFO',
        'src/arenyxa/old.before_release/__pycache__/old.pyc',
        'src/arenyxa/snapshot.bak/__pycache__/old.pyc',
        'src/.release/rollback/__pycache__/old.pyc',
        'src/.venv/__pycache__/dependency.pyc',
        'src/.env/__pycache__/dependency.pyc',
        'tests/build/__pycache__/fixture.pyc',
    ]
    paths = [_write(tmp_path, name) for name in protected]
    _script('phase0_gate').cleanup_ephemeral(tmp_path)
    assert all(path.is_file() and path.read_bytes() == b'preserved original' for path in paths), [
        name for name, path in zip(protected, paths) if not path.is_file()
    ]


def test_cleanup_does_not_follow_linked_source_directory(tmp_path):
    project = tmp_path / 'project'
    external = tmp_path / 'external'
    original = _write(external, '__pycache__/preserved.pyc')
    linked_source = project / 'src'
    project.mkdir()
    if os.name == 'nt':
        subprocess.run(['cmd.exe', '/c', 'mklink', '/J', str(linked_source), str(external)],
                       check=True, capture_output=True)
    else:
        linked_source.symlink_to(external, target_is_directory=True)
    _script('phase0_gate').cleanup_ephemeral(project)
    assert original.read_bytes() == b'preserved original'
    assert linked_source.is_dir()


def _manifest(root, names):
    rows = [hashlib.sha256((root / name).read_bytes()).hexdigest() + '  ' + name for name in names]
    (root / 'SOURCE_MANIFEST.sha256').write_text('\n'.join(rows) + '\n', encoding='utf-8')


def test_phase0_manifest_ignores_preserved_local_evidence_without_changing_it(tmp_path):
    _write(tmp_path, 'src/app.py')
    preserved = [_write(tmp_path, name) for name in (
        '.release/rollback/app.py', 'p99_pg16/data/pg_version',
        'audit_out_local/report.json', 'PUBLIC_SOURCE_SANITIZATION_REPORT.md',
        'src/app.py.before_fix',
    )]
    _manifest(tmp_path, ['src/app.py'])
    result = _script('verify_phase0_baseline').verify_source_manifest(tmp_path)
    assert result['files'] == 1
    assert all(path.read_bytes() == b'preserved original' for path in preserved)


@pytest.mark.parametrize('change', ['modified', 'missing', 'untracked'])
def test_phase0_manifest_still_rejects_real_source_inventory_damage(tmp_path, change):
    source = _write(tmp_path, 'src/app.py')
    _manifest(tmp_path, ['src/app.py'])
    if change == 'modified':
        source.write_bytes(b'changed source')
    elif change == 'missing':
        source.unlink()
    else:
        _write(tmp_path, 'src/new.py')
    with pytest.raises(RuntimeError, match='hash mismatch|missing file|not an exact inventory'):
        _script('verify_phase0_baseline').verify_source_manifest(tmp_path)


def test_phase0_clean_tree_local_mode_preserves_and_ignores_local_evidence(tmp_path):
    originals = [_write(tmp_path, name) for name in (
        '.release/rollback/__pycache__/original.pyc',
        'p99_tools/.venv/Lib/driver.egg-info/PKG-INFO',
        'audit_out_local/.coverage.data',
    )]
    verifier = _script('verify_phase0_baseline')
    assert verifier.verify_clean_tree(tmp_path, allow_local_artifacts=True)['forbidden_artifacts'] == 0
    assert all(path.read_bytes() == b'preserved original' for path in originals)
    with pytest.raises(RuntimeError, match='artefacts'):
        verifier.verify_clean_tree(tmp_path)


def test_phase0_clean_tree_still_rejects_source_cache_in_local_mode(tmp_path):
    _write(tmp_path, 'src/arenyxa/__pycache__/app.pyc')
    with pytest.raises(RuntimeError, match='artefacts'):
        _script('verify_phase0_baseline').verify_clean_tree(tmp_path, allow_local_artifacts=True)


def test_phase0_clean_tree_accepts_coverage_configuration(tmp_path):
    _write(tmp_path, '.coveragerc')
    assert _script('verify_phase0_baseline').verify_clean_tree(tmp_path)['forbidden_artifacts'] == 0


def test_phase0_local_mode_accepts_root_tool_cache_without_deleting_it(tmp_path):
    originals = [_write(tmp_path, name) for name in (
        '.pytest_cache/v/cache/nodeids', '.ruff_cache/version/cache',
        '.mypy_cache/version/cache', '.coverage', '.coverage.parallel',
    )]
    verifier = _script('verify_phase0_baseline')
    assert verifier.verify_clean_tree(tmp_path, allow_local_artifacts=True)['forbidden_artifacts'] == 0
    assert all(path.read_bytes() == b'preserved original' for path in originals)
    with pytest.raises(RuntimeError, match='artefacts'):
        verifier.verify_clean_tree(tmp_path)
