from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

import arenyxa
from arenyxa.domain.errors import ArenyxaError
from arenyxa.platform_compat import (
    LEGACY_RUNTIME,
    MODERN_RUNTIME,
    WindowsVersion,
    select_runtime,
    validate_python_for_runtime,
)
from arenyxa.qt_compat._helpers import QtProxy, class_with_scopes


ROOT = Path(__file__).resolve().parents[1]


def test_release_surface_is_v66_final() -> None:
    assert arenyxa.__version__ == "8.1"
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'version = "8.1.1"' in pyproject
    assert 'requires-python = ">=3.11,<3.14"' in pyproject
    assert "Python 3.8" in (ROOT / "scripts" / "bootstrap-win7.ps1").read_text(encoding="utf-8")
    assert (ROOT / "requirements-win7.txt").is_file()
    assert (ROOT / "packaging" / "arenyxa_win7.spec").is_file()
    assert (ROOT / "packaging" / "installer_win7.iss").is_file()
    assert (ROOT / "scripts" / "bootstrap-win7.ps1").is_file()
    assert (ROOT / "scripts" / "test-win7.ps1").is_file()
    assert (ROOT / "scripts" / "build-win7.ps1").is_file()


def test_runtime_selection_windows7_sp1_is_legacy() -> None:
    runtime = select_runtime(platform_name="nt", win_version=WindowsVersion(6, 1, 7601, 1))
    assert runtime is LEGACY_RUNTIME
    assert runtime.qt_binding == "PySide2"
    assert runtime.reduced_visuals is True
    assert runtime.browser_automation is False
    assert runtime.modern_backdrop is False


def test_runtime_selection_windows7_without_sp1_fails_closed() -> None:
    with pytest.raises(ArenyxaError) as caught:
        select_runtime(platform_name="nt", win_version=WindowsVersion(6, 1, 7600, 0))
    assert caught.value.code == "WINDOWS_7_SP1_REQUIRED"


def test_runtime_selection_rejects_vista() -> None:
    with pytest.raises(ArenyxaError) as caught:
        select_runtime(platform_name="nt", win_version=WindowsVersion(6, 0, 6002, 2))
    assert caught.value.code == "WINDOWS_RUNTIME_UNSUPPORTED"


def test_runtime_selection_old_windows10_uses_legacy_but_1809_is_modern() -> None:
    assert select_runtime(platform_name="nt", win_version=WindowsVersion(10, 0, 17762, 0)) is LEGACY_RUNTIME
    assert select_runtime(platform_name="nt", win_version=WindowsVersion(10, 0, 17763, 0)) is MODERN_RUNTIME


def test_python_contract_is_explicit_per_runtime_and_x64() -> None:
    validate_python_for_runtime(LEGACY_RUNTIME, (3, 8, 20), is_64bit=True)
    validate_python_for_runtime(MODERN_RUNTIME, (3, 11, 0), is_64bit=True)
    validate_python_for_runtime(MODERN_RUNTIME, (3, 13, 99), is_64bit=True)
    with pytest.raises(ArenyxaError) as caught:
        validate_python_for_runtime(LEGACY_RUNTIME, (3, 11, 0), is_64bit=True)
    assert caught.value.code == "PYTHON_RUNTIME_UNSUPPORTED"
    with pytest.raises(ArenyxaError) as caught:
        validate_python_for_runtime(LEGACY_RUNTIME, (3, 8, 20), is_64bit=False)
    assert caught.value.code == "WINDOWS_X64_REQUIRED"


def test_legacy_runtime_parses_with_python38_grammar() -> None:
    failures: list[str] = []
    for path in (ROOT / "legacy" / "win7" / "src").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        try:
            ast.parse(text, filename=str(path), feature_version=(3, 8))
        except SyntaxError as exc:
            failures.append(f"{path.relative_to(ROOT)}:{exc.lineno}: {exc.msg}")
    assert failures == []


def test_legacy_runtime_is_physically_isolated_from_modern_source() -> None:
    manifest = ROOT / "legacy" / "win7" / "LEGACY_RUNTIME.json"
    legacy_package = ROOT / "legacy" / "win7" / "src" / "arenyxa"
    assert manifest.is_file()
    assert legacy_package.is_dir()
    assert (legacy_package / "app.py").is_file()
    spec = (ROOT / "packaging" / "arenyxa_win7.spec").read_text(encoding="utf-8")
    bootstrap = (ROOT / "scripts" / "bootstrap-win7.ps1").read_text(encoding="utf-8")
    test_script = (ROOT / "scripts" / "test-win7.ps1").read_text(encoding="utf-8")
    assert "legacy" in spec and "win7" in spec
    assert "legacy\\win7\\src" in bootstrap
    assert "legacy\\win7\\src" in test_script


def test_modern_runtime_is_not_held_to_python38_source_constraints() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'requires-python = ">=3.11,<3.14"' in pyproject
    assert 'python_version = "3.11"' in pyproject
    for script_name in (
        "phase0_gate.py", "phase1_reliability_gate.py", "phase2_validation_gate.py",
        "phase3_feature_gate.py", "phase4_security_gate.py", "phase8_10_gate.py", "phase11_12_gate.py",
    ):
        script = ROOT / "scripts" / script_name
        if script.is_file():
            assert "check_python38_grammar.py" not in script.read_text(encoding="utf-8")

def test_desktop_source_never_imports_qt_binding_directly() -> None:
    violations: list[str] = []
    qt_root = ROOT / "src" / "arenyxa" / "qt_compat"
    for path in (ROOT / "src" / "arenyxa").rglob("*.py"):
        if qt_root in path.parents or path == qt_root / "__init__.py":
            continue
        text = path.read_text(encoding="utf-8")
        for line_no, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("from PySide") or stripped.startswith("import PySide"):
                violations.append(f"{path.relative_to(ROOT)}:{line_no}: {stripped}")
    assert violations == []



def test_desktop_startup_requires_runtime_specific_qt_binding() -> None:
    app_source = (ROOT / "src" / "arenyxa" / "app.py").read_text(encoding="utf-8")
    assert "active_qt_binding = available_binding_name()" in app_source
    assert "def _handle_qt_binding_preflight" in app_source
    assert "if active_qt_binding == runtime.qt_binding:" in app_source
    assert "if not binding_available()" not in app_source

def test_qt5_scope_proxy_maps_qt6_style_names_without_real_qt() -> None:
    class LegacyQt:
        AlignCenter = 1
        Horizontal = 2

    proxy = QtProxy(
        LegacyQt,
        {
            "AlignmentFlag": {"AlignCenter": "AlignCenter"},
            "Orientation": {"Horizontal": "Horizontal"},
        },
    )
    assert proxy.AlignmentFlag.AlignCenter == 1
    assert proxy.Orientation.Horizontal == 2


def test_qt5_exec_alias_maps_exec_() -> None:
    class LegacyDialog:
        Accepted = 1

        def exec_(self):
            return self.Accepted

    adapted = class_with_scopes(
        LegacyDialog,
        {"DialogCode": {"Accepted": "Accepted"}},
        ensure_exec=True,
    )
    assert adapted().exec() == 1
    assert adapted.DialogCode.Accepted == 1


def test_qt5_dialog_button_box_scope_exposes_ok_for_developer_consent() -> None:
    source = (ROOT / "src" / "arenyxa" / "qt_compat" / "QtWidgets.py").read_text(encoding="utf-8")
    assert '"Ok":"Ok"' in source


def test_legacy_packaging_excludes_modern_qt_and_browser_runtime() -> None:
    spec = (ROOT / "packaging" / "arenyxa_win7.spec").read_text(encoding="utf-8")
    req = (ROOT / "requirements-win7.txt").read_text(encoding="utf-8")
    installer = (ROOT / "packaging" / "installer_win7.iss").read_text(encoding="utf-8")
    assert "PySide2.QtCore" in spec and '"PySide6"' in spec
    assert "playwright" in spec
    assert "PySide2.QtWebEngineCore" in spec
    assert "PySide2.QtWebEngineWidgets" in spec
    assert "PySide2==5.15.2.1" in req
    assert "backports.zoneinfo==0.2.1" in req
    assert "MinVersion=6.1sp1" in installer


def test_python38_executor_shutdown_fallback_omits_cancel_futures(monkeypatch: pytest.MonkeyPatch) -> None:
    import arenyxa.compat as compat

    calls: list[bool] = []

    class LegacyExecutor:
        def shutdown(self, wait: bool) -> None:
            calls.append(wait)

    monkeypatch.setattr(compat, "sys", SimpleNamespace(version_info=(3, 8, 20)))
    compat.shutdown_executor(LegacyExecutor(), wait=False, cancel_futures=True)
    assert calls == [False]


def test_cancel_futures_keyword_isolated_to_compat_layer() -> None:
    violations: list[str] = []
    for path in (ROOT / "src" / "arenyxa").rglob("*.py"):
        if path.name == "compat.py":
            continue
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if any(keyword.arg == "cancel_futures" for keyword in node.keywords):
                                                                                             
                func = node.func
                if isinstance(func, ast.Name) and func.id == "shutdown_executor":
                    continue
                violations.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert violations == []


def test_module_level_type_aliases_avoid_python39_builtin_generics() -> None:
    
    builtin_generic_names = {"list", "dict", "set", "tuple", "frozenset", "type"}
    collections_generic_names = {
        "Callable", "Iterable", "Iterator", "Mapping", "MutableMapping", "Sequence",
        "MutableSequence", "Set", "MutableSet", "Generator", "Collection", "Container",
    }
    violations: list[str] = []
    for path in (ROOT / "src" / "arenyxa").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text)
        for statement in tree.body:
            if not isinstance(statement, ast.Assign):
                continue
            for node in ast.walk(statement.value):
                if not isinstance(node, ast.Subscript):
                    continue
                value = node.value
                if isinstance(value, ast.Name) and value.id in builtin_generic_names:
                    violations.append(f"{path.relative_to(ROOT)}:{node.lineno}:{value.id}")
                elif (
                    isinstance(value, ast.Attribute)
                    and isinstance(value.value, ast.Attribute)
                    and isinstance(value.value.value, ast.Name)
                    and value.value.value.id == "collections"
                    and value.value.attr == "abc"
                    and value.attr in collections_generic_names
                ):
                    violations.append(f"{path.relative_to(ROOT)}:{node.lineno}:collections.abc.{value.attr}")
    assert violations == []


def test_legacy_bootstrap_is_windows7_and_powershell2_safe() -> None:
    bootstrap = (ROOT / "scripts" / "bootstrap-win7.ps1").read_text(encoding="utf-8")
    assert "KB2533623" in bootstrap
    assert "SetDefaultDllDirectories" in bootstrap
    assert "GetProcAddress" in bootstrap
    assert "Get-HotFix -Id KB2533623" not in bootstrap
    assert "ServicePackMajorVersion" in bootstrap
    assert "PROCESSOR_ARCHITECTURE" in bootstrap
    assert "*>" not in bootstrap
    assert "Is64BitOperatingSystem" not in bootstrap
    assert "pip==24.3.1" in bootstrap
    assert "setuptools==75.3.2" in bootstrap
    assert "wheel==0.45.1" in bootstrap
    assert (ROOT / "scripts" / "run-win7.ps1").is_file()


def test_all_win7_powershell_scripts_avoid_post_v2_only_surface() -> None:
    forbidden = (
        "$PSScriptRoot",                                                                                      
        "*>",                                                                       
        "ForEach-Object -Parallel",
        "??",
        "?.",
        "::new(",
    )
    violations: list[str] = []
    for path in sorted((ROOT / "scripts").glob("*win7.ps1")):
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            if token in text:
                violations.append(f"{path.relative_to(ROOT)} -> {token}")
    assert violations == []


def test_legacy_security_and_packager_pins_match_win7_compatibility_window() -> None:
    runtime = (ROOT / "requirements-win7.txt").read_text(encoding="utf-8")
    dev = (ROOT / "requirements-dev-win7.txt").read_text(encoding="utf-8")
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "cryptography==42.0.7" in runtime
    assert "cryptography>=50,<51" in pyproject
    assert "pyinstaller==4.10" in dev
    assert "pyinstaller-hooks-contrib==2024.4" in dev
    assert "pyinstaller>=6.11,<7" in pyproject


def test_python38_source_avoids_parenthesized_with_statement_extension() -> None:
    
    import re

    violations: list[str] = []
    pattern = re.compile(r"(?m)^\s*with\s*\(")
    for path in (ROOT / "src" / "arenyxa").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            violations.append(f"{path.relative_to(ROOT)}:{line}")
    assert violations == []


def test_python38_runtime_expressions_avoid_builtin_pep585_generics() -> None:
    
    builtin_generic_names = {"list", "dict", "set", "tuple", "frozenset", "type"}
    violations: list[str] = []

    for path in (ROOT / "src" / "arenyxa").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text)
        parents: dict[ast.AST, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent

        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Subscript)
                and isinstance(node.value, ast.Name)
                and node.value.id in builtin_generic_names
            ):
                continue
            current: ast.AST = node
            annotation_safe = False
            while current in parents:
                parent = parents[current]
                if isinstance(parent, ast.AnnAssign):
                    if any(item is node for item in ast.walk(parent.annotation)):
                        annotation_safe = True
                    break
                if isinstance(parent, ast.arg):
                    if parent.annotation is not None and any(item is node for item in ast.walk(parent.annotation)):
                        annotation_safe = True
                    break
                if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if parent.returns is not None and any(item is node for item in ast.walk(parent.returns)):
                        annotation_safe = True
                    break
                current = parent
            if not annotation_safe:
                violations.append(
                    f"{path.relative_to(ROOT)}:{node.lineno}:"
                    f"{ast.get_source_segment(text, node) or node.value.id}"
                )
    assert violations == []


def test_python38_runtime_expressions_avoid_collections_abc_pep585_generics() -> None:
    
    generic_names = {
        "Awaitable", "Coroutine", "AsyncIterable", "AsyncIterator", "AsyncGenerator",
        "Iterable", "Iterator", "Generator", "Reversible", "Container", "Collection",
        "Callable", "Set", "MutableSet", "Mapping", "MutableMapping", "Sequence",
        "MutableSequence", "ByteString", "MappingView", "KeysView", "ItemsView", "ValuesView",
    }
    violations: list[str] = []
    for path in (ROOT / "src" / "arenyxa").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text)
        imported: set[str] = set()
        for statement in tree.body:
            if isinstance(statement, ast.ImportFrom) and statement.module == "collections.abc":
                imported.update(
                    alias.asname or alias.name
                    for alias in statement.names
                    if alias.name in generic_names
                )
        if not imported:
            continue
        parents: dict[ast.AST, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Subscript)
                and isinstance(node.value, ast.Name)
                and node.value.id in imported
            ):
                continue
            current: ast.AST = node
            annotation_safe = False
            while current in parents:
                parent = parents[current]
                if isinstance(parent, ast.AnnAssign):
                    if any(item is node for item in ast.walk(parent.annotation)):
                        annotation_safe = True
                    break
                if isinstance(parent, ast.arg):
                    if parent.annotation is not None and any(item is node for item in ast.walk(parent.annotation)):
                        annotation_safe = True
                    break
                if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if parent.returns is not None and any(item is node for item in ast.walk(parent.returns)):
                        annotation_safe = True
                    break
                current = parent
            if not annotation_safe:
                violations.append(
                    f"{path.relative_to(ROOT)}:{node.lineno}:"
                    f"{ast.get_source_segment(text, node) or node.value.id}"
                )
    assert violations == []


def test_python38_builtin_zip_strict_is_isolated_to_compat_layer() -> None:
    violations: list[str] = []
    for path in (ROOT / "src" / "arenyxa").rglob("*.py"):
        if path.name == "compat.py":
            continue
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            if node.func.id == "zip" and any(keyword.arg == "strict" for keyword in node.keywords):
                violations.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert violations == []


def test_python38_strict_zip_fallback_preserves_length_check(monkeypatch: pytest.MonkeyPatch) -> None:
    import arenyxa.compat as compat

    monkeypatch.setattr(compat, "sys", SimpleNamespace(version_info=(3, 8, 20)))
    assert list(compat.strict_zip([1, 2], [3, 4], strict=True)) == [(1, 3), (2, 4)]
    with pytest.raises(ValueError):
        list(compat.strict_zip([1], [2, 3], strict=True))
    assert list(compat.strict_zip([1], [2, 3], strict=False)) == [(1, 2)]



def test_qt5_facade_covers_all_scoped_enum_references_in_presentation() -> None:
    
    facade_files = (
        ROOT / "src" / "arenyxa" / "qt_compat" / "QtCore.py",
        ROOT / "src" / "arenyxa" / "qt_compat" / "QtGui.py",
        ROOT / "src" / "arenyxa" / "qt_compat" / "QtWidgets.py",
    )
    covered: set[tuple[str, str, str]] = set()
    for path in facade_files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for statement in tree.body:
            if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
                continue
            target = statement.targets[0]
            if not isinstance(target, ast.Name) or not isinstance(statement.value, ast.Call):
                continue
            call = statement.value
            if not isinstance(call.func, ast.Name) or call.func.id not in {"QtProxy", "class_with_scopes"}:
                continue
            if len(call.args) < 2 or not isinstance(call.args[1], ast.Dict):
                continue
            for scope_key, members_node in zip(call.args[1].keys, call.args[1].values):
                if not isinstance(scope_key, ast.Constant) or not isinstance(scope_key.value, str):
                    continue
                if not isinstance(members_node, ast.Dict):
                    continue
                for member_key in members_node.keys:
                    if isinstance(member_key, ast.Constant) and isinstance(member_key.value, str):
                        covered.add((target.id, scope_key.value, member_key.value))

    missing: list[str] = []
    presentation = ROOT / "src" / "arenyxa" / "presentation"
    for path in presentation.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text)
        qt_imports: set[str] = set()
        for statement in tree.body:
            if not isinstance(statement, ast.ImportFrom) or statement.module is None:
                continue
            if not statement.module.startswith("arenyxa.qt_compat."):
                continue
            qt_imports.update(alias.asname or alias.name for alias in statement.names)
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Attribute)
                and isinstance(node.value.value, ast.Name)
                and node.value.value.id in qt_imports
            ):
                continue
            key = (node.value.value.id, node.value.attr, node.attr)
            if key not in covered:
                missing.append(
                    f"{path.relative_to(ROOT)}:{node.lineno}:"
                    f"{key[0]}.{key[1]}.{key[2]}"
                )
    assert missing == []
