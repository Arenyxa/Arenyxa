from pathlib import Path

from arenyxa import __compat_version__, __package_version__, __version__
from arenyxa.architecture_contracts import (
    COMPATIBILITY_CONTRACTS,
    CORE_COMPONENTS,
    FAILURE_RULES,
    LIFECYCLE_SEQUENCE,
    component,
    lifecycle_is_ordered,
    validate_dependency_rules,
)


def test_phase1_core_runtime_has_explicit_owners_and_boundaries() -> None:
    expected = {"run", "workflow", "dataset", "capture", "recovery", "plugin", "storage", "ui_shell"}
    assert {item.key for item in CORE_COMPONENTS} == expected
    for item in CORE_COMPONENTS:
        assert item.owner
        assert item.module_prefixes
        assert item.inputs
        assert item.outputs
        assert item.lifecycle
        assert item.failure_boundary
        assert item.may_depend_on


def test_phase1_lifecycle_contract_is_ordered_and_pause_resume_repeatable() -> None:
    assert LIFECYCLE_SEQUENCE == (
        "create", "start", "pause", "resume", "terminal", "persist", "recover", "dispose"
    )
    assert lifecycle_is_ordered(["create", "start", "pause", "resume", "pause", "resume", "terminal", "persist", "recover", "dispose"])
    assert not lifecycle_is_ordered(["create", "start", "terminal", "resume"])
    assert component("run").lifecycle == LIFECYCLE_SEQUENCE


def test_phase1_failure_model_is_explicit_and_fail_closed() -> None:
    by_category = {item.category: item for item in FAILURE_RULES}
    assert set(by_category) == {"transient", "recoverable", "configuration", "permission", "corruption", "fatal"}
    assert by_category["transient"].retryable is True
    assert by_category["permission"].disposition == "reject"
    assert by_category["corruption"].rollback_required is True
    assert by_category["fatal"].disposition == "terminate"
    assert all(item.invariant for item in FAILURE_RULES)


def test_phase1_dependency_direction_gate_passes_current_core() -> None:
    root = Path(__file__).resolve().parents[1]
    assert validate_dependency_rules(root / "src") == []


def test_phase1_compatibility_contract_freezes_legacy_surface() -> None:
    assert __version__ == "8.1"
    assert __package_version__ == "8.1.0"
    assert __compat_version__ == "6.8.0"
    names = {(item.name, item.kind, item.compatibility_level) for item in COMPATIBILITY_CONTRACTS}
    assert ("arenyxa", "python-package", "8.1") in names
    assert ("arenyxa", "legacy-python-package", "8.1") in names
    assert ("plugin-api", "plugin", "6.8.0") in names
    pyproject = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    assert 'arenyxa = "arenyxa.cli:main"' in pyproject
    assert 'arenyxa-gui = "arenyxa.app:main"' in pyproject
