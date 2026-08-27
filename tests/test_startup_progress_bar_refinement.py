from __future__ import annotations

from pathlib import Path

from arenyxa.presentation.startup_motion_math import startup_progress_duration_ms

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "arenyxa"


def test_startup_progress_duration_is_bounded_distance_aware_and_non_regressive() -> None:
    assert startup_progress_duration_ms(10, 10) == 0
    assert startup_progress_duration_ms(80, 40) == 0
    short = startup_progress_duration_ms(10, 15)
    medium = startup_progress_duration_ms(10, 30)
    long = startup_progress_duration_ms(0, 100)
    assert 70 <= short < medium <= long <= 150
    assert startup_progress_duration_ms(-50, 10) == startup_progress_duration_ms(0, 10)
    assert startup_progress_duration_ms(90, 500) == startup_progress_duration_ms(90, 100)


def test_shell_progress_uses_high_resolution_time_driven_motion_without_bootstrap_threading_change() -> None:
    shell = (SRC / "presentation" / "shell_window.py").read_text(encoding="utf-8")
    app = (SRC / "app.py").read_text(encoding="utf-8")

    assert "self._progress_scale = 10" in shell
    assert "self.progress.setRange(0, 100 * self._progress_scale)" in shell
    assert 'self.progress.setFormat("%p%")' in shell
    assert "QVariantAnimation" in shell
    assert "startup_progress_duration_ms" in shell
    assert "phase = smootherstep(float(value))" in shell
    assert "guard.setInterval(duration_ms + 80)" in shell
    assert "_progress_timer" not in shell
    assert "def _advance_progress" not in shell

    # Cosmetic progress must not move bootstrap onto a worker thread or reorder
    # the existing Root/security startup boundary.
    main = app[app.index("def main("):]
    assert "context = bootstrap(" in main
    assert "bootstrap_with_animation(" not in main
    assert main.index("context = bootstrap(") < main.index("_enforce_registered_root_startup(")


def test_shell_progress_reports_real_granular_startup_activity() -> None:
    shell = (SRC / "presentation" / "shell_window.py").read_text(encoding="utf-8")
    bootstrap = (SRC / "bootstrap.py").read_text(encoding="utf-8")

    assert 'QLabel("Arenyxa")' in shell
    assert 'QLabel("Ultimate Architecture · Secure Network Intelligence")' in shell
    assert "layout.setContentsMargins(56, 48, 56, 48)" in shell
    assert "layout.addSpacing(32)" in shell
    assert 'self.state.setText(f"{bounded}% · {label}")' in shell
    assert "self.activity.setText(_startup_activity_hint(label))" in shell

    milestones = (4, 10, 16, 20, 24, 30, 36, 42, 48, 56, 64, 70, 78, 84, 90, 94, 97, 99)
    positions = [bootstrap.index(f"report({milestone},") for milestone in milestones]
    assert positions == sorted(positions)
    assert "Checking Root workstation binding and trust" in bootstrap
    assert "Opening database and validating schema" in bootstrap
    assert "Initializing Security Kernel and local control plane" in bootstrap
    assert "Loading proxy, MITM, plugins, and traffic automation" in bootstrap
    assert "Restoring persisted schedules" in bootstrap
    assert 'shell_window.show_bootstrap_stage(100, "Ready")' in (SRC / "app.py").read_text(encoding="utf-8")


def test_granular_progress_animation_budget_stays_bounded() -> None:
    milestones = (0, 4, 10, 16, 20, 24, 30, 36, 42, 48, 56, 64, 70, 78, 84, 90, 94, 97, 99, 100)
    total = sum(startup_progress_duration_ms(a, b) for a, b in zip(milestones, milestones[1:]))
    # The startup shell may spend a small bounded amount of time making real
    # milestones visible, but cosmetic motion must not add multiple seconds.
    assert total <= 1600
