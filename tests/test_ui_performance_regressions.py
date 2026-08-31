from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROXY = ROOT / "src/arenyxa/presentation/pages/proxy.py"
MITM = ROOT / "src/arenyxa/presentation/pages/mitm_proxy.py"
OPS = ROOT / "src/arenyxa/presentation/main_window_operations.py"


def _method_source(path: Path, class_name: str, method_name: str) -> str:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child.name == method_name:
                    return ast.get_source_segment(source, child) or ""
    raise AssertionError(f"{class_name}.{method_name} not found in {path}")


def test_proxy_repeater_is_offloaded_from_gui_thread() -> None:
    source = _method_source(PROXY, "ProxyPage", "send_repeater")
    assert "run_background(" in source
    assert "self.repeater_send.setEnabled(False)" in source
    assert source.count("self.repeater_send.setEnabled(True)") >= 2
    assert "self.engine.repeat_raw(" in source


def test_proxy_hidden_page_stops_ui_refresh_timer() -> None:
    source = _method_source(PROXY, "ProxyPage", "deactivated")
    assert "self.timer.stop()" in source
    assert "self.timer.start()" not in source


def test_mitm_hidden_page_stops_ui_refresh_timer() -> None:
    source = _method_source(MITM, "MitmInterceptionPage", "deactivated")
    assert "self.timer.stop()" in source
    assert "self.timer.start()" not in source


def test_mitm_flow_model_uses_incremental_sync_instead_of_periodic_full_reset() -> None:
    model_source = _method_source(MITM, "MitmEventModel", "sync")
    refresh_source = _method_source(MITM, "MitmInterceptionPage", "refresh_flows")
    assert "beginInsertRows" in model_source
    assert "beginRemoveRows" in model_source
    assert "self.flow_model.sync(" in refresh_source
    assert "self.flow_model.replace(rows[-10000:])" not in refresh_source


def test_mitm_message_refresh_reuses_polled_events_and_skips_identical_text_rebuilds() -> None:
    runtime_source = _method_source(MITM, "MitmInterceptionPage", "refresh_runtime")
    messages_source = _method_source(MITM, "MitmInterceptionPage", "refresh_messages")
    assert "self.refresh_messages(events)" in runtime_source
    assert "events:" in messages_source
    assert "_last_message_signature" in messages_source


def test_general_user_status_hides_frame_timing_internals() -> None:
    source = _method_source(OPS, "MainWindowOperationsMixin", "refresh_global_status")
    assert "is_general_user(self.context.settings)" in source
    # Detailed frame metrics remain available for advanced/developer surfaces,
    # but the general-user branch must not expose them in its status string.
    branch = source.split("is_general_user(self.context.settings)", 1)[1].split("else:", 1)[0]
    assert "p95" not in branch
    assert "refresh_hz" not in branch


def test_mitm_refresh_detects_new_events_after_engine_history_reaches_fixed_cap() -> None:
    init_source = _method_source(MITM, "MitmInterceptionPage", "__init__")
    runtime_source = _method_source(MITM, "MitmInterceptionPage", "refresh_runtime")
    assert "_last_event_signature" in init_source
    assert "events[-1].sequence" in runtime_source
    assert "len(events) != self._last_event_count" not in runtime_source
