from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_qt_wrapper_fallback_never_replaces_native_view_children() -> None:
    source = _read("src/arenyxa/presentation/widgets.py")
    start = source.index("def table_horizontal_header")
    end = source.index("def format_bytes", start)
    helpers = source[start:end]
    assert "table.setHorizontalHeader(" not in helpers
    assert "table.setVerticalHeader(" not in helpers
    assert "table.setSelectionModel(" not in helpers
    assert "QItemSelectionModel(model, table)" not in helpers


def test_navigation_rail_disables_graphics_effect_micro_motion() -> None:
    source = _read("src/arenyxa/presentation/main_window.py")
    block = source[source.index("self.nav = GlassPanel"):source.index("self.nav_layout =", source.index("self.nav = GlassPanel"))]
    assert 'self.nav.setProperty("arenyxa_motion_static", True)' in block


def test_console_runtime_enables_faulthandler_for_native_qt_faults() -> None:
    source = _read("src/arenyxa/app.py")
    assert "import faulthandler" in source
    assert "faulthandler.enable(all_threads=True)" in source
