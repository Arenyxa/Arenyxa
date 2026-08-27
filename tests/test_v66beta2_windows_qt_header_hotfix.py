from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "arenyxa"


def test_table_pages_do_not_chain_header_specific_calls_on_default_wrapper() -> None:
    pages = sorted((SRC / "presentation" / "pages").glob("*.py"))
    for path in pages:
        source = path.read_text(encoding="utf-8")
        assert ".horizontalHeader().setSectionResizeMode" not in source, path
        assert ".horizontalHeader().setStretchLastSection" not in source, path


def test_header_helper_degrades_without_replacing_qt_owned_children() -> None:
    source = (SRC / "presentation" / "widgets.py").read_text(encoding="utf-8")
    assert "def table_horizontal_header(table: Any) -> Any:" in source
    assert 'getattr(header, "setSectionResizeMode", None)' in source
    assert 'getattr(header, "setStretchLastSection", None)' in source
    assert "table.setHorizontalHeader(" not in source
    assert "table.setVerticalHeader(" not in source
    assert "table.setSelectionModel(" not in source
    assert "QHeaderView(Qt.Orientation.Horizontal, table)" not in source


def test_motion_effect_updates_are_guarded_against_deleted_cpp_objects() -> None:
    source = (SRC / "presentation" / "motion.py").read_text(encoding="utf-8")
    assert "valueChanged.connect(lambda value: effect.setOpacity" not in source
    assert "valueChanged.connect(lambda value: effect.setStrength" not in source
    assert source.count("except RuntimeError:") >= 8
