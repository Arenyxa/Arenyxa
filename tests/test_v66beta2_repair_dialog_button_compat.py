from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPAIR_DIALOG = ROOT / "src" / "arenyxa" / "presentation" / "repair_dialog.py"


def test_repair_dialog_constructs_concrete_push_buttons_before_button_box_registration() -> None:
    





    source = REPAIR_DIALOG.read_text(encoding="utf-8")
    assert 'start = QPushButton(_t(locale, "start"), buttons)' in source
    assert 'cancel = QPushButton(_t(locale, "cancel"), buttons)' in source
    assert 'buttons.addButton(start, QDialogButtonBox.ButtonRole.AcceptRole)' in source
    assert 'buttons.addButton(cancel, QDialogButtonBox.ButtonRole.RejectRole)' in source
    assert 'start = buttons.addButton(_t(locale, "start")' not in source


def test_repair_dialog_module_remains_syntax_valid() -> None:
    ast.parse(REPAIR_DIALOG.read_text(encoding="utf-8"), filename=str(REPAIR_DIALOG))
