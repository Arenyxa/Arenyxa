Arenyxa v6.6beta2 - Windows Repair Center Button Compatibility Hotfix
Date: 2026-08-10

Issue fixed:
  Opening Settings -> Repair Center could fail on Windows + PySide6 6.11.x with:
  'PySide6.QtWidgets.QWidget' object has no attribute 'setDefault'

Root cause:
  RepairSelectionDialog relied on QDialogButtonBox.addButton(text, role) returning a
  concrete QPushButton. On the affected PySide6 Windows runtime the overload result could
  be surfaced through a generic QWidget wrapper.

Fix:
  - Construct concrete QPushButton objects explicitly.
  - Set default/auto-default on the concrete start button.
  - Register the existing button objects with QDialogButtonBox.
  - Add a regression contract test.
  - Rebuild bundled repair seed/manifest and SOURCE_MANIFEST.

Validation:
  343 passed, 6 skipped, 0 failed.
  The skipped tests require a Qt binding unavailable in the Linux review environment.

Apply by copying this overlay into the existing Arenyxa v6.6beta2 source root, preserving
folders and replacing files. Then rebuild the local repair seed/source manifest if your
working tree contains additional local modifications.
