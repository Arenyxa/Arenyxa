# Arenyxa v8.0 Startup Repair Final Report

## Scope

This source package keeps the approved Arenyxa startup splash and its centered indeterminate progress element unchanged. The repair focuses only on the startup control path, dependency recovery, Qt binding detection, and main-window lifetime.

## Fixed issues

1. **Dependency repair loop**
   - `requirements.txt` now contains the source-mode runtime dependencies used by Repair Center.
   - Source-mode automatic dependency repair can restore `PySide6`, `lxml`, `cssselect`, `dnspython`, `openpyxl`, and related runtime support instead of flashing a terminal and exiting without fixing the missing modules.

2. **Partial Qt installation detection**
   - `available_binding_name()` now verifies that the Qt binding is actually importable, not merely discoverable through package metadata.
   - `StartupHealthScanner` and `RepairEngine` now treat native import failures as missing dependencies.

3. **Startup frame flash / premature event-loop exit**
   - `QApplication` no longer exits just because a transient startup or welcome surface closes before the shell commits the main workspace.
   - The shell window owns explicit process shutdown.
   - The `QApplication` object keeps strong references to the shell, main window, context, single-instance server, data-root lease, and finalizer for the lifetime of the event loop.

4. **Recovery UI clarity**
   - The pre-Qt native Repair Center prompt now includes concrete diagnostic details: category, code, title, detail, and evidence.

## Preserved behavior

- Startup splash visual design: preserved.
- Center progress element: preserved.
- Repair Worker architecture: preserved.
- Full Qt Repair Dialog path: preserved.
- v8.0 stable identity: preserved.

## Local verification performed

- `python -m compileall -q src scripts tests`
- `python scripts/verify_v80_release_identity.py`
- `python scripts/workflow_contract_gate.py`
- `python scripts/quality_20d_gate.py`
- `python scripts/architecture_debt_gate.py`
- `python scripts/hot_path_memory_gate.py`
- `python scripts/v8_acceptance_gate.py`
- `python scripts/verify_phase0_baseline.py`
- `pytest -q tests/test_repair_center.py tests/test_workflow_contract_gate.py`

Environment-specific Windows native, Npcap/tshark, PostgreSQL, and 24-hour soak certifications remain external validation items.
