from __future__ import annotations

from arenyxa.startup_diagnostics import checkpoint, install_early_diagnostics, record_crash

install_early_diagnostics()
checkpoint("BOOT-001-MODULE-ENTRY")

try:
    from arenyxa.app import main

    checkpoint("BOOT-002-APP-IMPORTED")
    _exit_code = main()
    checkpoint("BOOT-099-MAIN-RETURNED", exit_code=_exit_code)
except SystemExit:
    raise
except BaseException as exc:
    record_crash(exc, source="arenyxa.__main__")
    raise

raise SystemExit(_exit_code)
