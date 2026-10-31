Arenyxa v6.6beta2 - Windows Direct Terminal Test Quoting Fix

Fixes the Windows-only pytest failure in:
  tests/test_terminal_hardening.py::test_direct_process_streams_output_and_reports_exit

Root cause:
  The test helper used shlex.quote(), which emits POSIX shell quoting. Arenyxa Direct mode
  on Windows does not invoke a POSIX shell, so the generated `python -c` payload could be
  split incorrectly and arrive at Python as a truncated expression such as `print(`.

Fix:
  - Windows: construct the command line with subprocess.list2cmdline().
  - POSIX: retain shlex.quote().
  - No production TerminalSession behavior is changed by this overlay.
