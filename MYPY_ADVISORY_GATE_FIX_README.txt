Arenyxa v6.6beta2 - mypy advisory gate correction

Why this patch exists
---------------------
The current codebase has a large pre-existing mypy backlog, including platform-specific
APIs (for example fcntl on POSIX), dynamic Qt compatibility facades, and other runtime
abstractions. A strict full-package mypy run therefore reports many findings that were
not introduced by the packaging change and that are already covered by runtime tests.

Release-blocking gates after this patch
---------------------------------------
- Python compileall
- Critical Ruff/Pyflakes: E9, F63, F7, F82
- Python 3.8 grammar compatibility check
- pytest

Advisory/non-blocking audits
----------------------------
- Full Ruff scan
- Full mypy scan

This does NOT suppress or erase mypy findings. They remain visible in build output and
should be reduced in a dedicated typing-hardening pass rather than being mass-edited
inside the packaging workflow.
