Arenyxa v6.6beta2 - mypy packaging gate fix

Problem fixed:
- Modern mypy no longer accepts python_version=3.8.
- The previous release gate therefore aborted before pytest/PyInstaller.
- mypy could also follow installed third-party packages such as anyio and reject
  their Python 3.10+ syntax while pretending to target Python 3.8.

New release policy:
1. compileall is blocking.
2. fatal Ruff/Pyflakes checks are blocking.
3. full Ruff is advisory.
4. all Arenyxa runtime source is parsed with Python 3.8 grammar (blocking).
5. mypy uses a dedicated Python 3.11 release config and does not scan site-packages.
6. pytest is blocking.

The real Windows 7/Python 3.8 lane remains available through scripts/test-win7.ps1.
