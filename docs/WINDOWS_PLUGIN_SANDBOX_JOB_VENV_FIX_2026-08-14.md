# Arenyxa v7.0 — Windows Plugin Sandbox Job/Venv Fix

## Symptom

On a Windows source build running from `.venv`, the release-blocking plugin output-budget test could fail with `PLUGIN_EXECUTION_FAILED`, return code `101`, and stderr beginning with `Unable to create process using ...Python311\\python.exe...`.

## Root cause

`PluginSandbox` launched `sys.executable`. In a Windows virtual environment this is a venv redirector executable. Arenyxa immediately assigns the launched process to a Windows Job Object whose default active-process limit is one. The redirector then tries to create the real base Python interpreter; that transient second process is denied by the Job Object, so the redirector exits with code 101 before `plugin_worker.py` starts.

## Fix

- Source mode on Windows launches `sys._base_executable` directly when Arenyxa is running inside a venv. The worker is standard-library-only and remains isolated with `python -I`.
- Frozen builds re-enter the same `Arenyxa.exe` through a hidden `--internal-plugin-worker` dispatch that executes before normal application/runtime initialization. This avoids treating the frozen GUI executable as a general Python interpreter.
- The output-budget regression fixture keeps a 1 KiB output limit and uses the normal 256 MiB memory budget so that it measures output enforcement rather than an unrelated resource limit.

## Verification performed in the development environment

- `tests/test_deep_runtime_resilience.py` + `tests/test_phase3_reliability_resource_governance.py`: 49 passed.
- Python compileall: passed.
- Arenyxa v7.0 release identity gate: passed.
- Source repair seed and source manifest regenerated.

The Windows release-blocking build must still be rerun on a real Windows host; the expected result is that the previous return-code-101 failure disappears and the suite proceeds beyond the output-budget test.
