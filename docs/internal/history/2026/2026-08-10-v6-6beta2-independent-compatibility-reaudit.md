# Arenyxa V6.6beta2 — Independent Compatibility Re-audit (2026-08-10)

## Scope

This release is a fresh audit of the V6.6.1 Windows 7 Legacy Enterprise codebase. It does not assume that the prior six review passes were complete. The re-audit separately checks Python 3.8 runtime semantics, Qt5/Qt6 isolation, Windows 7 / PowerShell 2 bootstrap constraints, scheduler generation consistency, Runner shutdown behavior, source-repair integrity, packaging metadata, and repeated process-exit behavior.

## Compatibility defects found after V6.6.1

1. Several evaluated `typing.cast(...)` expressions used PEP 585 built-in generics such as `dict[str, Any]` / `list[...]`. Postponed annotations do not defer evaluation of ordinary call arguments, so those branches can fail under CPython 3.8 even when the module parses on a modern interpreter.
2. A capture/TLS path used a parenthesized multi-context `with (...)` statement. This syntax is not part of the Python 3.8 grammar used by the Legacy lane.
3. Several modules called built-in `zip(..., strict=True/False)`. The `strict` keyword is newer than Python 3.8. These calls now go through `arenyxa.compat.strict_zip`, whose Python 3.8 path preserves lazy iteration and strict equal-length validation.
4. A runtime type expression imported `Callable` from `collections.abc` and subscribed it. Runtime subscription of these ABCs is newer than the Legacy interpreter contract. Evaluated types now use `typing.Callable` / `typing.List` / `typing.Dict` where required.

## Concurrency defects found

### Scheduler stale-generation writeback

A callback belonging to an older schedule definition could finish after that schedule had been replaced or toggled off/on. Without an explicit generation identity, the old callback could persist `last_run_at` / `next_run` into the newer definition. V6.6beta2 assigns every definition a monotonically increasing generation and verifies the captured generation before callback dispatch completion and durable writes.

The completion path also persists the current in-memory next deadline. This prevents a long-running callback from overwriting an overlap-advanced deadline with an older dispatched deadline.

### Runner shutdown/request-submit race

`request_executor.submit()` can race with non-blocking orchestrator shutdown after a request has passed an earlier cancellation checkpoint. When the executor rejects that submission because shutdown is intentional, V6.6beta2 maps the run to `CANCELLED` rather than misclassifying the teardown as an unexpected `FAILED` run.

## Added regression gates

- Python 3.8 source parse gate.
- parenthesized `with (` source rejection in the shared Legacy tree.
- evaluated PEP 585 built-in generic rejection outside postponed annotations.
- evaluated `collections.abc` subscription rejection outside postponed annotations.
- direct `zip(strict=...)` isolation to the compatibility helper.
- strict-zip fallback behavior test.
- all `*win7.ps1` scripts reject post-PowerShell-2-only surfaces used by this project, including `$PSScriptRoot`.
- stale Scheduler generation cannot mark or reschedule a replacement definition.
- callback completion cannot overwrite a disable/re-enable generation.
- intentional executor-shutdown submission race finishes as cancellation.

## Additional defects found during the second-stage audit

### SQLite connection lifetime

`ExperienceStore` previously relied on `with sqlite3.Connection`, which controls transaction commit/rollback but does not close the connection. The Legacy/enterprise workload can therefore defer handle release to garbage collection. Its connection factory is now a real context manager that always closes in `finally`.

`SQLiteStore.connect()` also had an initialization-failure leak: if a PRAGMA failed after the connection object was created (for example while scanning a corrupt database), the connection was never returned to the caller and therefore could not be closed by the caller's context manager. Connection setup now closes on every exception before re-raising. Both paths have deterministic ResourceWarning regression coverage.

### Fail-closed Qt binding selection

Desktop startup now requires the Qt binding selected by the active runtime contract instead of accepting any installed PySide generation. Legacy requires PySide2 and Modern requires PySide6. A mismatched Qt major version enters dependency repair instead of silently falling through to an incompatible binding.

### Windows loader capability detection

The Win7 bootstrap no longer treats `Get-HotFix -Id KB2533623` as the source of truth. Enterprise images may contain the required loader functionality through a superseding cumulative update. The bootstrap now probes Kernel32 for `SetDefaultDllDirectories` through `GetProcAddress` and rejects the host only when the required loader capability is actually absent.

### Distribution metadata consistency

`Requires-Python` now excludes Python 3.9 and 3.10 (`>=3.8,<3.14,!=3.9.*,!=3.10.*`) so package installation metadata agrees with the runtime contract: Python 3.8.x is the Legacy lane, while Python 3.11-3.13 is the Modern lane.

## Expanded compatibility gates

- Independent Python 3.8 grammar reparse now covers `src`, `scripts`, and `tests`, not only application sources.
- Qt6 scoped-enum usages in Presentation are statically reconciled against the Qt5 compatibility mapping.
- Resource-lifetime tests run with `ResourceWarning` promoted to an error; corrupt-database and Autopilot paths additionally force garbage collection to expose delayed leaks.
- Win7 bootstrap tests verify loader capability probing rather than brittle hotfix-inventory matching.
- Runtime-specific Qt binding selection has a dedicated startup contract test.

## Review-environment limits

The re-audit environment is not a Windows 7 machine and does not contain a native CPython 3.8 + PySide2 GUI runtime. Static Python 3.8 grammar/runtime-expression gates, package constraints and modern-host regression tests materially reduce compatibility risk, but they are not a substitute for native Windows 7 SP1 x64 certification. A final Legacy binary release still requires the repository-provided Win7 bootstrap/test/build path to be run on Windows 7 SP1 x64 with the required Microsoft loader update and then exercised as a packaged GUI/EXE/installer.


## First frozen full-suite gate

After the compatibility/concurrency changes and integrity-resource regeneration, the isolated full suite completed with **310 passed, 6 skipped, 0 failed** in **27.42 seconds** and the pytest process exited normally. The six skips are GUI smoke tests because the Linux review environment has no supported PySide binding; they are not assertion failures. This was an intermediate frozen gate; final post-documentation results are recorded in the QA report and release artifacts after Repair Seed / source-manifest regeneration.

## Final frozen verification

- Resource-lifetime full gate: **312 passed / 6 skipped / 0 failed / Exit 0**.
- Ordinary full gate: **312 passed / 6 skipped / 0 failed / Exit 0**.
- Six high-risk Scheduler/Runner race tests: **10 consecutive rounds passed**.
- Python 3.8 grammar reparse: `src` 84/84, `scripts` 5/5, `tests` 41/41; zero parse-error files.
- Direct PySide binding imports outside `qt_compat`: 0. Direct `zip(strict=...)` outside `compat.strict_zip`: 0.

Native Windows 7 certification remains intentionally separate from these host-independent gates.
