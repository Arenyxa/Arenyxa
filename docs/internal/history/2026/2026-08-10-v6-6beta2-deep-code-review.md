# Arenyxa v6.6beta2 — Deep Code Review & Stability Hardening

Date: 2026-08-10
Release identity: **Arenyxa v6.6beta2**
Python package version: **6.6b2** (PEP 440)
Plugin compatibility version: **6.6.2** (numeric compatibility comparator only)

## 1. Review objective

This review continues from the independently hardened v6.6 code line and treats v6.6beta2 as a beta-quality stabilization release rather than a feature-only increment. The review focuses on failure atomicity, lifecycle serialization, shutdown ordering, crash recovery, cross-process ownership, SQLite durability, plugin isolation, capture child-process cleanup, terminal process identity, Windows 7 legacy compatibility boundaries, and release/version consistency.

The review intentionally searches beyond existing green tests. Particular attention is paid to interleavings that are difficult to reproduce in normal UI testing: start/stop overlap, a child process exiting before its reader thread finishes, repair hand-off while another runtime launches, a second process acquiring the data root during shutdown, permission-denied process enumeration, and partial subprocess startup.

## 2. High-impact findings fixed in v6.6beta2

### 2.1 CaptureController start/stop race — fixed

**Risk:** High. `CaptureController.start()` and `stop()` did not originally share one lifecycle mutex. A stop request could interleave after writer creation but before the adapter finished starting; the original start path could then continue and start an adapter after the session had already been finalized.

**Fix:** A re-entrant lifecycle lock now serializes prepare/start/pause/resume/stop. Adapter-start failure rolls the session back through one lifecycle boundary. This prevents a logical STOPPED/CANCELLED session from resurrecting an underlying capture source.

### 2.2 Paused capture stop could discard synchronous tail events — fixed

**Risk:** Medium. Some adapters emit final metadata synchronously while `adapter.stop()` drains buffers. When the session was PAUSED, the generic emit gate rejected those final events.

**Fix:** Stop opens a narrow, explicit tail-acceptance window only while the adapter is being stopped. Ordinary PAUSED capture still rejects incoming events. Final counters and durable capture records therefore include adapter tail data without reopening general capture.

### 2.3 Terminal process-slot reuse race — fixed

**Risk:** High. A child can exit before its reader thread finishes draining stdout and committing `TerminalResult`. The old code could allow a new process to reuse the shared slot in that gap. The older reader could then set the newer run's completion event or observe newer cancellation/timing state.

**Fix:** A terminal slot cannot be reused until reader cleanup sets `_process` back to `None`. Reader finalization is process-identity guarded and uses the run-local start time. Old reader callbacks cannot commit state for a replacement process.

### 2.4 QApplication quit ordering could release DataRootLease too early — fixed

**Risk:** High. `aboutToQuit` previously had a direct path that could release the cross-process data-root lock before every runtime service had been shut down when quitting outside the normal `MainWindow.closeEvent` path.

**Fix:** Runtime finalization is now idempotent and ordered: freeze UI background work, shut down `ApplicationContext`, remove the crash marker, then release `DataRootLease` last. The event-loop `finally` repeats the same idempotent finalizer as a final safety boundary.

### 2.5 Repair worker data-root ownership gap — fixed

**Risk:** Critical for repair integrity. Waiting for the parent PID to exit did not guarantee ownership of the data root. A user could manually launch a new Desktop/Server runtime in the gap while Repair Center modified SQLite, settings, cache, plugin state or recovery files.

**Fix:** `RepairEngine` now acquires the same OS-level `DataRootLease` as Desktop/Headless before it creates repair logs/backups or mutates shared data. If exclusive ownership cannot be obtained within the bounded acquisition window, repair safely cancels without mutation.

### 2.6 Packaged repair program-file phase was outside DataRootLease — fixed with two-phase repair ownership

**Risk:** Critical. The packaged PowerShell worker can restore program files before the Python repair engine reaches its DataRootLease acquisition. A newly launched runtime therefore needed a separate exclusion signal covering the entire external-repair phase.

**Fix:** Repair launch now performs an atomic two-phase ownership hand-off:

1. Parent writes `repair_in_progress.json` with its own PID in `handoff` state **before** child spawn.
2. Child is spawned.
3. Marker is atomically rewritten with the worker PID in `active` state.
4. Desktop and Headless Server refuse startup while an active/fresh hand-off marker exists.
5. The no-Qt startup-repair lane additionally obtains `DataRootLease` before scanning/preparing repair, so a broken GUI dependency cannot bypass Server/Desktop exclusion.
6. If child spawn succeeds but marker ownership update fails, the child is terminated and the marker is removed; launch is failure-atomic.
7. When program-file and data repair complete, the marker is cleared before controlled relaunch. Dead-worker markers are treated as stale and cleaned conservatively; a fresh parent-to-worker hand-off fails closed for a short grace window.

### 2.7 Plugin isolated worker could not import sibling modules — fixed

**Risk:** Medium/High functional regression. Plugin workers run with Python `-I` for isolation, but that also removed the plugin directory from ordinary import resolution. Multi-file plugins using `import helper` could fail even though the helper lived inside the validated plugin root.

**Fix:** After the audit hook is installed, the validated plugin root is appended behind system/stdlib paths. Plugins can import sibling modules while the permission audit boundary remains active.

### 2.8 Process network attribution could turn permission denial into capture failure — fixed

**Risk:** Medium, especially on Windows 7/10 enterprise endpoints. `psutil.net_connections()` can raise `psutil.AccessDenied` for ordinary users or hardened policy environments. The old fallback did not catch psutil's own exception base class.

**Fix:** Process attribution catches `psutil.Error` plus OS/permission failures and falls back to bounded `netstat`. `netstat` has a hard timeout and failure returns an empty attribution snapshot. Missing process attribution is now diagnostic degradation, not a capture-chain failure.

### 2.9 tshark/dumpcap partial startup could orphan dumpcap — fixed

**Risk:** High for system capture. With raw pcap enabled, `dumpcap` was started before `tshark`. If `tshark` spawn failed, `dumpcap` could continue running and writing capture files even though adapter startup had failed.

**Fix:** System-capture startup is transactional. Every child started during initialization is tracked. Any later startup exception terminates and waits for already-started children, escalates to kill when required, clears handles, and re-raises. Reader-thread startup failure also routes through bounded normal shutdown.

### 2.10 Repair-time pip operations were unbounded — fixed

**Risk:** Medium. Dependency self-repair used `subprocess.run()` without a timeout, allowing a broken package index, proxy or network stack to leave Repair Center stuck indefinitely.

**Fix:** Core dependency repair and optional psutil repair now use explicit bounded timeouts. Optional psutil timeout is recorded as an unresolved capability rather than blocking the rest of repair.

### 2.11 Source manifest accidentally captured local coverage state — fixed

**Risk:** High for clean-source delivery. The source-manifest generator excluded common cache/build directories but did not exclude `.coverage`. A developer/audit workspace containing that ephemeral file could generate a manifest that passed locally yet failed immediately after the clean source ZIP was extracted.

**Fix:** Manifest generation now excludes `.coverage`, `.coverage.*`, `coverage.xml`, htmlcov, pytest/mypy/ruff/hypothesis/tox/nox caches, bytecode, build/dist output and egg-info. A clean-source extraction regression run is part of the release gate so local audit artifacts cannot become hidden distribution dependencies.

### 2.12 Public release identity drift (`6.6.2` vs `6.6beta2`) — fixed

**Risk:** Medium release/upgrade ambiguity. The development line had accumulated `6.6.2` labels even though the release name is required to remain v6.6beta2.

**Fix:** Public application version, README/docs, Windows version strings, Inno Setup names and release attestation default use `6.6beta2`. Python distribution metadata uses legal PEP 440 `6.6b2`. A dedicated numeric `__compat_version__ = "6.6.2"` is retained only for plugin semantic-version comparison.

## 3. Existing hardening retained and re-reviewed

The review re-checks the previous v6.6 hardening baseline rather than replacing it. Important retained controls include scheduler generation ownership before durable reschedule writes, runner shutdown/submit race handling, bounded worker queues, SQLite explicit connection lifetime, atomic file replacement, recovery-state reconciliation, source/install provenance validation, plugin process budgets, Windows Job containment where available, HTTP connect/read bounds, data-root single-writer locking, runtime recovery, and the separate Windows 7 legacy dependency lane.

## 4. Windows 7 compatibility boundary

v6.6beta2 continues to expose a legacy enterprise lane for Windows 7 SP1 x64. The public release name does not change this compatibility contract. The legacy requirements file remains separate, and runtime selection keeps browser automation/modern Qt functionality behind capability checks instead of pretending unsupported modern components work on Win7.

Compatibility verification in this review includes source compilation, the repository's legacy compatibility tests, and a Python-3.8 grammar-oriented AST gate. These checks are strong static/regression evidence, but they are **not a substitute for native Windows 7 SP1 hardware/VM certification** with the pinned CPython 3.8 and Qt 5 stack.

## 5. Verification gates

Final release gates are populated after all generated repair/source manifests are rebuilt from the finalized tree:

- Full `pytest` suite: **329 passed, 6 skipped, 0 failed**
- Targeted v6.6beta2 deep-review tests: **17 passed per run; 10 repeated runs = 170/170 passed**
- Python compileall (`src`, `scripts`, `tests`): **passed**
- Python 3.8 grammar-oriented AST gate: **89 Python files parsed successfully**
- `ResourceWarning`-as-error regression pass: **329 passed, 6 skipped, 0 failed**
- Source manifest: **regenerated from the finalized tree; final integrity tests pass**
- Repair seed/manifest: **regenerated from the finalized tree; final integrity tests pass**
- Wheel build: **passed; `arenyxa-6.6b2-py3-none-any.whl`**

## 6. Environment limitations and residual risk

This review environment is Linux and does not provide a live PySide2/PySide6 desktop stack. GUI smoke tests that explicitly require a Qt binding are therefore expected to skip here. Native Windows-only behavior (Win7 SP1 Qt5 rendering, Npcap/tshark process semantics, Windows Job Objects, PowerShell repair console, Inno Setup installation, session shutdown) is validated by source-level contracts and platform-specific regression tests where possible, but must still receive a final native Windows certification pass before calling the beta a production-certified Windows 7 release.

`ruff` and `mypy` are not installed in the current audit runtime, so the release gate does not claim those external linters/type-checkers were executed. The repository test suite, compile/AST gates, targeted concurrency tests, generated integrity manifests, and wheel build are used as the executable verification baseline instead.

## 7. Release assessment

v6.6beta2 is materially stronger than the pre-review baseline in process lifecycle integrity, repair exclusivity, capture failure atomicity, shutdown ordering and version coherence. The highest-risk issues found in this pass are repaired with dedicated regression coverage rather than documented as known failures. Remaining caveats are primarily native-platform certification scope, not known uncorrected logic failures in the reviewed paths.
