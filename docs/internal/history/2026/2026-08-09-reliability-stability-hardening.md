# Arenyxa V6.0 Reliability & Stability Hardening Audit

**Date:** 2026-08-09  
**Baseline:** `Arenyxa_V6.0_Competitive_Edge_Web_Intelligence_Reviewed.zip`  
**Scope:** Reliability/stability hardening only. Existing product surfaces, workflows, developer tools, Intelligence Studio, taskbar/tray integration, themes, i18n, project format, local-first architecture and release-provenance model are retained.

## Goals

1. Prevent a damaged control file, oversized response, malformed imported data or partial disk write from crashing or corrupting the application.
2. Make shutdown, retries, scheduling, migrations, backup, capture and plugin execution deterministic under failure.
3. Bound memory, thread, retry, response and metadata growth where a pathological input could otherwise exhaust resources.
4. Preserve prior known-good data whenever a write, migration, repair or environment rebuild fails.
5. Avoid introducing a closed/DRM-style restriction: source/development builds remain intentionally editable.

## Runtime hardening completed

### Atomic/durable local state

A shared `arenyxa.infrastructure.atomic_io` layer now provides same-directory temporary staging, flush/fsync and atomic replace for small control files. It is used by settings, secrets, worker registry, browser profiles, project environment metadata, repair state/report files, diagnostic summaries, crash markers, marketplace packages and other durability-sensitive metadata.

Concurrent settings/vault writers are verified to leave complete JSON/encrypted documents rather than partial files. SecretVault instances sharing one root also share an in-process transaction lock.

### HTTP and run execution

- Retry accounting now uses the effective retry budget after idempotency rules are applied. Retryable POST failures with non-idempotent retries disabled are no longer swallowed/reclassified.
- Read sockets use short polling where possible while preserving the configured read timeout as an inactivity deadline. Pause/cancel/shutdown therefore remain responsive during a slow response.
- Connect/read timeouts and retry backoff are bounded and validated as finite values.
- Response body and gzip-expanded body limits remain enforced.
- Run progress/result persistence failures are converted to stable `RUN_STORAGE_FAILED` terminal states instead of leaking unhandled worker-Future exceptions.
- A Run is not queued if its initial durable row cannot be saved.
- Adaptive per-host limiter state has an idle TTL and maximum host count to prevent unique-host workloads from growing memory without bound.

### SQLite lifecycle and migrations

- Existing databases with pending migrations receive a verified native SQLite backup **before** Arenyxa changes migration metadata.
- Each migration version runs under explicit `BEGIN IMMEDIATE`/`COMMIT`; a failing statement rolls back the whole version.
- Native SQLite backup writes to a unique temporary database, performs `PRAGMA quick_check(1)`, fsyncs and atomically replaces the rolling backup only after verification.
- Corrupt optional settings rows are quarantined logically (logged + default value) rather than taking down the settings/dashboard surface.
- Cheap `SELECT 1` liveness is separated from `quick_check`, so `/health` no longer performs an integrity scan on every probe.
- Shutdown performs best-effort WAL checkpoint and `PRAGMA optimize` only after application writers are stopped.

### Scheduler correctness

Daily/weekly schedules now use calendar wall-clock reconstruction and UTC round-trips across DST transitions. Spring-forward nonexistent times normalize to the first representable instant; fall-back ambiguous times deliberately choose the first occurrence, preventing duplicate scheduled execution. Interval schedules remain elapsed-time/UTC based.

### Capture pipeline

- Capture controller shared state/listeners/drop accounting are synchronized.
- Filter callback failures become stable capture failures instead of escaping adapter threads.
- If a capture source dies asynchronously, Arenyxa stops accepting new input but drains and commits already queued tail events before persisting the failed session.
- Listener failures remain observational and cannot break capture persistence.
- Browser DOM snapshots are atomically written.

### Secrets, project environments and distributed workers

- SecretVault key/vault reads are bounded; malformed keys produce a stable error.
- The encrypted last-known-good vault backup can restore a corrupted primary without creating cleartext backup material.
- Project `.venv` rebuilds are transactional: the previous working environment is restored if discovery/creation/status validation fails.
- Project environment metadata uses bounded reads and atomic writes.
- Distributed worker registry corruption no longer falls back to an empty list that could overwrite all configured workers.
- Token updates are rolled back when worker-registry persistence fails.
- Remote worker IDs placed into REST paths are URL-quoted.
- Remote worker payloads/responses and timeouts are bounded; non-loopback plain HTTP workers remain rejected.

### Plugin sandbox

- Manifest, permission payload, plugin input, execution time, memory and combined stdout/stderr are bounded.
- Output is drained concurrently while the child runs so a noisy plugin cannot exhaust the parent before a post-hoc check.
- The isolated worker validates malformed metadata/request input without depending on Arenyxa package imports under Python `-I`.
- Existing audit-hook permission boundaries for filesystem/network/process access remain intact.

### Import/export and marketplace

- Export temp files are flushed before atomic commit; progress callbacks are observational and cannot destroy a valid long export.
- XLSX row rollover follows Excel worksheet limits; excessive columns/cell lengths fail with stable errors instead of silent truncation/corruption.
- Marketplace catalog/package reads are bounded, HTTPS redirect requirements remain enforced, SHA-256 is checked, and package commit uses the atomic I/O layer.
- `.arenyxa` project packages are validated before commit and fsynced before replacement.
- HAR imports now have a 256 MiB / 250,000-entry safety boundary and robust handling of malformed noncritical numeric/header fields, preventing pathological JSON from exhausting the process or raising unrelated type errors.

### Generated request code parity

- Request code generation now reuses production URL-building semantics so existing duplicate query parameters are preserved, and generated requests mirror production Content-Type behavior.
- HTTP Workbench reconstructs `RetryPolicy` from JSON rather than leaving an untyped dictionary in `RequestSpec`.

### Startup / repair / provenance

- Startup locale/settings reads, crash markers, health reports, integrity-state files, repair plans/reports, trust store, attestation and release manifests use bounded/atomic control-file handling where appropriate.
- Repair source-file restoration commits each verified payload atomically.
- Repair build scripts no longer delete the prior repair seed/manifest before a complete replacement pair has been staged; generated ZIP CRC is checked before commit.
- Source-manifest generation now stages and fsyncs the manifest before replacement.
- PyInstaller UPX compression is disabled to favor binary compatibility and reduce packed-binary/AV edge cases; this trades package size for release stability without removing functionality.

## Added reliability regression coverage

`tests/test_reliability_stability_hardening.py` now covers, among other cases:

- HTTP query/header validation and cancellation polling
- production/codegen URL parity
- JSON-to-`RetryPolicy` reconstruction
- encrypted vault backup recovery and invalid key handling
- concurrent multi-instance vault writes
- worker-registry corruption preservation and token rollback
- transactional `.venv` rebuild rollback
- verified SQLite backup and atomic migration rollback
- true pre-migration backup for legacy databases
- DST gap/fold schedule behavior
- capture-source failure with queued tail-event durability
- oversized settings/repair/HAR control input limits
- stable Run storage-failure behavior
- concurrent settings writer atomicity
- distributed worker task-ID path quoting
- malformed HAR field tolerance

The dedicated reliability suite is intentionally repeated during review to detect timing-sensitive flakiness.

## Validation boundary

The review container can compile and execute the non-GUI Python core, but it does **not** contain PySide6 or a Windows desktop session. Therefore this audit does not claim runtime verification of Qt rendering, Windows taskbar COM, System Tray, PyInstaller-produced EXE behavior or Inno Setup installation. Those remain mandatory Windows release-gate checks via:

```powershell
.\scripts\bootstrap.ps1
.\scripts\test.ps1
.\scripts\build.ps1
```

The reliability changes deliberately preserve those UI/shell surfaces rather than redesigning them in this pass.
