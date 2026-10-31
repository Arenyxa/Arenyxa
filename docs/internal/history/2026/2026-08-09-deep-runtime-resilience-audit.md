# Arenyxa V6.0 Deep Runtime Resilience Audit — 2026-08-09

## Scope

This audit starts from `Arenyxa_V6.0_Multithreaded_Web_Scraping.zip` and deliberately preserves the existing product structure, Dashboard, navigation, themes, i18n/RTL, motion system, Repair Center, provenance/anti-tamper model, capture stack, developer tools, Headless Server, plugins, `.arenyxa` project format, and concurrent scraping UX. The work is focused on failure semantics, concurrency, bounded resource usage, transaction integrity, shutdown/restart behavior, and latent edge cases.

## Implemented corrections

### Concurrent scraping and Run lifecycle

- Reworked per-host concurrency acquisition so a request waiting for a busy host does not occupy a global request-pool worker. Pending requests rotate until a host lease is available, preventing unrelated hosts from being starved by one saturated domain.
- Host leases are reserved before worker submission, released immediately after network I/O, and are idempotently released when a queued Future is cancelled.
- Run submission is serialized against shutdown; queued Runs cancelled during shutdown are persisted as `CANCELLED` instead of remaining indefinitely queued.
- Archived/deleted Tasks are rejected before Run creation with stable `TASK_INACTIVE` semantics.
- Pause/resume state is now persisted immediately, so in-memory status, SQLite state, and crash recovery agree during a long pause.
- Whole-Run result de-duplication moved from an unbounded Python `set` into SQLite `run_result_hashes(run_id, content_hash)`. This preserves exact de-duplication while keeping normal Run memory approximately bounded as URL count grows. Preview remains an in-memory-only operation and keeps a temporary set.

### Scheduler and automation

- Replaced one-daemon-thread-per-trigger behavior with a bounded callback executor.
- Disabled/re-enabled schedules recalculate stale deadlines instead of firing years-old occurrences immediately.
- Queued callbacks are cancelled when a schedule is disabled, removed, or replaced.
- Callback execution re-checks current schedule identity/enabled state immediately before user code runs.
- `next_run` durability is delayed until an occurrence is actually attempted, favoring at-least-once recovery over silently skipped schedules if the process dies between dispatch and execution.
- Desktop-created and restored schedules now track submitted Run handles so a slow Run cannot overlap with itself merely because the scheduling callback returned quickly.

### SQLite and storage integrity

- SQLite connections now truly close after context-manager use; WAL negotiation occurs at initialization rather than on every connection.
- Startup recovery closes abandoned Run/Capture lifecycle rows from a previous crashed owner and recalculates capture counters from persisted events.
- Task row and FTS task-index changes share one transaction, preventing task/index split-brain states.
- Capture event batch + capture summary updates can commit atomically through `append_capture_events`.
- Revision counting no longer loads the entire revision into Python merely to calculate a count.
- Network-event iteration uses keyset paging to avoid a single long-lived read transaction retaining WAL pages.
- External SQLite database-adapter DDL types use a strict allowlist; arbitrary type text can no longer be spliced into `CREATE TABLE`.
- SQLite/SQLAlchemy bulk writers reject row schema drift instead of silently discarding unexpected columns.
- SQLAlchemy positional parameters now use `exec_driver_sql`; unsupported schema types raise instead of silently becoming text.
- App settings are saved using a unique same-directory temporary file + fsync + atomic replace, removing the fixed `settings.tmp` collision window.
- Boolean JSON values are no longer accepted as numeric concurrency/timeout values through Python's `bool`-is-`int` coercion.

### HTTP and parsing resilience

- Retryable HTTP statuses actually honor RetryPolicy; Retry-After supports numeric and HTTP-date forms with jittered bounded backoff.
- Non-idempotent POST/PATCH retries are disabled unless explicitly opted in, reducing duplicate side effects after uncertain network failure.
- Query parameters are inserted before URL fragments.
- Response Content-Length is guarded before read; actual response reads are bounded.
- gzip decompression is bounded and streaming instead of allowing a compressed response to expand without the configured limit.
- Unsupported Content-Encoding and invalid declared charsets now produce deterministic behavior.
- Network/timeout/TLS errors map to stable error domains rather than leaking arbitrary urllib exceptions.
- Field specifications are validated before execution, including selector modes, built-in cleaner/validator kinds, regex syntax, extraction groups, and typed parameters.

### Capture stack

- Capture adapter asynchronous failures propagate to the controller and result in `FAILED` sessions rather than a false `COMPLETED` state.
- Writer/database failures stop the session reliably; listener callback failures no longer kill the writer.
- tshark/dumpcap stderr is drained, unexpected child termination is detected, and process cleanup waits/reaps children.
- Batch event persistence and session counters use one atomic store operation where supported.

### Repair Center

- Database corruption recovery no longer joins the entire `iterdump()` into RAM. SQL statements are replayed incrementally into a same-filesystem candidate database.
- The original corrupt database receives a unique timestamped preserved filename; a later repair can no longer overwrite an earlier forensic/recovery copy.
- The recovered candidate must pass `quick_check` before replacement; failed reconstruction leaves the primary database untouched.
- If final replacement fails, Arenyxa attempts to restore the preserved original to the primary path.
- Plugin repair treats non-object JSON manifests as invalid instead of raising `AttributeError`.
- Plugin quarantine uses microsecond-unique batches and never deletes an older quarantine copy merely because a name collides.
- Language repair remains isolated from program-file restoration in source/development builds.

### Plugins, projects, and extensibility boundaries

- Plugin subprocess stdout/stderr budgets are enforced while the child is running, preventing unbounded parent-side `communicate()` buffering.
- Spawned plugin children are killed/reaped if Windows Job Object assignment fails.
- Plugin effective permissions are the intersection of manifest requests and user grants.
- Worker audit hooks tighten network/process/storage/symlink/native-code boundaries.
- `.arenyxa` validation rejects duplicate ZIP entries, unmanifested files, missing files, traversal, symlinks, encrypted entries, portable-path collisions, invalid Windows path components, and files outside known project roots.
- `.arenyxa` pack/unpack uses atomic destination semantics and avoids recursively packaging an older output archive from inside the project tree.
- Workflow validation detects duplicate IDs, dangling edges and cycles; handler output is iterated instead of force-converted to a list.
- Browser Profile IDs/paths are validated and profile writes are atomic.
- Marketplace catalog/package transport remains HTTPS-only across redirects with size/hash checks.

### Desktop / Headless runtime ownership

- Added `DataRootLease`, an OS advisory lock shared by Desktop and Headless Server. Desktop-vs-Desktop remains handled by QLocalServer, while the filesystem lease prevents a Server and Desktop from independently owning lifecycle recovery for the same data directory.
- Different data directories remain independently usable. The lock file itself may remain after a crash; OS ownership is released with the process.

### Developer/GUI responsiveness

- Developer Console built-in SQLite/JSON commands now run through the bounded Qt background pool rather than blocking the GUI thread.
- Console JSON output is capped for display; users are directed to dedicated filtering/export pages for complete very-large datasets.
- Developer system commands use the existing bounded background-job infrastructure rather than creating an unbounded daemon thread per click.
- Background-job retention cleanup is delivered through a GUI-thread QObject slot rather than mutating the shared active-job set from a receiver-less worker-thread lambda.

## Deliberately retained architectural limits

The following issues are real, but a correct solution would materially change the execution model or dependency stack. They are documented instead of being hidden behind a risky patch:

1. **User regular-expression worst-case runtime.** Syntax is validated, but Python `re` has no reliable per-match timeout. Adversarial catastrophic-backtracking expressions can still consume CPU. A robust solution requires a timeout-capable regex engine or process isolation for regex evaluation.
2. **Dataset Revision memory model.** `DatasetRevision.records` is currently a dictionary by design. Creating/comparing very large revisions therefore materializes the dataset. A streaming/chunked revision store would require a versioned data-model change.
3. **Workflow full backpressure.** Handler output is streamed, but multi-root fan-in and retained node outputs can still scale with workflow data volume. True bounded backpressure needs an execution-graph redesign with bounded channels/spill storage.
4. **urllib connection pooling/cancellation.** The current standard-library client is bounded and thread-safe, but it lacks the mature connection pooling and cancellable async I/O of a modern HTTP client. Replacing it would be a deliberate dependency/API decision, not a patch.
5. **System packet-capture pause semantics.** Pausing Arenyxa event ingestion does not necessarily pause a native dumpcap raw-pcap producer identically on every platform. Changing that requires platform-specific capture lifecycle semantics and validation against packet-analysis tooling.
6. **SQLite migration transaction model.** Existing migrations are idempotent `CREATE IF NOT EXISTS` scripts. Future destructive/non-idempotent migrations should introduce an explicit migration transaction/backup protocol rather than relying on the current executescript behavior.
7. **Plugin memory enforcement portability.** Windows Job Objects provide the hard memory budget on the primary target platform. Equivalent hard POSIX resource isolation is not yet a product requirement/implementation.
8. **Qt visual/runtime verification.** The audit environment does not contain PySide6 and is not Windows, therefore DPI, multi-monitor, animation, native PowerShell repair, tshark/dumpcap, PyInstaller and Inno Setup remain Windows release-gate tests.

## Regression strategy

The audit adds/extends tests for host-starvation prevention, queue cancellation, pause/resume durability, scheduler replacement/disable behavior, interrupted lifecycle recovery, plugin output budgeting, field validation, non-idempotent HTTP retry policy, invalid charsets, adapter schema drift, settings atomicity/type normalization, durable result de-duplication, Repair database preservation, Repair plugin quarantine, data-root runtime ownership, and server ownership contention.

A passing unit/integration suite is evidence for the paths covered by those fixtures; it is not a claim that no defect can exist. Windows GUI and native-capture release gates remain mandatory before a production installer is signed.
