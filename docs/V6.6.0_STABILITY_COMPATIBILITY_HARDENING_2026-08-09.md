# Arenyxa V6.6.0 — Stability & Compatibility Hardening

V6.6.0 starts from the independently re-audited V6.5.6 baseline. The release deliberately prioritizes crash reduction, bounded shutdown, Windows filesystem compatibility and runtime preflight over new surface-area features.

## Reliability changes

- Small atomic control-file replacements retry transient sharing/access violations for a short bounded interval. This targets Windows Defender, indexer and sync-client races while preserving the old destination on permanent failure.
- `HttpFetcher` bounds the single uninterruptible DNS/TCP/TLS connect phase to 60 seconds. Persisted request timeout fields remain compatible; read waits remain cancellation-aware and short-polled.
- Python source-runtime compatibility is explicit: 3.11, 3.12 and 3.13 are supported. Unsupported direct-source runtimes fail before application state initialization with a stable error code.
- SQLite runtime preflight requires SQLite >= 3.24 and FTS5 before migrations touch the persistent database. Custom/embedded Python builds therefore fail into Recovery Mode with actionable diagnostics instead of low-level migration traces.
- Recovery Mode preserves `ArenyxaError` codes and maps database/dependency/plugin/capture domains to the corresponding repair category.

## Stability test gates

The V6.6 suite adds repeated Runner shutdown/thread-leak checks, Scheduler lifecycle checks, Bootstrap/ApplicationContext shutdown cycles, Headless Server lifespan cycles, DataRootLease contention/reacquisition, concurrent SQLite writers with `quick_check`, transient and permanent atomic-replace tests, HTTP connect-cap verification and file-descriptor leak accounting where `/proc` is available.

V6.5.6 plugin sandbox, Workflow recovery, Dataset lineage, Capture cleanup, Qt background shutdown and Repair Center contracts remain mandatory regression coverage.
