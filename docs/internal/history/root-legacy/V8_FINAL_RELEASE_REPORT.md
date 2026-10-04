# Arenyxa v8.0 Stable Source Promotion Report

The v8.0 engineering baseline has been promoted to stable source identity `8.0` / package `8.0.0` / Windows file version `8.0.0.0`. Runtime/plugin compatibility remains `6.8.0` by design.

Final promotion work included stable release identity propagation across modern/legacy runtimes, packaging, installer output names, compatibility manifests, release verification, production configuration gates, architecture contracts, tests and launch metadata; a dedicated `verify_v80_release_identity.py` stable identity gate; final acceptance/test evidence regeneration; repair seed/source manifest regeneration; and final impacted-regression verification.

Local engineering acceptance is PASS. Complete production certification remains PARTIAL only for explicitly environment-bound external/native gates documented in `FINAL_ACCEPTANCE_REPORT.md` and `V8_TEST_EVIDENCE.json`.


## Startup launch probe status

The previously identified source-launch false-negative problem is fixed in this stable source line. `scripts/launch.ps1` delegates probing to `scripts/launch_probe.ps1`, which uses `System.Diagnostics.ProcessStartInfo` rather than PowerShell stream merging. stdout, stderr, ExitCode, Python executable, Python version, and working directory are reported independently. Source startup remains `python.exe -m arenyxa`. A timeout regression was added so a wedged Python probe returns a bounded diagnostic instead of blocking startup forever.

## Maintainability split completed for official source

As part of the final v8.0 stable promotion, oversized persistence and distributed-runtime files were reduced without changing public APIs:

- `src/arenyxa/infrastructure/database.py` is now a 210-line SQLite facade.
- Schema text moved to `src/arenyxa/infrastructure/database_migrations.py`.
- Operational maintenance/recovery/settings/enterprise binding helpers moved to `src/arenyxa/infrastructure/database_maintenance.py`.
- `src/arenyxa/enterprise/distributed_queue.py` is now focused on queue core, fencing and lease execution.
- Worker registry, heartbeat, revocation and expired-lease recovery moved to `src/arenyxa/enterprise/distributed_queue_workers.py`.

The split is deliberately API-preserving: callers still import and use `SQLiteStore` and `DurableDistributedQueue` through their original modules.
