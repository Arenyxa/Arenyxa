# Arenyxa V6.1 Release Audit — 2026-08-09

## Baseline

Source baseline: `Arenyxa_V6.0_Reliability_Stability_Hardened_Reviewed(1).zip` supplied by the user on 2026-08-09. V6.1 is an additive architecture release: existing UI/capture adapters continue to ingest `NetworkEvent`, while the persistence layer creates deterministic normalized network entities in the same transaction.

## Implemented scope

- Application/package version advanced to `6.1.0`; default runtime User-Agent advanced to `Arenyxa/6.1` while plugin minimum compatibility remains `6.0.0`.
- Added `Project` and `ProjectSource` domain ownership and validated Capture → Project/Source bindings.
- Added normalized `NetworkFlow`, HTTP request/response, DNS, TLS and WebSocket domain entities.
- Added deterministic `NetworkNormalizer` projection from the legacy `NetworkEvent` ingestion envelope.
- Added an additive SQLite migration for normalized Network Core tables and indexes.
- `append_network_events()` and `append_capture_events()` now write legacy and normalized facts under one SQLite transaction.
- Added `network_projection_events` ledger so projection and historical backfill are idempotent.
- Added `network_core_backlog()` and bounded `backfill_network_core()` for V6.0 historical captures; corrupt legacy rows fail with stable `NETWORK_CORE_BACKFILL_CORRUPT` diagnostics instead of being silently skipped.
- Added normalized HTTP exchange iteration and Network Core metrics APIs for later Replay/API Map integration.
- Preserved the existing Domain serialization schema version to avoid unrelated Task/Run/Workflow format drift in this architecture-only release.

## Reliability checks

- V6.0-style database migration test verifies the new migration is additive, recorded in `schema_migrations`, and creates a pre-migration backup.
- Projection failure test verifies the legacy `network_events` insert rolls back together with normalized tables.
- Historical backfill test verifies repeated backfill is idempotent and does not double-count flows.
- Cross-project Source binding test verifies invalid bindings roll back the Capture row atomically.
- Existing domain/database/network/capture/reliability tests remain green.

## Validation result

Review environment validation after the final source changes:

- `python -m compileall -q src tests`: passed.
- Non-UI regression suite (`pytest -q --ignore=tests/test_visual_motion_capture.py`): **189 passed, 2 skipped**.
- The two reported skips are PySide6-dependent suites because PySide6 is not installed in the review container. `test_visual_motion_capture.py` was intentionally not collected for the same environment limitation; this is not represented as a passed UI gate.
- Source Repair Seed regenerated after package changes.
- `SOURCE_MANIFEST.sha256` regenerated after source/documentation changes.
- `python -m arenyxa --version`: `Arenyxa 6.1.0`.
- Wheel build (`pip wheel --no-deps --no-build-isolation`): passed and includes the new Network Core module plus Repair Seed/manifest.

## Deferred by design

V6.1 does **not** move Replay/API Map/UI to the normalized entities yet. That work belongs to the next gates so the new persistence model can stabilize without simultaneously rewriting user-facing capture workflows. The intended sequence remains: V6.2 capture metadata enrichment → V6.3 normalized Replay/API Map → V6.4 Dataset/Data Lineage → V6.5 Workflow Engine integration.
