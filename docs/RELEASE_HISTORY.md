# Arenyxa Engineering Release History

> **Version interpretation:** GitHub public release numbering starts at **v0.1**. The v6.x, v7.x, and v8.x labels preserved below are **internal engineering milestones**, not prior GitHub public releases. Historical text is intentionally retained for provenance, even where the original internal document used words such as "Public", "Stable", or "Official". Those words describe the internal promotion state that existed at the time.
>
> Current public product identity is defined by `README.md`, `VERSIONING.md`, `RELEASE_IDENTITY.json`, and the active source/package metadata.

This document consolidates historical release notes, release checklists, version-alignment records, and release audits. The original milestone text remains below as engineering evidence.


---

## Source: `V6.6_STABLE_RELEASE_CHECKLIST.txt`

Arenyxa v6.6 Stable Release Checklist

Identity
- Public: 6.6
- Python package: 6.6.0
- Plugin compatibility: 6.6.2
- Modern installer: dist\installer\Arenyxa_V6.6_Setup_x64.exe

Windows build
1. Set-ExecutionPolicy -Scope Process Bypass -Force
2. .\scripts\build.ps1
3. Confirm release-blocking pytest passes.
4. Confirm PyInstaller COLLECT completes.
5. Confirm $env:QT_QPA_PLATFORM is unchanged/empty after build.
6. Launch .\dist\Arenyxa\Arenyxa.exe and validate Dashboard, Capture/Tasks, Network, Data, Advanced, Settings, Repair Center, restart and shutdown.
7. Enable Developer Mode, accept both developer agreements, then run `test-all` in the built-in terminal.
8. Run `stress-test standard`; use `stress-test extreme` only on a saved/idle development workstation.
9. If Inno Setup 6 or 7 is installed, verify .\dist\installer\Arenyxa_V6.6_Setup_x64.exe.

Distribution
- Portable release must include the entire dist\Arenyxa directory, not Arenyxa.exe alone.
- Official channel requires ARENYXA_RELEASE_SIGNING_KEY; the legacy signing variable remains accepted for migration builds.
- Legacy Win7 binary certification remains independent.


---

## Source: `V6.7_STABLE_RELEASE_CHECKLIST.txt`

Arenyxa v6.7 Stable Release Checklist
====================================

Version identity
- Public: 6.7
- Python package: 6.7.0
- Plugin minimum-app comparator: 6.7.0
- Modern installer: dist\installer\Arenyxa_V6.7_Setup_x64.exe
- Legacy installer: dist\installer\Arenyxa_V6.7_Legacy_Win7_x64_Setup.exe

Startup transition contract
- Splash first paint must happen before bootstrap work begins.
- Splash must never use sleep()/blocking waits or delay initialization.
- MainWindow is shown before the splash exit animation starts.
- Bootstrap/recovery failures abort the splash before any recovery dialog appears.
- Reduce Motion, smoke tests, safe mode and reduced-visual legacy runtimes bypass animated exit.
- Animation is best-effort: any splash failure falls back to ordinary startup.

Release gates
1. Run scripts\bootstrap.ps1 on Windows.
2. Run scripts\test.ps1.
3. Run test-all in Developer Terminal.
4. Run stress-test extreme in Developer Terminal.
5. Build modern package with scripts\build.ps1.
6. If supporting Windows 7, run the separate Legacy build/test lane.
7. Verify Repair Seed and SOURCE_MANIFEST.sha256 after all code/resource changes.
8. Verify window/taskbar/tray/installer icon and startup splash use the same approved Arenyxa icon.
9. Verify clean launch, second-instance activation, recovery-mode launch, --safe-mode and --smoke-test.


---

## Source: `V6.8_BETA_RELEASE_CHECKLIST.txt`

Arenyxa v6.8 Beta Release Checklist
Date: 2026-08-11

Identity
- Public: 6.8beta
- Python package: 6.8.0b1
- Plugin/API comparator: 6.8.0
- Modern installer: dist\installer\Arenyxa_V6.8beta_Setup_x64.exe
- Legacy installer: dist\installer\Arenyxa_V6.8beta_Legacy_Win7_x64_Setup.exe

Core v6.8 Beta gates
- Adaptive global request admission starts from a four-slot floor when ceiling > 4.
- Local parse/extract P95 drives global grow/backoff; network latency does not.
- Existing per-host HTTP adaptive limiter remains independent.
- Manual live request budget suspends auto mode; Auto Budget restores it.
- Settings adaptive_request_concurrency is type-safe and defaults to true.
- stress-test reports recommended_local_workers without treating it as an HTTP limit.
- Repair single-console hotfix remains present.
- Repair Seed and Source Manifest are regenerated only after source freeze.

Required validation
- Python compileall
- Python 3.8 grammar gate
- Full pytest regression
- Repair Seed SHA-256 / internal manifest / ZIP CRC
- Source Manifest current hashes
- test-all
- stress-test standard
- stress-test extreme
- Windows GUI/Repair/Capture/manual-vs-auto concurrency smoke


---

## Source: `V6.8_STABLE_RELEASE_CHECKLIST.txt`

Arenyxa v6.8 Stable Release Checklist
Date: 2026-08-11

Release identity
- Public runtime: 6.8
- Python package: 6.8.0
- Plugin/API compatibility: 6.8.0
- Modern installer: dist\installer\Arenyxa_V6.8_Setup_x64.exe
- Legacy installer: dist\installer\Arenyxa_V6.8_Legacy_Win7_x64_Setup.exe

Stable gates
[x] 01 Python compileall
[x] 02 Python 3.8 grammar / Windows 7 static compatibility
[x] 03 v6.8 stable identity + packaging contracts
[x] 04 startup geometry/handoff/motion contract
[x] 05 Repair single-console + Repair payload integrity
[x] 06 Capture terminal progress lifecycle
[x] 07 Runner pause/resume persistence + token-failure transaction boundary
[x] 08 adaptive request admission + concurrency/shutdown regressions
[x] 09 Dataset/Workflow/lineage + diagnostic logging regressions
[x] 10 security/provenance/plugin/terminal regressions
[x] 11 complete split regression suite
[x] 12 Source Manifest + Repair Seed + ZIP CRC/SHA-256 freeze

Performance/startup continuity hotfix gates
[x] 13 beta/Stable source-hash comparison and regression-cause audit
[x] 14 tracemalloc timing-boundary A/B verification
[x] 15 steady-state Standard ramp repeated three times
[x] 16 center-logo scale and quintic endpoint math
[x] 17 circular reveal coverage for portrait/ultrawide/high-DPI geometry
[x] 18 native Qt center-mask render and full-surface completion
[x] 19 shared launch geometry + in-window handoff order
[x] 20 Reduce Motion + safe/smoke/reduced-visual bypasses
[x] 21 Repair/Capture/UI-scale/adaptive-concurrency preservation
[x] 22 complete regression + Python 3.8 grammar + critical Ruff
[x] 23 refreshed Repair Seed + Source Manifest integrity
[x] 24 final source ZIP CRC, extraction, and SHA-256

Final performance/stability/compatibility freeze gates
[x] 25 TLS context reuse + SQLite connection/task/run hot-path contracts
[x] 26 lazy host buckets + refill fairness + 100k backlog cancellation
[x] 27 Windows Repair process probe cannot terminate the observed process
[x] 28 Capture prepare/start/pause/resume rollback + late-session rejection
[x] 29 Capture filter-error/stop state-commit serialization
[x] 30 Runner control I/O ordering + queued cancellation
[x] 31 Workflow shutdown waits across preflight repository side effects
[x] 32 mixed-DPI/small-logical-screen geometry + physical-DPR logo rendering
[x] 33 OS/user Reduced Motion + Modern/explicit-Legacy runtime selection
[x] 34 subprocess decode fallback + one-click launcher dependency probe
[x] 35 three Standard + one Extreme zero-error performance freeze
[x] 36 refreshed Repair Seed + Source Manifest + clean D: deployment + ZIP verification

Source-only delivery note
- This freeze does not modify Git state and does not build or change Inno Setup installers.

Native Windows release verification still required after extraction/build:
- confirm exact startup motion on the target compositor and both monitors;
- run test-all, stress-test standard, stress-test extreme;
- run Repair Center repeatedly and confirm one visible progress terminal only;
- start/stop Browser/tshark Capture and confirm the top progress strip clears;
- build with scripts\build.ps1 and smoke the generated Arenyxa_V6.8_Setup_x64.exe.


---

## Source: `V7.0_STABLE_RELEASE_CHECKLIST.txt`

Arenyxa v7.0 Stable Release Checklist
=====================================

Release identity
[x] Public/runtime display version: 7.0
[x] Python package version: 7.0.0
[x] Windows file/product version: 7.0.0.0 / 7.0
[x] Modern installer name: Arenyxa_V7.0_Setup_x64.exe
[x] Legacy Win7 installer name: Arenyxa_V7.0_Legacy_Win7_x64_Setup.exe
[x] Release attestation default version: 7.0
[x] Public launcher title: Arenyxa v7.0

Compatibility
[x] Historical arenyxa Python/CLI namespace remains available
[x] Plugin/runtime compatibility identity intentionally remains 6.8.0
[x] Enterprise protocol remains N/N-1: current 2, minimum 1
[x] No schema/protocol bump is implied solely by the product version promotion

Automated release gates
[x] multi-dimensional quality gates pass on the release tree
[x] phase11_12_gate.py passes
[x] verify_v70_release_identity.py passes
[x] Source Manifest and Repair Seed regenerated after final edits
[x] Fresh-extract regression passes: 592 passed / 12 environment skips / 0 failed
[x] ZIP CRC/SHA-256 passes

Native/operator release gates
[ ] Windows modern lane: startup, multi-monitor, DPI, Repair, Capture, install/upgrade/uninstall
[ ] Windows 7 legacy lane (if distributed): launch, core features, installer/upgrade/uninstall
[ ] Root Developer DPAPI workstation binding on real Windows
[ ] Enterprise Server + at least two Workers: loss/reconnect/restart/duplicate-delivery drill
[ ] Upgrade backup/migration/rollback drill with representative v6.8 data
[ ] Independent security review record signed off

Signing/publication
[ ] Official build uses a dedicated release-signing key (never Developer Root/Enterprise Root)
[ ] Matching public release key is embedded before channel=official build
[ ] Private Authority state, Root/Issuing private vaults, Owner private keys are absent from source/installer
[ ] Published installer SHA-256 recorded out of band

IMPORTANT
Arenyxa v7.0 is the product release identity. The source does not bypass Phase-12 native-Windows,
distributed-failure, security-review, or signing requirements. An unsigned community build remains
functional but is intentionally reported as unverified.


---

## Source: `V8_1_RELEASE_NOTES.md`

# Arenyxa v8.1 Release Notes

Arenyxa v8.1 is a stable source refresh based on the v8.0 feature set. It does not remove product features or relax Root Developer authentication/integrity controls.

## v8.1 changes

- Replaced the legacy green network/crawler application artwork with the new Arenyxa geometric `A` + Core identity.
- Regenerated the canonical 1024 px RGBA application PNG and the Windows multi-size ICO (16/24/32/48/64/128/256 px).
- The new icon is used by the Qt runtime, title bar, main window, About page, startup splash, PyInstaller executable, Windows service packaging, and Inno Setup installer through the existing canonical branding paths.
- Promoted the product/display version to `8.1`, Python distribution/package version to `8.1.0`, and Windows file version to `8.1.0.0`.
- Updated installer output names to `Arenyxa_V8.1_Setup_x64.exe` and `Arenyxa_V8.1_Legacy_Win7_x64_Setup.exe`.
- Hardened the source launcher so a stale editable virtual environment cannot silently import an older Arenyxa source tree. The launch probe now verifies that `arenyxa.__file__` resolves under the current project's `src` directory before startup.
- The clean v8.1 source delivery intentionally omits the machine-bound `.venv`; `RUN_ARENYXA.cmd` / `scripts\bootstrap.ps1` recreates it against the extracted v8.1 source tree. This prevents an old editable environment from silently pointing back to a previous project directory.

## Compatibility

- Runtime/plugin compatibility identity remains `6.8.0` by design.
- Existing v8.0 feature architecture is preserved; this release is a brand/version/launcher-integrity refresh, not a database schema migration.


---

## Source: `V8_FINAL_RELEASE_REPORT.md`

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


---

## Source: `V8_OFFICIAL_RELEASE_NOTES.md`

# Arenyxa v8.0 Official Source Release Notes

Arenyxa v8.0 is promoted from the final engineering candidate to the official stable source identity.

## Stable identity

- Display version: `8.0`
- Package version: `8.0.0`
- Windows file version: `8.0.0.0`
- Release channel: `stable`
- Artifact name: `Arenyxa_v8.0`
- Runtime/plugin compatibility identity: `6.8.0`

## Startup launcher finalization

- Source launch remains standardized on `python.exe -m arenyxa`; `pythonw.exe` is intentionally not preferred so diagnostics remain observable.
- The environment probe uses `System.Diagnostics.ProcessStartInfo` and separately captures stdout, stderr, process start state, Python version, working directory, and ExitCode.
- Probe execution now has a bounded timeout path that returns `ExitCode = -2` with preserved stdout/stderr instead of hanging the launcher indefinitely.

## Promotion policy

This promotion does not invalidate existing 6.8-compatible plugins, workers, or distributed metadata. Environment-dependent certifications such as native Windows driver capture, real PostgreSQL multi-node stress, TPM/CNG, DPAPI, SCM, and 24-hour soak tests must continue to report `NOT_EXECUTED` unless run on suitable hardware.

## Small finalization optimizations

- Current v8 artifact identity is stable-only across release metadata, runtime namespace, Windows packaging, manifests, and generated source archive names.
- v8 phase regression test filenames no longer carry pre-release identity; historical v6 pre-release compatibility tests are retained as compatibility history.
- Physical QA guidance is now separated from automated CI so official release evidence does not confuse logic correctness with hardware certification.


---

## Source: `VERSION_ALIGNMENT_v8.2.md`

# Arenyxa v8.2 version alignment (2026-09-11)

Official identity after this pass:

| Field | Value |
|---|---|
| `__version__` | `8.2` |
| `__package_version__` / pyproject `version` / `__display_version__` / `__distribution_version__` | `8.2.0` |
| `__engineering_build__` | `v8.2.0` |
| Windows filevers/prodvers | `8.2.0.0` |
| Plugin/runtime compatibility | `6.8.0` (intentionally unchanged) |

Corrected stale live tokens that still said 8.1 / 8.1.0 / 8.1.1:

- `src/arenyxa/__init__.py`
- `legacy/win7/src/arenyxa/__init__.py` (full identity fields + phase)
- `pyproject.toml`
- `src/arenyxa.egg-info/PKG-INFO`
- `HANDOFF.md` product label
- HAR/export creator version and default Repeater/Replay/crawler User-Agent product tags
- architecture product compatibility_level `8.1` → `8.2`
- leftover tests still asserting `filevers=(8,1,1,0)`

Historical reports named `Arenyxa_v7.0_*`, `V6.*` checklists, and "baseline: Arenyxa_v8.1.1" provenance fields were left as history.

`scripts/verify_v82_release_identity.py`: PASS

## Offline repair seed (2026-09-11 follow-up)

Regenerated with `python scripts/build_source_repair_seed.py` and `--win7`.

| Lane | Path | SHA-256 | Size |
|---|---|---|---|
| modern | `src/arenyxa/resources/repair_seed.zip` | `7aad1f4a2591fea3d1e5c55f7c281043fe36c613fc7b1fb15460d254abf95231` | 2690198 |
| win7 | `legacy/win7/src/arenyxa/resources/repair_seed.zip` | `dd14b6c8731e3d5b0d0a0bc20e161089c9d10eca86ad421960f966b639bfc498` | 1136561 |

`repair_manifest.json` `seed_sha256` matches the zip bytes. Previous tree had the manifest but **no zip**, which is exactly `REPAIR_SEED_INVALID` / fingerprint `NXF-C2CDCD687E1D`.


---

## Source: `docs/V6.1_RELEASE_AUDIT_2026-08-09.md`

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


---

## Source: `docs/V6.2_RELEASE_AUDIT_2026-08-09.md`

# Arenyxa V6.2 Release Audit — 2026-08-09

## Baseline

Source baseline: `Arenyxa_V6.1_Unified_Domain_Network_Core_Reviewed.zip` generated from the user-supplied latest V6.0 reliability/stability baseline. V6.2 is an additive capture-enrichment release; it does not rewrite Replay/API Map or remove the legacy `NetworkEvent` compatibility envelope.

## Implemented

### Normalized body storage

- Added `BodyArtifact` to `arenyxa.domain.network`.
- Added `NetworkBodyStore` with a default 2 MiB per-body storage budget.
- Body IDs are stable per capture session + original payload SHA-256.
- Truncated bodies retain both original SHA-256 and stored-prefix SHA-256; `.partial` storage suffix prevents a truncated prefix from masquerading as a complete content-addressed blob.
- Stored payload references are relative to the capture body root and guarded against path traversal on resolution.
- Full stored-body readback verifies exact stored length and stored SHA-256.
- Added `network_bodies` SQLite table and read/quality-metric APIs.

### Browser Capture

- HTTP emission moved to the Playwright `requestfinished` lifecycle so response payload reads occur after successful body download.
- Request body references are persisted when Playwright exposes post data.
- Response body capture is budget-aware: known oversized responses are not materialized; unknown-size body reads are restricted to document/XHR/fetch resources.
- Response-body capture outcome is recorded (`stored`, `stored_truncated`, `empty`, `disabled`, or skipped reason).
- Server address and TLS security details are attached when Playwright exposes them.
- WebSocket open/frame/close events enter the standard Network Core pipeline; text/binary frame payloads use the same Body Store.
- Failed browser requests remain represented as normalized request records with stable error metadata.

### System Capture

- Optional tshark dissector fields are negotiated through `tshark -G fields`; unsupported enrichment fields are not forced into the capture command.
- TCP/UDP stream IDs are used as Flow references where available.
- Process-port correlation now infers inbound/outbound direction and local/remote endpoints when possible.
- `frame.time_epoch` is preserved as event time.
- DNS metadata now uses the canonical Network Core keys (`query_name`, `query_type`, `answers`, `elapsed_ms`), fixing the previous `dns_qname`/`query_name` mismatch.
- TLS SNI, version, cipher and ALPN are projected into `TlsHandshake`/Flow metadata.
- System capture continues to make no claim of decrypting HTTPS payloads.

### HAR

- HAR request `postData` and response `content.text` can be persisted through `NetworkBodyStore`.
- Valid base64 HAR content is decoded before body hashing/storage.
- HAR connection ID, server address and Chromium-style security details are projected when available.
- One-shot HAR import now atomically commits capture summary + legacy events + body metadata + normalized projections through `append_capture_events()`.

### Persistence reliability

`append_capture_events()` now upserts the parent capture row before child network rows inside the same transaction. This allows a one-shot import to be created atomically and removes the previous crash window where a `COMPLETED` capture session could exist without its event rows.

## Migration

V6.2 adds one additive migration after the V6.1 Network Core migration. Existing V6.1 databases receive `network_bodies` through the normal `pre-migration.bak` safety path. V6.0 migration regression coverage was corrected so it actually starts before both the V6.1 and V6.2 migrations rather than accidentally treating the latest-minus-one migration set as V6.0 forever.

## Release/version synchronization

- Package/application version: `6.2.0`.
- Runtime User-Agent defaults: `Arenyxa/6.2`.
- Headless API version: `6.2.0`.
- Windows installer metadata/output name: `Arenyxa_V6.2_Setup_x64`.
- Version-sensitive provenance and packaging tests now derive the current version instead of hardcoding V6.1 fixture strings.

## Verification

Final source-tree test gate:

- `196 passed`
- `3 skipped`
- `1 warning`

The three skipped modules require PySide6, which is not installed in the verification container:

- `tests/test_i18n_motion_refinement.py`
- `tests/test_visual_motion_capture.py`
- `tests/test_ui_smoke.py`

The remaining warning is the intentional duplicate ZIP-entry fixture used to verify project-import rejection behavior.

Targeted V6.2/V6.1 network tests passed before the full gate, including body integrity/truncation, V6.1→V6.2 database migration, V6.0→current migration, HAR body/TLS/connection projection, tshark DNS/TLS/endpoint enrichment, optional tshark field negotiation, and one-shot atomic capture creation.

`python -m arenyxa --version` returned `Arenyxa 6.2.0`.

Wheel build succeeded with the locally installed `setuptools 82.0.1` / `wheel 0.46.3` using `--no-build-isolation`. The first isolated build attempt could not obtain `setuptools>=75` from the execution environment's package index; this was an environment/index limitation rather than a source build failure.

## Environment-limited checks

The Python Playwright package is installed and its current sync API was inspected to verify the methods/properties used by V6.2 (`Request.post_data_buffer`, `Request.timing`, `Request.response()`, `Response.body()`, `Response.server_addr()`, `Response.security_details()`, WebSocket frame events). The verification container does **not** contain the Playwright Chromium binary, so an end-to-end browser launch test could not be completed here. The adapter preserves the existing explicit dependency/browser-install error path.

PySide6 is also absent, so the three Qt visual/smoke suites were skipped rather than reported as passing.

## Next gate

V6.3 should consume normalized `http_requests`/`http_responses` and `network_bodies` for Replay/API Map, while retaining explicit confirmation for side-effecting methods and redaction/secret handling. Capture adapters should not be rewritten again as part of that UI/application-layer migration unless a demonstrated data-quality gap requires it.


---

## Source: `docs/V6.6_STABLE_RELEASE_2026-08-10.md`

# Arenyxa v6.6 — Stable Release (2026-08-10)

## Release identity

- Public application version: **6.6**
- Python package version (PEP 440): **6.6.0**
- Plugin/API compatibility comparator: **6.6.2**
- Windows version-resource numeric revision: **6.6.0.3**
- Modern installer output: `Arenyxa_V6.6_Setup_x64.exe`
- Legacy installer output: `Arenyxa_V6.6_Legacy_Win7_x64_Setup.exe`

## Stable promotion basis

This release promotes the independently reviewed v6.6beta2 stabilization line without reopening the architecture. It retains the native Qt ownership hardening, lazy page construction/navigation contract, ApplicationContext shutdown serialization, DataRootLease recovery, workflow/dataset lineage consistency, capture and terminal lifecycle fixes, Scheduler generation protection, Runner pause/resume and shutdown-race fixes, Repair Center wrapper compatibility, Windows terminal command quoting fix, and the Modern/Legacy runtime split.

## Final Windows packaging closure

The final packaging blocker was not a PyInstaller or MainWindow failure. The release test script assigned `QT_QPA_PLATFORM=offscreen` at process scope and did not restore it. Running the newly built GUI from the same PowerShell session therefore inherited Qt's offscreen platform: the process remained alive and Qt reported the window as visible, but Windows received no normal desktop top-level window.

`test.ps1` now scopes `QT_QPA_PLATFORM=offscreen` only around pytest and restores the exact previous process-level value in `finally`. `MYPYPATH` receives the same cleanup discipline. The temporary packaged-startup trace used to isolate the defect is intentionally excluded from the stable runtime.

## Release gates

The stable source preserves the beta2 release gates: Python compile, critical Ruff (`E9,F63,F7,F82`), Python 3.8 grammar compatibility, release-blocking pytest, advisory full Ruff, and advisory mypy. The final source also adds regression coverage for stable version identity, Qt offscreen environment restoration, and absence of diagnostic startup-trace instrumentation.

A native Windows rebuild is required to produce the final EXE/installer artifacts from this source. A Linux/static review cannot substitute for that native packaging step or for the separate Windows 7 Legacy binary certification requirement.


---

## Source: `docs/V6.8_BETA_ADAPTIVE_CONCURRENCY_2026-08-11.md`

# Arenyxa v6.8 Beta — Adaptive Concurrency

Date: 2026-08-11

## Release identity

- Public runtime: `6.8beta`
- Python distribution: `6.8.0b1`
- Plugin/API compatibility comparator: `6.8.0`
- Modern installer target: `Arenyxa_V6.8beta_Setup_x64.exe`
- Windows 7 Legacy installer target: `Arenyxa_V6.8beta_Legacy_Win7_x64_Setup.exe`

## Why this beta exists

The v6.7 Windows stability run reached 64 local stress workers with zero errors, but the
controlled mixed local workload reached peak throughput at four workers and showed increasing
P95 latency above that point. That measurement is useful for local CPU/SQLite/atomic-write
pressure, but it is not valid to treat four workers as a universal HTTP concurrency limit:
real crawling is frequently I/O-bound and may benefit from a larger request pool.

v6.8 Beta therefore separates the two concerns instead of hard-capping all concurrency at four.

## Adaptive process-wide request admission

`RunOrchestrator` still owns a bounded request executor whose configured size is the hard
ceiling. When adaptive request concurrency is enabled:

1. the live process-wide admission budget begins at `min(4, request_workers)`;
2. only local parse/extract processing time is sampled;
3. network latency is explicitly excluded from the global pressure signal;
4. after a full healthy sample window with pending demand, the live budget grows by one;
5. if local-processing P95 grows materially above the low-contention baseline, the live budget
   backs off toward the four-slot floor;
6. already-running requests are never cancelled merely because the budget is reduced;
7. executor objects are never rebuilt during a live adjustment.

Remote-host throttling remains a separate concern. Existing per-host adaptive rate limiting
continues to react to HTTP 429/503 and large remote latency increases.

## Manual control

Settings now exposes `自动调节全局请求并发（推荐）`.

- Enabled: the configured global request concurrency is a ceiling and v6.8 controls the live
  admission budget.
- Disabled: the configured budget is fixed/manual.
- The Developer Live Run & Activity Center exposes both `Apply Request Budget` and `Auto Budget`.
- Applying a manual live budget suspends automatic changes for that session until `Auto Budget`
  is selected again.

The concurrency diagnostic snapshot now includes the live mode, floor, ceiling, local P95 and
last adaptive decision.

## Stress-test reporting

`stress-test` remains a bounded local stability test. v6.8 adds:

- `recommended_local_workers`
- `max_p95_ms`

`recommended_local_workers` intentionally describes only the local mixed stress workload; it
must not be interpreted as a per-host HTTP concurrency recommendation.

## Compatibility and safety

- Existing `request_concurrency` and `per_host_concurrency` settings remain valid.
- Settings schema advances to 7; old settings load with adaptive request concurrency enabled by
  default unless the user explicitly disables it.
- The historical `arenyxa` implementation namespace remains for compatibility.
- Windows 7 Legacy remains on the same shared core and can disable adaptive request concurrency
  if a deployment requires a fixed budget.
- The v6.7 Repair single-console fix is retained unchanged.

## Validation boundary

The v6.8 Beta source is regression-tested in the build environment. Final Windows release
acceptance still requires rerunning `test-all`, `stress-test standard`, and `stress-test extreme`
on the target Windows machine and checking GUI/Repair/Capture behavior. The earlier v6.7 Windows
measurements motivated this controller but are not represented as post-change v6.8 Windows
certification.


---

## Source: `docs/V6.8_STABLE_FINAL_PERFORMANCE_STABILITY_COMPATIBILITY_FREEZE_2026-08-11.md`

# Arenyxa v6.8 Stable 最终性能、稳定性与兼容性冻结

日期：2026-08-11

## 交付边界

本次继续使用 `6.8 / 6.8.0` 正式版身份，不删减页面、服务、数据模型、插件接口或历史兼容入口。
Repair 单终端、Capture 结束态、85%-160% UI 缩放、自适应请求并发、X 风格中心 Logo 连续启动
交接均保留。Git 历史和 Inno Setup 安装包不在本次源码交付范围内。

## 性能修复

- HTTP 请求不再逐次创建默认 TLS 上下文。验证/不验证证书的上下文按进程惰性缓存，opener 仍按请求
  隔离，兼顾线程安全与代理行为。隔离测量避免了每次请求约 `18.5 ms` 的上下文构造成本。
- SQLite 新连接的会话级 PRAGMA 合并为一次初始化；`timeout=30` 继续提供相同 busy handler，
  `foreign_keys`、`synchronous=NORMAL`、WAL checkpoint、cache 和 memory temp-store 合同不变。
- `save_task()` 只构造一次规范 JSON，并直接对同一字节序列计算 SHA-256；5000 请求任务的隔离测量
  约为原路径的 `1.93x`。
- `save_run()` 对已有运行采用窄 UPDATE，只有首次创建才序列化不可变任务快照；100 次 5000 请求
  进度保存由约 `3.322 s` 降至 `1.627 s`，约 `2.04x`。
- Runner 将受主机并发/速率限制的待办项惰性分桶并轮转补位。10 万同主机积压由反复 O(N)
  扫描改为一次分类和稳态 O(1) 等待；旧路径持续占用约 `76.7%` 单核，新路径分类后采样接近
  `0%`，取消进入终态约 `14 ms`。
- 自适应控制的本地处理计时现包含 `ResultRecord` 规范化与哈希；解析后尽早释放响应字节和文档树，
  大响应并发下不会因为漏计 CPU 成本而错误扩容。
- 压力报告明确标记为 `local-persistence-mixed-v2`，并拒绝在外部 `tracemalloc` 已开启时给出受污染
  的计时结果。该通道代表 SQLite/FTS、原子文件、JSON 和选择器混合负载，不冒充公网 HTTP 分数。

旧版与本版交替 Standard A/B 中，新版 4-worker 平均吞吐提高约 `4.6%`，8-worker 提高约
`11.6%`；4/8/12-worker P95 分别下降约 `11.5% / 17.0% / 23.8%`。最终冻结连续执行三次
Standard 与一次 Extreme，共 9,600 次计时操作，全部零错误：Standard 的 4-worker 吞吐/P95
中位数为 `495.87 ops/s / 30.06 ms`，三轮均推荐 4 workers；Extreme 验证到 64 workers 仍未
出现错误或不稳定级别，并继续推荐 4 workers。

## 稳定性修复

- Windows Repair 进程探测不再调用 `os.kill(pid, 0)`；该调用在 Windows 并非 POSIX 无害探测，
  可终止被检查进程。现在使用具有明确 HANDLE 签名的 WinAPI，拒绝访问/未知状态按保守存活处理。
- Capture 的 prepare、start、pause/resume 和 stop 边界进一步事务化：无效过滤器或持久化失败不会
  毒化控制器；线程启动失败可复用；暂停/恢复写库失败会回滚适配器与内存状态。
- Capture 回调严格绑定 session，并在入队和过滤器失败提交前二次校验。旧适配器迟到事件、过滤期间
  换会话，以及 stop 与过滤失败最终提交的 TOCTOU 均被同一状态锁隔离，不会污染下一会话或把
  `COMPLETED` 反写为 `FAILED`。
- Runner pause/resume 的控制 I/O 独立串行，避免内存为 RUNNING、数据库却被旧 pause 写回 PAUSED；
  尚未开始的 queued Future 在取消时可立即进入取消路径。
- Workflow shutdown token 从公开入口、首次仓储副作用之前登记；shutdown 不会在 revision/execution
  仍可能写库时提前返回。

## 兼容性与启动连续性

- MainWindow 最小尺寸按实际启动屏幕的逻辑可用矩形收缩，1920×1080@200%、960×540、800×600
  等小逻辑桌面不会被固定 1120×720 再次撑出屏幕，也不会破坏 Splash 与主窗的几何连续性。
- Splash Logo 按设备像素比生成物理像素并写入 pixmap DPR；高 DPI 下保持清晰、中心一致。
- Windows 的 `SPI_GETCLIENTAREAANIMATION` 系统辅助功能偏好与用户 Reduce Motion 设置做运行时 OR；
  系统偏好不会被写回用户配置，也不能被后续质量档位绕过。
- Windows 10/11 默认继续使用现代 Python/Qt 通道；显式 `legacy-enterprise` 可在现代 Windows 上验证
  Python 3.8/PySide2 企业环境。旧版启动入口保持兼容。
- 文本子进程对本地代码页异常字节采用 replacement 解码，避免输出解码崩溃；一键启动器会实际导入
  Qt、lxml、cssselect、dnspython、openpyxl、cryptography 和 tzdata，二进制损坏或缺依赖会触发恢复。
- 中心 Logo、干净背景、连续放大、同窗圆形遮罩揭开以及 portrait/ultrawide/多屏/DPI/Reduce Motion
  路径保持完整，不引入第二个可见主窗口。

## 验证矩阵

本轮至少覆盖以下独立维度：

1. 完整 pytest 单元/集成/契约回归；
2. Python compileall；
3. release-blocking Ruff；
4. Python 3.8 grammar；
5. Windows Repair 子进程存活与未知句柄；
6. Capture 生命周期、迟到回调、过滤器/stop 交错和持久化回滚；
7. Runner host 分桶公平性、许可补位、大积压取消与 pause/resume 顺序；
8. Workflow shutdown 与仓储副作用排序；
9. SQLite task/run 快照、状态保护和 PRAGMA 合同；
10. TLS 上下文缓存与并发复用；
11. 960×540、800×600、200% DPI 与多屏启动几何；
12. 系统/用户 Reduce Motion 与 X 风格遮罩终点；
13. Modern/Legacy runtime 选择与 Python 3.8/PySide2 通道；
14. PowerShell 一键启动脚本语法和核心依赖实际加载；
15. 三次 Standard 及一次 Extreme 压力冻结；
16. Repair Seed 内容、CRC 与 SHA-256；
17. Source Manifest 全文件哈希；
18. 干净源码目录与 ZIP 的 CRC、解压后逐文件一致性。

完整性重建后的最终全量回归为 `474 passed / 1 skipped / 0 failed`；唯一跳过项是在 Windows 上
不可用的 POSIX `/proc` 文件描述符统计。Repair Seed 独立完成 CRC/清单/内容校验，兼容性冻结另有
85 项 Windows/DPI/Reduced Motion/Legacy/Qt 专项全部通过，92 个源码文件通过 Python 3.8 grammar。

完整性文件在所有源码、测试和本文档冻结后重新生成。交付目录不包含 `.venv`、缓存、`*.egg-info`、
构建目录、Git 元数据或 Inno Setup 输出。


---

## Source: `docs/V6.8_STABLE_RELEASE_2026-08-11.md`

# Arenyxa v6.8 Stable Release Audit

Date: 2026-08-11

## Release identity

- Public runtime: **6.8**
- Python distribution: **6.8.0**
- Plugin/API compatibility comparator: **6.8.0**
- Modern Windows installer target: `Arenyxa_V6.8_Setup_x64.exe`
- Windows 7 Legacy installer target: `Arenyxa_V6.8_Legacy_Win7_x64_Setup.exe`

## Stable-release goals

v6.8 promotes the adaptive-concurrency beta line to a stable release while concentrating on startup presentation and failure-boundary reliability. No feature was intentionally removed. The release retains the v6.7 multi-monitor launch-geometry contract, Repair single-console hotfix, UI scaling, Capture lifecycle cleanup, and the v6.8 adaptive request-admission controller.

## Startup motion refinement

The startup handoff was redesigned to remove several sources of visible micro-stutter on Windows compositors:

- the in-window handoff overlay is now paint-only instead of combining two `QGraphicsOpacityEffect` objects;
- the icon is no longer rescaled into a new `QPixmap` on every animation frame;
- `QPainter` draws the original icon with `SmoothPixmapTransform` and a scalar transform;
- a quintic smootherstep curve gives zero start and end velocity instead of the abrupt initial acceleration of the prior OutCubic handoff;
- icon opacity reaches zero before the opaque launch surface begins revealing the real workspace;
- Quality/Balanced/Efficiency modes keep distinct durations without artificial sleeps or nested event loops;
- Reduce Motion remains a static continuous handoff;
- the existing single launch-geometry plan continues to bind splash, MainWindow, handoff overlay, Recovery Mode, and refresh-rate policy to the same target display.

The temporary top-level fallback path preserves the same two-stage visual order, so a compositor or overlay-preparation failure does not expose the dashboard behind a still-visible logo.

## Reliability hardening

### Run pause/resume transaction boundary

`CancellationToken.pause()` / `resume()` failures are now handled before volatile or durable Run state is changed. Token-transition failures are logged and leave both the in-memory Run and database status unchanged. Existing persistence rollback remains in place for database-write failures after a successful token transition.

### Diagnostic visibility

Several non-fatal recovery paths that previously swallowed secondary exceptions now retain the safe fallback behavior but emit diagnostic logging, including Dataset terminal-state writeback, Activity Center subscriber failures, distributed-worker vault rollback, and native Repair dialog fallback.

### Packaging audit output

Full Ruff and mypy audits remain available, but advisory findings are written to `dist/audit` instead of flooding the packaging console. Release-blocking compile, critical-lint, Python 3.8 grammar, and pytest gates remain separate hard gates in the Windows build script.

## Regression matrix for previously observed issues

- Multi-monitor startup surface and MainWindow placement: shared `LaunchGeometryPlan` retained and re-tested.
- Startup icon visible while workspace appears: two-stage icon-then-surface reveal retained and strengthened.
- Startup motion feels abrupt: paint-only smootherstep handoff introduced.
- Repair progress terminal followed by a blank terminal: source relaunch continues to prefer `pythonw.exe` with no-console/detached fallbacks and DEVNULL standard handles.
- Repair progress terminal not closing: Repair worker/relaunch process boundaries remain independently testable and the visible progress host is not inherited by the relaunched GUI.
- Large-display text too small: automatic/manual 85%-160% UI scaling contract retained.
- Capture completed but top activity strip keeps moving: terminal Capture states continue to clear the indeterminate global-progress state.
- Pause/resume persistence mismatch: durable rollback retained; token-transition failures are now covered before state mutation.
- Adaptive concurrency overload: configured worker count remains the ceiling, while automatic admission starts from the local four-slot floor and can grow/back off based on local-processing pressure.
- Silent secondary failures: reviewed and reduced; intentional destructor/Windows-API fallback catches remain non-fatal by design.

## Validation record

Before the final Source Manifest freeze, the complete historical regression collection (excluding only the manifest self-check while files were still changing) completed with **434 passed / 6 skipped / 0 failed**. The six skips are native Qt visual/UI tests because the current audit container has no installable PySide2/PySide6 binding.

Additional focused gates completed successfully for stable identity/packaging, startup geometry and motion mathematics, Repair/Capture/UI-scale contracts, Runner concurrency and shutdown, Dataset/Workflow/lineage/recovery, security/provenance/terminal, Python compilation, and Python 3.8 grammar compatibility.

After the release tree was frozen, the Repair Seed and Source Manifest were regenerated. The final Source Manifest covers **259 files**. Repair/Manifest/stable-release focused integrity checks completed with **31 passed / 0 failed**. Including the Source Manifest self-check, the complete historical regression result is **435 passed / 6 skipped / 0 failed**.

## Windows-native release verification

The current audit environment cannot honestly certify exact Windows compositor smoothness or native Qt rendering. On the target Windows machine, verify the final source/build with:

1. normal startup on each connected display, repeated close/relaunch, maximize/restore, display disconnect/reconnect, and Reduce Motion;
2. `test-all`;
3. `stress-test standard` and `stress-test extreme`;
4. repeated Repair Center runs, confirming only one visible progress terminal and no blank terminal after relaunch;
5. Browser/tshark Capture start/stop/completed/failed/cancelled paths, confirming the top activity strip always clears;
6. `scripts\build.ps1`, followed by install/upgrade/uninstall smoke testing of `Arenyxa_V6.8_Setup_x64.exe`.

The stable designation reflects the verified source/runtime contracts and regression record; native Windows visual playback remains the authoritative final check for subjective animation smoothness.


---

## Source: `docs/V7.0_STABLE_RELEASE_2026-08-14.md`

# Arenyxa v7.0 Stable Release — 2026-08-14

## Release identity

Arenyxa v7.0 promotes the cumulative Phase 1–12 hardened development line to the **7.0 product release identity**. The public runtime version is `7.0`, the Python distribution version is `7.0.0`, and Windows file metadata is `7.0.0.0`. The modern installer is `Arenyxa_V7.0_Setup_x64.exe`; the isolated Windows 7 Legacy Enterprise installer is `Arenyxa_V7.0_Legacy_Win7_x64_Setup.exe`.

This promotion deliberately **does not** pretend that the plugin/runtime compatibility contract changed. `__compat_version__` remains `6.8.0` until an explicit compatibility migration is designed, reviewed, and tested. The historical `arenyxa` Python/CLI namespace also remains supported so existing integrations are not broken by the product version promotion.

## Included platform scope

The v7.0 source integrates the Phase 1–12 architecture/contracts, Web Intelligence, Reliability/Resource Governance, Security Foundation, Official Developer Trust, Local Enterprise Identity/RBAC, Enrollment/Device Trust, Office Coordinator, Enterprise Governance, Enterprise Server/Worker distributed runtime, and Release Hardening/LTS foundations in one Core Runtime line.

The startup visual baseline is intentionally frozen. The v7.0 version promotion does not alter the approved splash/handoff implementation or its motion math.

## Release hardening

The build chain now has an explicit v7.0 release-identity gate. It verifies the runtime/package versions, Windows file metadata, modern and legacy Inno Setup names, release-attestation version, launcher identity, and the distinction between product release version (`7.0.0`) and runtime/plugin compatibility identity (`6.8.0`). The release gate is executed by the packaging scripts before building binaries.

Worker health reporting publishes the real product package version while distributed registration continues to negotiate the explicit compatibility identity. This prevents a future product-version bump from silently becoming a protocol/plugin compatibility change.

## Automated verification

The final release tree and a fresh extraction were exercised through the release-identity, compile/grammar, static-security, startup-freeze, independent Welcome window, UI button-wiring, Phase 1-12 targeted, integrity, and historical regression gates. The complete historical pytest regression on the fresh extraction is **592 passed / 12 environment skips / 0 failed**. The skips are limited to Qt/Windows-native probes unavailable on the headless validation host; no failing test was reclassified as a skip.

The frozen startup files remain byte-identical to the approved baseline: `startup_splash.py` SHA-256 `a95bf948c3ddb2a165100711c59843e1eef013e7f9fb7e392ffbc38c9ddd5267` and `startup_motion_math.py` SHA-256 `81ce778eed5682ca042cdd1c7875ac46b20ea622d75c50d144d3b8043963231e`.

## Stable/GA boundary

The source is branded and packaged as the v7.0 Stable release line, but the Phase-12 policy remains fail-closed: automated regression is not a substitute for real Windows validation, a distributed-failure drill, migration/rollback evidence, independent security review, and official release signing. `ReleaseGateReport` continues to reject Stable/Enterprise promotion when those operator/native gates are missing.

Arenyxa release signing is a separate trust domain. Developer Root, Owner Authority keys, Enterprise Root keys, and private Authority state must never be reused as release-signing keys or included in the installer.

